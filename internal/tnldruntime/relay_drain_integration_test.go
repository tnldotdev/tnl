package tnldruntime

import (
	"bufio"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestIntegrationRelayDrainPreservesActiveVisitorStream(t *testing.T) {
	fixture := newSplitPublishFixture(t, "relay-drain")
	streamStarted := make(chan struct{})
	releaseStream := make(chan struct{})
	release := sync.OnceFunc(func() { close(releaseStream) })
	target := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/stream" {
			_, _ = io.WriteString(response, "new visitor")
			return
		}
		response.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(response, "first\n")
		response.(http.Flusher).Flush()
		close(streamStarted)
		<-releaseStream
		_, _ = io.WriteString(response, "second\n")
	}))
	t.Cleanup(target.Close)
	t.Cleanup(release)
	quic, tcp := fixture.connectors()
	publisher := fixture.startPublisher(t, target.URL, quic, tcp)
	ready := fixture.waitReady(t, publisher)

	request, err := http.NewRequest(http.MethodGet, ready.PublicURL+"/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := fixture.visitor.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	reader := bufio.NewReader(response.Body)
	first, err := reader.ReadString('\n')
	if err != nil || first != "first\n" {
		t.Fatalf("first streamed event = %q, %v", first, err)
	}
	select {
	case <-streamStarted:
	default:
		t.Fatal("local service did not start the visitor stream")
	}

	stored, found, err := fixture.identity.state.ControlSession(t.Context())
	if err != nil || !found {
		t.Fatalf("read control session: found %t, error %v", found, err)
	}
	admin, err := controlclient.New(
		fixture.identity.controlOrigin, fixture.controlHTTP, credentials.AccessToken(stored.AccessToken),
	)
	if err != nil {
		t.Fatal(err)
	}
	var active controlv1.AdminRelayLease
	waitForIntegrationCondition(t, 10*time.Second, func() (bool, error) {
		page, err := admin.AdminListRelays(t.Context())
		if err != nil {
			return false, err
		}
		for _, relay := range page.Relays {
			if !relay.Draining && relay.ReportedStreams > 0 {
				active = relay
				return true, nil
			}
		}
		return false, nil
	})
	deadline := time.Now().Add(5 * time.Second).UTC()
	draining, err := admin.AdminDrainRelay(t.Context(), string(active.RelayId), controlv1.AdminDrainRelayRequest{
		RelayRunId: active.RelayRunId, RelayLeaseRevision: active.RelayLeaseRevision, Deadline: deadline,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !draining.Draining || draining.DrainDeadline == nil {
		t.Fatalf("drained relay lease = %#v", draining)
	}
	waitForIngressRoutingCurrent(t, fixture.inspect, 1)
	probe, body, err := fixture.visitor.requestURL(http.MethodGet, ready.PublicURL+"/after-drain", nil)
	if err != nil {
		t.Fatal(err)
	}
	if probe.StatusCode != http.StatusOK || string(body) != "new visitor" {
		t.Fatalf("visitor after relay drain = %s, %q", probe.Status, body)
	}

	drainedProcess := fixture.relayA.process
	if string(active.RelayId) == fixture.relayB.config.RelayID {
		drainedProcess = fixture.relayB.process
	}
	drainedProcess.cancel()
	select {
	case <-drainedProcess.done:
		t.Fatal("relay process stopped before its active visitor stream completed")
	case <-time.After(100 * time.Millisecond):
	}
	release()
	second, err := reader.ReadString('\n')
	if err != nil || second != "second\n" {
		t.Fatalf("second streamed event = %q, %v", second, err)
	}
	waitForIntegrationProcess(t, drainedProcess)
}
