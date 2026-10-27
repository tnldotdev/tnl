package daemon

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisher"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// the candidate response keeps control's region and service IDs, but points
// each published relay address at that service's disposable listener.
type measuredFixtureControl struct {
	*publisheridentity.Native
	addresses  map[string]string
	discovered bool
	preferred  []string
}

func (c *measuredFixtureControl) RelayCandidates(ctx context.Context, access string) (controlv1.RelayCandidates, error) {
	result, err := c.Native.RelayCandidates(ctx, access)
	if err != nil {
		return result, err
	}
	for index := range result.Candidates {
		candidate := &result.Candidates[index]
		address := c.addresses[candidate.RelayAddress]
		if address == "" {
			return controlv1.RelayCandidates{}, publisheridentity.ErrRegionUnsupported
		}
		candidate.RelayAddress = address
	}
	c.discovered = true
	return result, nil
}

func (c *measuredFixtureControl) CreatePublishRunInRegions(ctx context.Context, id, key string, preferred []string) (controlv1.PublishRunSetup, error) {
	c.preferred = slices.Clone(preferred)
	return c.Native.CreatePublishRunInRegions(ctx, id, key, preferred)
}

var _ publisher.RegionalRunControl = (*measuredFixtureControl)(nil)

type measuredServiceFixtureControl struct {
	*publisheridentity.Native
	addresses  map[string]string
	discovered bool
	preferred  []string
}

func (c *measuredServiceFixtureControl) RelayCandidates(ctx context.Context, access string) (controlv1.RelayCandidates, error) {
	result, err := c.Native.RelayCandidates(ctx, access)
	if err != nil {
		return result, err
	}
	for index := range result.Candidates {
		candidate := &result.Candidates[index]
		address := c.addresses[candidate.RelayAddress]
		if address == "" {
			return controlv1.RelayCandidates{}, publisheridentity.ErrRegionUnsupported
		}
		candidate.RelayAddress = address
	}
	c.discovered = true
	return result, nil
}

func (c *measuredServiceFixtureControl) StartServiceRunInRegions(ctx context.Context, service, run, access string, number int64, preferred []string) (controlv1.ServiceRunSetup, error) {
	c.preferred = slices.Clone(preferred)
	return c.Native.StartServiceRunInRegions(ctx, service, run, access, number, preferred)
}

var _ publisherservice.RegionalRunControl = (*measuredServiceFixtureControl)(nil)

func TestIntegrationSplitMeasuredTwoRegionPublisherServesVisitor(t *testing.T) {
	f := newSplitPublishFixtureWithOptions(t, "measured-regions", splitPublishOptions{twoRegions: true})
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "measured visitor path")
	}))
	cleanupIntegrationHTTPServer(t, target, f.owner)
	quic, tcp := f.connectors()
	config, err := prepareIntegrationPublisher(t.Context(), f.identity.publisherConfig(target.URL, quic, tcp))
	if err != nil {
		t.Fatal(err)
	}
	control := &measuredFixtureControl{Native: config.Control.(*publisheridentity.Native), addresses: make(map[string]string)}
	for _, relay := range []splitRelayFixture{f.relayA, f.relayB, f.relayC, f.relayD} {
		control.addresses[relay.config.RelayAddress] = relay.config.RelayTCPListen
	}
	config.Control = control
	handle := startOwnedIntegrationPublisher(t, f.owner, config, func() string { return integrationPublisherDiagnostics(f.inspect, f.pebble.logPath) })
	ready := f.waitReady(t, handle)
	if !control.discovered || len(control.preferred) != 2 || !slices.Contains(control.preferred, "sjc") || !slices.Contains(control.preferred, "ord") {
		t.Fatal("real publisher skipped successful two-region probe ranking", control.preferred)
	}
	rows, err := f.inspect.Query(`SELECT slot.relay_service_id, service.region
	    FROM control.publisher_service_connection_slots slot
	    JOIN control.relay_services service ON service.relay_service_id=slot.relay_service_id
	    WHERE slot.service_id=$1 AND slot.run_number=$2 ORDER BY slot.connection_slot`, ready.PublicURLID, ready.PublishRunNumber)
	if err != nil {
		t.Fatal(err)
	}
	var assigned []string
	for rows.Next() {
		var service, region string
		if err := rows.Scan(&service, &region); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		if region != control.preferred[0] {
			rows.Close()
			t.Fatal("regional preference was not honored by control", region, control.preferred)
		}
		assigned = append(assigned, service)
	}
	queryErr := rows.Err()
	rows.Close()
	if queryErr != nil || len(assigned) != 2 || assigned[0] == assigned[1] {
		t.Fatal("measured run did not claim two distinct relay services", assigned, queryErr)
	}
	response, body, err := f.visitor.requestURL(http.MethodGet, ready.PublicURL+"/measured", nil)
	if err != nil || response.StatusCode != http.StatusOK || string(body) != "measured visitor path" {
		t.Fatal("visitor did not reach the local app through measured placement", response, string(body), err)
	}
}

func TestIntegrationPrivateMeasuredTwoRegionPublisherServesVisitor(t *testing.T) {
	f := newServiceRuntimeFixtureTopology(t, false, nil, false, nil, serviceRuntimeTopologyOptions{twoRegions: true})
	startSeparatedPrivateIngress(t, f, 0, "quic", nil)
	startSeparatedPrivateIngress(t, f, 1, "quic", nil)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(w, r.Body)
	}))
	t.Cleanup(target.Close)
	key, err := opaqueid.New(opaqueid.IdempotencyPrefix)
	if err != nil {
		t.Fatal(err)
	}
	service, err := f.identity.routes.CreateService(t.Context(), f.identity.teamID, "regional-private-http", key, controlv1.ServiceMetadata{Protocol: controlv1.ServiceProtocol("http"), TrustRevision: 1})
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := f.identity.routes.CreatePublisherEnrollment(t.Context(), controlv1.CreatePublisherEnrollmentRequest{TeamId: service.TeamId, ServiceId: &service.Id, Kind: controlv1.CreatePublisherEnrollmentRequestKindInstalled, Name: "regional-private"})
	if err != nil {
		t.Fatal(err)
	}
	native, identity, err := publisheridentity.EnrollNative(t.Context(), f.identity.state, f.identity.routes, f.identity.authority, enrollment.EnrollmentKey)
	if err != nil {
		t.Fatal(err)
	}
	control := &measuredServiceFixtureControl{Native: native, addresses: f.tcpAddresses}
	quic, tcp := f.connectors()
	ctx, cancel := context.WithCancel(t.Context())
	ready, done := make(chan struct{}), make(chan error, 1)
	go func() {
		done <- publisherservice.Publish(ctx, publisherservice.RunConfig{Control: control, State: f.identity.state, Access: native.Access, Identity: identity, ServiceID: service.Id,
			Target: target.Listener.Addr().String(), TransportTLS: f.roots,
			Metadata: controlv1.ServiceMetadata{Protocol: service.Protocol, TargetTls: service.TargetTls, TrustRevision: service.TrustRevision, PublisherPool: service.PublisherPool}, HeartbeatInterval: 100 * time.Millisecond,
			Ready: func() error { close(ready); return nil }, Connect: func(ctx context.Context, bound *publisherservice.Bound, slot uint8) (publisherservice.SlotSession, error) {
				return bound.ConnectSlotWithTransports(ctx, slot, false, quic, tcp)
			}})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("measured private publisher shutdown: %v", err)
			}
		case <-time.After(12 * time.Second):
			t.Error("measured private publisher did not join")
		}
	})
	select {
	case <-ready:
	case err := <-done:
		done <- err
		t.Fatal("measured private publisher failed before readiness", err)
	case <-time.After(20 * time.Second):
		t.Fatal("measured private publisher did not become ready")
	}
	if !control.discovered || len(control.preferred) != 2 || !slices.Contains(control.preferred, "sjc") || !slices.Contains(control.preferred, "ord") {
		t.Fatal("private publisher skipped verified two-region ranking", control.preferred)
	}
	rows, err := f.inspect.Query(`SELECT slot.relay_service_id, service.region FROM control.publisher_service_connection_slots slot
	    JOIN control.relay_services service ON service.relay_service_id=slot.relay_service_id
	    WHERE slot.service_id=$1 AND slot.service_kind='private' AND slot.state='ready' ORDER BY slot.connection_slot`, service.Id)
	if err != nil {
		t.Fatal(err)
	}
	var assigned []string
	for rows.Next() {
		var name, location string
		if err := rows.Scan(&name, &location); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		if location != control.preferred[0] {
			rows.Close()
			t.Fatal("private service ignored measured preference", location, control.preferred)
		}
		assigned = append(assigned, name)
	}
	queryErr := rows.Err()
	rows.Close()
	if queryErr != nil || len(assigned) != 2 || assigned[0] == assigned[1] {
		t.Fatal("private publisher did not claim two distinct services", assigned, queryErr)
	}
	person, err := f.identity.authority.IdentityContext(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	visitorControl, err := connectorstream.NewControl(f.identity.routes, f.identity.state, person.Identity.Id)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	visitorCtx, stopVisitor := context.WithCancel(t.Context())
	visitorReady, visitorDone := make(chan struct{}), make(chan error, 1)
	go func() {
		visitorDone <- connectorstream.Serve(visitorCtx, listener, connectorstream.Config{Control: &separatedVisitorControl{Control: visitorControl}, ServiceID: service.Id, IdentityID: person.Identity.Id,
			Protocol: "http", TrustRevision: service.TrustRevision, Endpoint: service.Endpoint, ServiceTLS: f.visitorRoots, Ready: func() error { close(visitorReady); return nil }})
	}()
	t.Cleanup(func() {
		stopVisitor()
		select {
		case err := <-visitorDone:
			if err != nil {
				t.Errorf("measured private visitor shutdown: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("measured private visitor did not join")
		}
	})
	select {
	case <-visitorReady:
	case err := <-visitorDone:
		visitorDone <- err
		t.Fatal("private visitor setup failed", err)
	case <-time.After(10 * time.Second):
		t.Fatal("private visitor did not become ready")
	}
	verification := f.visitorRoots.Clone()
	verification.ServerName = service.Endpoint.Hostname
	transport := &http.Transport{Proxy: nil, TLSClientConfig: verification}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	response, err := client.Post("https://"+listener.Addr().String()+"/measured", "application/octet-stream", strings.NewReader("private measured visitor"))
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if readErr != nil || response.StatusCode != http.StatusOK || string(body) != "private measured visitor" {
		t.Fatal("private visitor did not reach the target", response.StatusCode, string(body), readErr)
	}
}
