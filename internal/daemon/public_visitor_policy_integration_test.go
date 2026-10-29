package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationPublicSignedVisitorStopsOnPreparedIPRevocation(t *testing.T) {
	f := newSplitPublishFixture(t, "public-policy")
	var opens atomic.Int32
	closed := make(chan struct{})
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		opens.Add(1)
		defer close(closed)
		_, _ = io.WriteString(w, "signed visitor\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	cleanupIntegrationHTTPServer(t, target, f.owner)
	quic, _ := disabledIntegrationConnector("signed public visitor proof uses TLS/TCP")
	_, tcp := f.connectors()
	config := f.identity.publisherConfig(target.URL, quic, tcp)
	config.AccessMode = controlv1.Restricted
	publisher := startOwnedIntegrationPublisher(t, f.owner, config, func() string {
		return integrationPublisherDiagnostics(f.inspect, f.pebble.logPath)
	})
	ready := f.waitReady(t, publisher)
	identity, err := f.identity.authority.IdentityContext(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	state, err := controlstate.Open(t.Context(), f.databaseURL, testStorageKey, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(state.Close)
	source, err := json.Marshal(controlv1.VisitorTokenControlSessionSource{Kind: controlv1.VisitorTokenControlSession})
	if err != nil {
		t.Fatal(err)
	}
	permission, err := f.identity.routes.IssueVisitorToken(t.Context(), controlv1.VisitorTokenRequest{
		Resource: controlv1.VisitorResourceScope{Kind: "public_url", Id: ready.PublicURLID}, Source: source,
	})
	if err != nil {
		t.Fatal("prepare signed visitor permission", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, ready.PublicURL+"/held", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Tnl-Visitor-Token", permission.VisitorToken)
	client := *f.visitor.client
	client.Timeout = 0
	response, err := client.Do(request)
	if err != nil {
		t.Fatal("real publisher rejected control-signed visitor", err)
	}
	defer response.Body.Close()
	assertIntegrationPublicURLCertificate(t, response, ready.Hostname)
	reader := bufio.NewReader(response.Body)
	if line, err := reader.ReadString('\n'); err != nil || response.StatusCode != http.StatusOK || line != "signed visitor\n" {
		t.Fatalf("signed visitor response: status=%d line=%q error=%v", response.StatusCode, line, err)
	}
	// mutate live IP authority through control's state owner. saved-definition
	// updates intentionally reject open runs. neither the signed token's later
	// expiry nor an active body extends the publisher's prepared IP policy.
	if _, err := state.MutateVisitorIPs(t.Context(), ready.PublicURLID, identity.Identity.Id, "set", "", []controlstate.VisitorIPGrantInput{{Prefix: "192.0.2.0/24"}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if rest, err := io.ReadAll(reader); err == nil || len(rest) != 0 {
		t.Fatalf("revoked source completed or received more target bytes: bytes=%d error=%v", len(rest), err)
	}
	select {
	case <-closed:
	case <-ctx.Done():
		t.Fatal("revocation did not cancel target work before the visitor deadline")
	}
	if ctx.Err() != nil || opens.Load() != 1 {
		t.Fatal("test deadline or target replay satisfied revocation", ctx.Err(), opens.Load())
	}
	select {
	case <-publisher.done:
		t.Fatal("visitor policy revocation stopped the publisher", publisher.result())
	default:
	}
}
