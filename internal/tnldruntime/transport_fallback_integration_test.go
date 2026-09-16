package tnldruntime

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tnldotdev/tnl/internal/muxsession"
)

func TestIntegrationPublisherFallsBackWhenQUICStalls(t *testing.T) {
	fixture := newStandalonePublishFixture(t, "fallback")
	target := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(response, "TLS/TCP fallback")
	}))
	cleanupIntegrationHTTPServer(t, target, fixture.owner)

	var quicAttempts eventRecorder[struct{}]
	quic := muxsession.ConnectorFunc(func(ctx context.Context, _ muxsession.Endpoint) (muxsession.Session, error) {
		quicAttempts.append(struct{}{})
		<-ctx.Done()
		return nil, context.Cause(ctx)
	})
	_, tcp := fixture.connectors()
	handle := fixture.startPublisher(t, target.URL, quic, tcp)
	ready := fixture.waitReady(t, handle)

	if attempts, _ := quicAttempts.snapshot(); len(attempts) < 2 {
		t.Fatal("publisher connection did not try QUIC before falling back")
	}
	response, body, err := fixture.visitor.requestURL(http.MethodGet, ready.PublicURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "TLS/TCP fallback" {
		t.Fatalf("fallback visitor response = %s, %q", response.Status, body)
	}
}
