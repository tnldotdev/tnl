package service

import (
	"bytes"
	"errors"
	"log"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/observability/operatorlog"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestPublicVisitorDiagnosticSeesRequestStallAfterTLS(t *testing.T) {
	var output bytes.Buffer
	previous := log.Writer()
	previousBudget := publicHTTPLogBudget
	log.SetOutput(&output)
	publicHTTPLogBudget = operatorlog.NewBudget(0, 1)
	t.Cleanup(func() {
		log.SetOutput(previous)
		publicHTTPLogBudget = previousBudget
	})
	entered := make(chan struct{})
	f := newPendingHTTPFixture(t, 1, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
	}))
	v := f.mustOpen(t, 0, netip.MustParseAddr("192.0.2.10"))
	if err := v.handshake(t, false); err != nil {
		t.Fatal("fixture must complete TLS before stalling HTTP", err)
	}
	request, err := http.NewRequest(http.MethodGet, "https://"+f.source.prepared.managedHostname+"/private-path", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer unchanged-application")
	if err := request.Write(v.secure); err != nil {
		t.Fatal(err)
	}
	claimedAwait(t, entered)
	v.close()
	v.join(t)
	text := output.String()
	if !strings.Contains(text, "publisher http request") || !strings.Contains(text, "visitor_connection_id="+v.header.VisitorConnectionID) ||
		!strings.Contains(text, "last_progress=application_entered close_trigger=request_context_ended") ||
		strings.Contains(text, "headers_ms=") || strings.Contains(text, "/private-path") {
		t.Fatalf("publisher did not distinguish an application stall from TLS failure: %q", text)
	}
}

func TestPublicVisitorDiagnosticBoundsLogVolume(t *testing.T) {
	var output bytes.Buffer
	previous := log.Writer()
	previousBudget := publicVisitorLogBudget
	log.SetOutput(&output)
	publicVisitorLogBudget = operatorlog.NewBudget(0, 2)
	t.Cleanup(func() {
		log.SetOutput(previous)
		publicVisitorLogBudget = previousBudget
	})
	d := publicVisitorDiagnostic{header: tunnelv1.ServiceForwardingHeader{
		ServiceStreamHeader: tunnelv1.ServiceStreamHeader{
			VisitorConnectionID: "vc_test", PublicService: &tunnelv1.PublicServiceAdmission{},
		},
	}, started: time.Now(), step: "visitor_tls", transport: tunnel.TransportWSS}
	d.finish(t.Context(), nil)
	if output.Len() != 0 {
		t.Fatal("a normal visitor emitted new log lines")
	}
	for range 100 {
		d.finish(t.Context(), errors.New("private failure text"))
	}
	text := output.String()
	if strings.Count(text, "\n") != 2 || strings.Count(text, "visitor_connection_id=vc_test") != 2 ||
		!strings.Contains(text, "step=visitor_tls") || strings.Contains(text, "private failure text") {
		t.Fatalf("publisher log lost its bound or exposed a raw error: %q", text)
	}
}
