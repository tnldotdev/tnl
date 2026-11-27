package service

import (
	"bytes"
	"errors"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
	"golang.org/x/time/rate"
)

func TestPublicVisitorDiagnosticBoundsLogVolume(t *testing.T) {
	var output bytes.Buffer
	previous := log.Writer()
	previousBudget := publicVisitorLogBudget
	log.SetOutput(&output)
	publicVisitorLogBudget = rate.NewLimiter(0, 2)
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
