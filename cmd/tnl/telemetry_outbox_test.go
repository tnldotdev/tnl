package main

import (
	"encoding/json"
	"testing"

	api "github.com/tnldotdev/tnl/pkg/api/integrations/telemetry/v1"
)

// delivery and outbox assertions moved with their owner to client/telemetry.
func TestTypedFailureEventKeepsBoundedFields(t *testing.T) {
	r := &recordingTelemetryReporter{}
	i := newTelemetryInvocation(r)
	i.finished(telemetryLogin, telemetryAuthenticationStage, diagnosticError())
	data, _ := json.Marshal(r.payloads[0])
	if api.ValidateEvent(data) != nil {
		t.Fatalf("invalid event: %s", data)
	}
	event, _ := r.payloads[0].AsCommandEvent()
	if event.Payload.Command != "login" || event.Payload.Outcome != api.Failed || event.Payload.FailureStage == nil || *event.Payload.FailureStage != "authentication" || event.Payload.DiagnosticCode == nil || *event.Payload.DiagnosticCode != "TNL_AUTHENTICATION_REQUIRED" {
		t.Fatalf("failure: %s", data)
	}
}
