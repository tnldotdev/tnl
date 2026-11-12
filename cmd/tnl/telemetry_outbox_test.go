package main

import (
	"encoding/json"
	"testing"

	clienttelemetry "github.com/tnldotdev/tnl/internal/client/telemetry"
	api "github.com/tnldotdev/tnl/pkg/api/integrations/telemetry/v1"
)

// delivery and outbox assertions moved with their owner to client/telemetry.
func TestTypedFailureEventKeepsBoundedFields(t *testing.T) {
	payload := clienttelemetry.Command(commandOutcome("login", "", api.Authentication, diagnosticError()))
	data, _ := json.Marshal(payload)
	if api.ValidateEvent(data) != nil {
		t.Fatalf("invalid event: %s", data)
	}
	event, _ := payload.AsCommandEvent()
	if event.Payload.Command != "login" || event.Payload.Outcome != api.Failed || event.Payload.FailureStage == nil || *event.Payload.FailureStage != "authentication" || event.Payload.DiagnosticCode == nil || *event.Payload.DiagnosticCode != "TNL_AUTHENTICATION_REQUIRED" {
		t.Fatalf("failure: %s", data)
	}
}
