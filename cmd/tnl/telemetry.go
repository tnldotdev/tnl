package main

import (
	"context"
	"os"

	"strings"

	"github.com/spf13/cobra"
	clienttelemetry "github.com/tnldotdev/tnl/internal/client/telemetry"
	"github.com/tnldotdev/tnl/internal/cliflags"
	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
	api "github.com/tnldotdev/tnl/pkg/api/integrations/telemetry/v1"
)

type telemetryFactory func(clienttelemetry.Config) *clienttelemetry.Collector

func commandOutcome(command api.CommandOutcomeCommand, action api.CommandOutcomeAction, stage api.CommandOutcomeFailureStage, err error) api.CommandOutcome {
	payload := api.CommandOutcome{Command: command, Outcome: api.Succeeded}
	if action != "" {
		payload.Action = &action
	}
	if err == nil {
		return payload
	}
	payload.Outcome = api.Failed
	if code, ok := diagnostic.CodeOf(err); ok {
		value := string(code)
		payload.DiagnosticCode = &value
		if stage != api.Setup {
			switch code {
			case diagnostic.AuthenticationTimeout, diagnostic.AuthenticationRequired:
				stage = api.Authentication
			case diagnostic.TargetUnavailable, diagnostic.TargetInvalid:
				stage = api.LocalService
			case diagnostic.PublicURLInvalid, diagnostic.PublicURLConflict, diagnostic.DNSSetupPending, diagnostic.ProvisioningStalled:
				stage = api.PublicUrl
			}
		}
	}
	if code, _ := terminalResult(err); code == 0 {
		payload.Outcome, payload.DiagnosticCode = api.Canceled, nil
	} else {
		payload.FailureStage = &stage
	}
	return payload
}

func selectedTelemetryCommand(parsed *cobra.Command) (api.CommandOutcomeCommand, api.CommandOutcomeAction, bool) {
	command := strings.Fields(selectedPath(parsed))
	if len(command) == 0 {
		return "", "", false
	}
	if command[0] == "auth" {
		if len(command) < 2 || command[1] != "login" && command[1] != "logout" {
			return "", "", false
		}
		command = command[1:]
		if len(command) == 2 && command[1] == "run" {
			command = command[:1]
		}
	}
	name := api.CommandOutcomeCommand(command[0])
	if !name.Valid() {
		return "", "", false
	}
	var action api.CommandOutcomeAction
	if len(command) > 1 {
		action = api.CommandOutcomeAction(command[len(command)-1])
		if !action.Valid() {
			action = api.CommandOutcomeActionOther
		}
	}
	return name, action, true
}

func commandStateRoot(parsed *cobra.Command) (string, error) {
	stateDir := os.Getenv("TNL_STATE_DIR")
	if f := parsed.Flags().Lookup("state-dir"); f != nil && len(f.Annotations["env"]) != 0 {
		stateDir = f.Value.String()
	}
	return clientStateRoot(cliflags.ExpandPath(stateDir))
}

func closeTelemetry(ctx context.Context, close func(context.Context)) {
	ctx, stop := processFlushContext(ctx, clienttelemetry.RequestTimeout)
	defer stop()
	close(ctx)
}
