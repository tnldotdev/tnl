package main

import (
	"context"
	"os"

	"github.com/alecthomas/kong"
	clienttelemetry "github.com/tnldotdev/tnl/internal/client/telemetry"
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

func selectedTelemetryCommand(parsed *kong.Context) (api.CommandOutcomeCommand, api.CommandOutcomeAction, bool) {
	var command []string
	for _, element := range parsed.Path {
		if element.Command != nil && element.Command.Type == kong.CommandNode {
			command = append(command, element.Command.Name)
		}
	}
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

func commandStateRoot(parsed *kong.Context) (string, error) {
	stateDir := os.Getenv("TNL_STATE_DIR")
	if stateDir != "" {
		stateDir = kong.ExpandPath(stateDir)
	}
	for _, flag := range parsed.Flags() {
		if flag.Name != "state-dir" || !hasEnvironment(flag.Envs, "TNL_STATE_DIR") {
			continue
		}
		if value, ok := parsed.FlagValue(flag).(string); ok {
			stateDir = value
		}
	}
	return clientStateRoot(stateDir)
}

func hasEnvironment(environments []string, name string) bool {
	for _, environment := range environments {
		if environment == name {
			return true
		}
	}
	return false
}

func closeTelemetry(c *clienttelemetry.Collector) {
	ctx, stop := context.WithTimeout(context.Background(), clienttelemetry.RequestTimeout)
	defer stop()
	c.Close(ctx)
}
