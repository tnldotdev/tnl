package main

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/alecthomas/kong"
	clienttelemetry "github.com/tnldotdev/tnl/internal/client/telemetry"
	api "github.com/tnldotdev/tnl/pkg/api/integrations/telemetry/v1"
)

func TestTelemetryCommandsUseOnlyParsedCommandNodes(t *testing.T) {
	for _, test := range []struct {
		args    []string
		command api.CommandOutcomeCommand
		action  api.CommandOutcomeAction
		tracked bool
	}{
		{[]string{"publish"}, "publish", "", true},
		{[]string{"auth", "login"}, "login", "", true},
		{[]string{"auth", "logout"}, "logout", "", true},
		{[]string{"team", "invite", "revoke", "ivt_secret"}, "team", "revoke", true},
		{[]string{"feedback", "inspect", "fb_secret"}, "feedback", "inspect", true},
		{[]string{"share"}, "share", "create", true},
		{[]string{"share", "--service", "web"}, "share", "create", true},
		{[]string{"version"}, "", "", false},
		{[]string{"telemetry", "on"}, "", "", false},
	} {
		var flags cli
		parser, err := kong.New(&flags)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := parser.Parse(test.args)
		if err != nil {
			t.Fatalf("%v: %v", test.args, err)
		}
		command, action, tracked := selectedTelemetryCommand(parsed)
		if command != test.command || action != test.action || tracked != test.tracked {
			t.Fatalf("%v: command=%q action=%q tracked=%t", test.args, command, action, tracked)
		}
	}
}

func TestTelemetryCommandWireExcludesArguments(t *testing.T) {
	action := api.CommandOutcomeActionRevoke
	payload := clienttelemetry.Command(api.CommandOutcome{Command: "team", Action: &action, Outcome: api.Succeeded})
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, []byte(`"command":"team"`)) ||
		!bytes.Contains(encoded, []byte(`"action":"revoke"`)) || bytes.Contains(encoded, []byte("ivt_secret")) {
		t.Fatalf("command telemetry = %s", encoded)
	}
}
