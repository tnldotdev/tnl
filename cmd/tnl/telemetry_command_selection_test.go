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
		command telemetryTrackedCommand
		action  telemetryCommandAction
		tracked bool
	}{
		{[]string{"publish"}, telemetryPublish, "", true},
		{[]string{"team", "invite", "revoke", "ivt_secret"}, api.CommandOutcomeCommandTeam, api.CommandOutcomeActionRevoke, true},
		{[]string{"feedback", "inspect", "fb_secret"}, api.CommandOutcomeCommandFeedback, api.CommandOutcomeActionOther, true},
		{[]string{"version"}, "", "", false},
		{[]string{"telemetry", "on"}, "", "", false},
		{[]string{"runtime", "connections", "capabilities"}, "", "", false},
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
	var flags cli
	parser, err := kong.New(&flags)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parser.Parse([]string{"team", "invite", "revoke", "ivt_secret"})
	if err != nil {
		t.Fatal(err)
	}
	command, action, _ := selectedTelemetryCommand(parsed)
	event := clienttelemetry.Observation{Event: clienttelemetry.CommandCompleted, Command: command, Action: action}
	encoded, err := json.Marshal(event)
	if err != nil || !bytes.Contains(encoded, []byte(`"Command":"team"`)) || !bytes.Contains(encoded, []byte(`"Action":"revoke"`)) || bytes.Contains(encoded, []byte("ivt_secret")) {
		t.Fatalf("command observation includes arguments: %s %v", encoded, err)
	}
}
