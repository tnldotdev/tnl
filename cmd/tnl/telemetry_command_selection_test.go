package main

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/alecthomas/kong"
)

func TestTelemetryCommandsUseOnlyParsedCommandNodes(t *testing.T) {
	for _, test := range []struct {
		args    []string
		command telemetryTrackedCommand
		action  telemetryCommandAction
		tracked bool
	}{
		{[]string{"dev"}, telemetryDev, "", true},
		{[]string{"team", "invite", "revoke", "ivt_secret"}, "team invite", "revoke", true},
		{[]string{"feedback", "inspect", "fb_secret"}, "feedback", "inspect", true},
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
	payload := newTelemetryStarted("team invite")
	payload.Action = "revoke"
	payload.InvocationID = "ivk_0123456789abcdefghijkl"
	encoded, err := json.Marshal(payload.wireEvent("tev_0123456789abcdefghijkl"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, []byte(`"command":"team invite"`)) ||
		!bytes.Contains(encoded, []byte(`"action":"revoke"`)) || bytes.Contains(encoded, []byte("ivt_secret")) {
		t.Fatalf("command telemetry = %s", encoded)
	}
}
