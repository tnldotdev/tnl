package main

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
)

func TestIntegrationURLProgressFailureStopsTheTunnelWithItsCause(t *testing.T) {
	state, err := clientstate.Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	tunnel, err := state.BeginTunnel(t.Context(), clientstate.BeginTunnelOptions{
		Command: clientstate.TunnelCommandPublish, Server: "https://control.example.test", Target: "3000", Project: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Finish(context.Background(), nil)
	cause := errors.New("private output destination failed with secret")
	output := &publishOutput{command: "tnl publish", stderr: errorWriter{err: cause}}
	reportIntegrationURL(tunnel, output, "oauth ready", "", clioutput.Text("https://oauth.example.test"))
	select {
	case <-tunnel.Context().Done():
	default:
		t.Fatal("integration URL output failure did not stop the tunnel")
	}
	reported := context.Cause(tunnel.Context())
	if reason, ok := failure.ReasonOf(reported); !ok || reason != failure.OutputUnavailable || !errors.Is(reported, cause) {
		t.Fatalf("integration URL output cause = %v", reported)
	}
	definition, _ := failure.DefinitionFor(failure.OutputUnavailable)
	if definition.Message == "" || definition.Action == "" {
		t.Fatal("output error did not have safe presentation")
	}
}
