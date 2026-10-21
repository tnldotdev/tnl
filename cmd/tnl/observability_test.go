package main

import (
	"bytes"
	"context"
	"testing"

	"github.com/tnldotdev/tnl/internal/observability"
)

func TestObservabilityRoleFollowsOwningCommand(t *testing.T) {
	for _, test := range []struct {
		command string
		role    observability.Role
	}{{"version", observability.RoleClient}, {"status", observability.RoleClient}, {"publisher enroll", observability.RoleClient}, {"connect start <name>", observability.RoleClient}, {"publish <service-or-target>", observability.RolePublisher}, {"publisher serve", observability.RolePublisher}, {"runtime serve", observability.RolePublisher}, {"service serve", observability.RolePublisher}} {
		if role := commandObservabilityRole(test.command, cli{}); role != test.role {
			t.Fatalf("%s: %s", test.command, role)
		}
	}
	var flags cli
	flags.Publish.Detach = true
	if commandObservabilityRole("publish <service-or-target>", flags) != observability.RoleClient {
		t.Fatal("launcher was classified as publisher")
	}
	flags.Publisher.Serve.Install = true
	if commandObservabilityRole("publisher serve", flags) != observability.RoleClient || persistentObservabilityOwner("publisher serve", flags) {
		t.Fatal("finite group installer was classified as a persistent owner")
	}
}

func TestVersionBypassesInvalidObservabilityConfiguration(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://invalid-secret")
	var stdout, stderr bytes.Buffer
	err := run(context.WithValue(t.Context(), nativeProcessKey{}, true), []string{"version"}, &stdout, &stderr)
	if err != nil || stdout.Len() == 0 || stderr.Len() != 0 {
		t.Fatal(err, stdout.String(), stderr.String())
	}
}
