package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/failure"
)

func TestRetainedPublicationNeverFallsBackToOperatorLogin(t *testing.T) {
	flags := publishCommand{Target: "http://127.0.0.1:4096", Enrolled: true}
	flags.StateDir = filepath.Join(t.TempDir(), "publisher")
	flags.ServerURL = "https://control.example"
	_, err := retainedPublishFlags(t.Context(), flags)
	if typed, ok := failure.Of(err); !ok || typed.Reason() != failure.PublisherEnrollmentRequired {
		t.Fatalf("missing state attempted operator authentication: %v", err)
	}
	for _, change := range []func(*publishCommand){
		func(f *publishCommand) { f.Team = "studio" },
		func(f *publishCommand) { f.Name = "opencode" },
		func(f *publishCommand) { f.Anonymous = true },
		func(f *publishCommand) { f.AccessToken = "human-secret" },
	} {
		changed := flags
		change(&changed)
		_, err := retainedPublishFlags(t.Context(), changed)
		if typed, ok := failure.Of(err); !ok || typed.Reason() != failure.InvalidTunnelFlags {
			t.Fatal("retained mode accepted operator scope or policy", err)
		}
	}
}

func TestPublisherImageRequiresAnImmutableDigest(t *testing.T) {
	for _, value := range []string{"ghcr.io/tnldotdev/tnl:latest", "ghcr.io/tnldotdev/tnl@sha256:short", "user:secret@registry.example/tnl@sha256:" + strings.Repeat("a", 64)} {
		if err := validatePublisherImage(func(string) (string, bool) { return value, true }); err == nil {
			t.Fatal("mutable or invalid image accepted")
		}
	}
	if err := validatePublisherImage(func(string) (string, bool) { return "ghcr.io/tnldotdev/tnl@sha256:" + strings.Repeat("a", 64), true }); err != nil {
		t.Fatal(err)
	}
}
