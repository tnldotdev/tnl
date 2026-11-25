package main

import (
	"errors"
	"io"
	"path/filepath"
	"slices"
	"testing"

	"github.com/tnldotdev/tnl/internal/failure"
)

func TestCheckoutRecoveryKeepsDirectoryAndLeavesChildFlagsAlone(t *testing.T) {
	const checkout = "/path with spaces/checkout"
	t.Setenv("TNL_CONFIG", "tnl.yml")
	flags := cli{Cwd: checkout, Wait: waitCommand{Service: []string{"accounts"}}}
	err := failure.Wrap("wait for service", failure.AppReadinessTimeout, errors.New("fixture timed out"))
	want := []string{"tnl", "--cwd", checkout, "--config", "tnl.yml", "status", "--last-known", "--service", "accounts"}
	if got := commandDiagnosticFor(observationFollowup(err, flags)).Command; !slices.Equal(got, want) {
		t.Fatalf("recovery = %q, want %q", got, want)
	}
	var parsed cli
	command := commandForTest(&parsed, io.Discard)
	args := []string{"--cwd", ".", "connect", "orders", "--client", "psql", "--", "--cwd", "client-options"}
	absolute, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := command(args); err != nil || parsed.Cwd != absolute ||
		!slices.Equal(parsed.Connect.Start.clientArgs, []string{"--cwd", "client-options"}) {
		t.Fatalf("did not keep the child args: checkout=%q args=%q err=%v", parsed.Cwd, parsed.Connect.Start.clientArgs, err)
	}
	root, err := resolveCheckout(t.TempDir())
	if err != nil || !filepath.IsAbs(root) {
		t.Fatalf("checkout not canonical: %q, %v", root, err)
	}
}
