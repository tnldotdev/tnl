package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/oidcauth"
)

func TestAuthenticationPromptUsesCommandFrame(t *testing.T) {
	var output bytes.Buffer
	prompt := authenticationPrompt(&output, "tnl auth login")
	if err := prompt(oidcauth.Prompt{URL: "https://account.example/device", Code: "ABCD-EFGH"}); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	for _, fragment := range []string{
		"+--[ tnl auth login ]-- authentication required ",
		"https://account.example/device",
		"ABCD-EFGH",
		"+-- waiting for authentication ",
	} {
		if !strings.Contains(got, fragment) {
			t.Fatalf("authentication prompt does not contain %q:\n%s", fragment, got)
		}
	}
}

func TestHumanTransitionUsesSharedShape(t *testing.T) {
	var output bytes.Buffer
	if err := writeHumanTransition(&output, "tnl url delete", "deleted", "route.example", "", "public URL deleted", ""); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	for _, fragment := range []string{
		"+--[ tnl url delete ]-- deleted ",
		"route.example",
		"public URL deleted",
	} {
		if !strings.Contains(got, fragment) {
			t.Fatalf("transition does not contain %q:\n%s", fragment, got)
		}
	}
}

func TestHumanOutputLabels(t *testing.T) {
	if got := countState(1, "public URL", "public URLs"); got != "1 public URL" {
		t.Fatalf("singular count = %q", got)
	}
	if got := countState(2, "public URL", "public URLs"); got != "2 public URLs" {
		t.Fatalf("plural count = %q", got)
	}
	if allowedState(true) != "allowed" || allowedState(false) != "blocked" {
		t.Fatal("enabled state labels are inconsistent")
	}
}
