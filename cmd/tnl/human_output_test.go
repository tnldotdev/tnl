package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/oidcauth"
)

func TestAuthenticationPromptUsesCommandFrame(t *testing.T) {
	var output bytes.Buffer
	prompt := authenticationPrompt(&output, "tnl login")
	if err := prompt(oidcauth.Prompt{URL: "https://account.example/device", Code: "ABCD-EFGH"}); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	for _, fragment := range []string{
		"+--[ tnl login ]-- authentication required ",
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
	if err := writeHumanTransition(&output, "tnl route delete", "deleted", "route.example", "", "route deleted", ""); err != nil {
		t.Fatal(err)
	}
	got := output.String()
	for _, fragment := range []string{
		"+--[ tnl route delete ]-- deleted ",
		"route.example",
		"route deleted",
	} {
		if !strings.Contains(got, fragment) {
			t.Fatalf("transition does not contain %q:\n%s", fragment, got)
		}
	}
}

func TestHumanOutputLabels(t *testing.T) {
	if got := countState(1, "route", "routes"); got != "1 route" {
		t.Fatalf("singular count = %q", got)
	}
	if got := countState(2, "route", "routes"); got != "2 routes" {
		t.Fatalf("plural count = %q", got)
	}
	if allowedState(true) != "allowed" || allowedState(false) != "blocked" {
		t.Fatal("enabled state labels are inconsistent")
	}
}
