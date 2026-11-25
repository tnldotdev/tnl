package main

import (
	"bytes"
	"testing"

	"github.com/tnldotdev/tnl/internal/client/auth"
)

func TestAuthenticationPromptShowsApprovalURLAndVerificationCode(t *testing.T) {
	var output bytes.Buffer
	prompt := authenticationPrompt(&output, "tnl auth login")
	if err := prompt(auth.Prompt{URL: "https://account.example/device", Code: "ABCD-EFGH"}); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); got != "Open this URL to sign in:\nhttps://account.example/device\nMatch code: ABCD-EFGH\n" {
		t.Fatalf("authentication prompt = %q", got)
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
