package main

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/client/auth"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
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

func TestCopyableCommandPreservesPathBytes(t *testing.T) {
	for _, name := range []string{"sh", "bash", "zsh", "fish"} {
		t.Run(name, func(t *testing.T) {
			shell, err := exec.LookPath(name)
			if err != nil {
				t.Skip("shell not installed")
			}
			paths := []string{"my project's files", `two\\slashes\`, "café's files/資料", "x$(exit 1)\\$\n\tend", "\xff1"}
			if name == "bash" || name == "zsh" {
				paths = append(paths, "ends in newlines\n\n")
			}
			for _, path := range paths {
				var out bytes.Buffer
				if err := writeResult(&out, clioutput.Literal("printf '%s' --state-dir="+shellWord(path))); err != nil {
					t.Fatal(err)
				}
				got, err := exec.Command(shell, "-c", out.String()).Output()
				if err != nil || string(got) != "--state-dir="+path {
					t.Fatalf("pasted %q: got %q, %v", out.String(), got, err)
				}
			}
		})
	}
}

func TestUnconfiguredServiceNamesOnlyValidSelectorsInHumanOutput(t *testing.T) {
	for _, name := range []string{"acounts", "untrusted\nselector"} {
		err := unconfiguredService(name)
		var output bytes.Buffer
		writeCommandError(&output, err)
		if name == "acounts" && !strings.Contains(output.String(), `Service "acounts" is not configured.`) ||
			name != "acounts" && strings.Contains(output.String(), "untrusted") {
			t.Fatalf("human error: %q", output.String())
		}
		machine := commandDiagnosticFor(err)
		if machine.Reason != string(failure.ServiceNotConfigured) || machine.Message != "the selected service is not configured" {
			t.Fatalf("machine diagnostic: %+v", machine)
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
