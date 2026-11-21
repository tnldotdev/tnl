package cli_test

import (
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/testutil"
)

func TestIntegrationCLIGuideExamples(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	output, err := exec.CommandContext(t.Context(), *cliBinary, "agent-guide", "--skill").Output()
	if err != nil || !strings.HasPrefix(string(output), "---\nname: tnl\n") {
		t.Fatal("cannot load skill", err)
	}
	version, err := exec.CommandContext(t.Context(), *cliBinary, "version").Output()
	if err != nil || !strings.Contains(string(output), strings.TrimSpace(string(version))) {
		t.Fatal("guide does not match installed version")
	}
	examples := regexp.MustCompile("(?m)^`tnl ([^`]+)`$").FindAllStringSubmatch(string(output), -1)
	if len(examples) == 0 {
		t.Fatal("no command examples")
	}
	for _, example := range examples {
		args := strings.Fields(example[1])
		out, err := exec.CommandContext(t.Context(), *cliBinary, append(args, "--help")...).CombinedOutput()
		if err != nil || !strings.Contains(string(out), "Usage:") {
			t.Fatalf("%v: %s (%v)", args, out, err)
		}
	}
}
