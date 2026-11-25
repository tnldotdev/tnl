package cli_test

import (
	"encoding/csv"
	"os/exec"
	"regexp"
	"slices"
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
	examples := regexp.MustCompile("(?m)^```sh\n"+`tnl ([^\n]+)`+"\n```$").FindAllStringSubmatch(string(output), -1)
	if len(examples) == 0 {
		t.Fatal("no command examples")
	}
	for _, example := range examples {
		reader := csv.NewReader(strings.NewReader(example[1]))
		reader.Comma = ' '
		args, err := reader.Read()
		if err != nil {
			t.Fatalf("guide example %q: %v", example[1], err)
		}
		at := slices.Index(args, "--")
		if at == -1 {
			at = len(args)
		}
		out, err := exec.CommandContext(t.Context(), *cliBinary, slices.Insert(args, at, "--help")...).CombinedOutput()
		if err != nil || !strings.Contains(string(out), "Usage:") {
			t.Fatalf("%v: %s (%v)", args, out, err)
		}
	}
}
