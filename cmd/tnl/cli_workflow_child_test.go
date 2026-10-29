package main

import (
	"context"
	"flag"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/testutil"
)

var cliWorkflowBinary = flag.String("tnl-cli-binary", "", "CLI built by the workflow Task before child lifecycle deadlines")

func workflowExecutable(t *testing.T) string {
	t.Helper()
	if *cliWorkflowBinary == "" {
		t.Fatal("run task go:test:integration:cli to build the workflow CLI")
	}
	return *cliWorkflowBinary
}

// each real CLI workflow gets its own trust cache and protected state. the
// parent never changes infrastructure roots for other tests in the process.
func cliWorkflowInChild(t *testing.T) bool {
	t.Helper()
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	if runtime.GOOS != "linux" {
		t.Skip("real CLI state protection is qualified in the Linux integration target")
	}
	if *cliWorkflowChild {
		return true
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "-test.run=^"+regexp.QuoteMeta(t.Name())+"$", "-test.v", "-test.timeout=110s", "-tnl-test-tier=integration", "-tnl-test-postgres-url="+flag.Lookup("tnl-test-postgres-url").Value.String(), "-tnl-cli-binary="+*cliWorkflowBinary, "-tnl-cli-workflow-child")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("CLI workflow child: %v\n%s", err, output)
	}
	t.Logf("%s", output)
	return false
}
