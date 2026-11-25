package main

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/client/background"
)

type workflowCLIResult struct {
	stdout, stderr []byte
	err            error
}

func workflowBackgroundCLI(t *testing.T, f *cliWorkflow) func(context.Context, ...string) workflowCLIResult {
	t.Helper()
	binary := workflowExecutable(t)
	caFile := filepath.Join(t.TempDir(), "root.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.issuer.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "SSL_CERT_FILE="+caFile, "GODEBUG=x509usefallbackroots=0")
	return func(ctx context.Context, args ...string) workflowCLIResult {
		cmd := exec.CommandContext(ctx, binary, append([]string{"--no-config", "--no-telemetry"}, args...)...)
		cmd.Env = env
		var out, diagnostics bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &diagnostics
		err := cmd.Run()
		return workflowCLIResult{out.Bytes(), diagnostics.Bytes(), err}
	}
}

func cleanupBackgroundJobs(t *testing.T, stateDir string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	entries, err := background.List(ctx, stateDir)
	if err != nil {
		t.Error(err)
		return
	}
	for _, entry := range entries {
		if _, err := background.Stop(ctx, stateDir, entry.JobID); err != nil && !errors.Is(err, background.ErrNotFound) {
			t.Error(err)
		}
		waitBackgroundJobExit(t, ctx, stateDir, entry.JobID)
	}
}

func waitBackgroundJobExit(t *testing.T, ctx context.Context, stateDir, jobID string) {
	t.Helper()
	workflowWait(t, 20*time.Second, func() bool {
		_, err := background.Status(ctx, stateDir, jobID)
		return errors.Is(err, background.ErrNotFound)
	})
}
