package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/client/supervisor"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/publisher/setup"
)

func TestSystemInstallLoadsConfiguredTargetBeforeSetup(t *testing.T) {
	root := t.TempDir()
	configuration := filepath.Join(root, "tnl.json")
	if err := os.WriteFile(configuration, []byte(`{"version":1,"tnl":{"services":{"opencode":{"public_url":{},"target":{"type":"app"}}}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var output, diagnostics bytes.Buffer
	err := run(t.Context(), []string{"--no-telemetry", "--config", configuration, "publish", "opencode", "--name", "opencode", "--install", "--system", "--state-dir", filepath.Join(root, "state")}, &output, &diagnostics)
	if reason, ok := failure.ReasonOf(err); !ok || reason != failure.InstalledTargetMissing {
		t.Fatal("system installation skipped configured target selection", err)
	}
	if output.Len() != 0 || diagnostics.Len() != 0 {
		t.Fatal("invalid configured target reached authentication or installation")
	}
}

func TestPrivateInstallationResultPreservesOnlyAnOwnedFailure(t *testing.T) {
	var output bytes.Buffer
	err := runPublicationRegister(t.Context(), serviceRegisterCommand{PrivateResult: true}, strings.NewReader(`{"job":{"access_token":"human-secret"}}`), &output,
		supervisor.ExecutorFunc(func(context.Context, supervisor.Command) error {
			t.Fatal("invalid private payload reached the supervisor")
			return nil
		}))
	if err != nil {
		t.Fatal(err)
	}
	var result setup.RegistrationResult
	if json.Unmarshal(output.Bytes(), &result) != nil || result.Reason != failure.InvalidTunnelFlags || result.Output != "" || bytes.Contains(output.Bytes(), []byte("human-secret")) {
		t.Fatal("private installer exposed raw input or lost its failure reason")
	}
}
