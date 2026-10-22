package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/policy/publisherprovenance"
)

func TestPublisherDeploymentInvalidMetadataFailsBeforeIdentityState(t *testing.T) {
	t.Setenv(publisherprovenance.DeploymentIDEnv, "must-not-appear-in-diagnostics")
	state := filepath.Join(t.TempDir(), "state")
	var output, diagnostics bytes.Buffer
	err := run(t.Context(), []string{"--no-config", "publisher", "serve", "--group", "production", "--instance", "replica-1", "--state-dir", state}, &output, &diagnostics)
	if reason, _ := failure.ReasonOf(err); reason != failure.PublisherDeploymentMetadataInvalid {
		t.Fatal("wrong deployment validation boundary", err)
	}
	writeCommandError(&diagnostics, err)
	if bytes.Contains(diagnostics.Bytes(), []byte("must-not-appear")) || output.Len() != 0 {
		t.Fatal("metadata leaked into output")
	}
	if _, err := os.Lstat(state); !os.IsNotExist(err) {
		t.Fatal("invalid metadata opened client state")
	}
}
