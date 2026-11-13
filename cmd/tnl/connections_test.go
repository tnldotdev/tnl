package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/tnldotdev/tnl/internal/connector"
	"github.com/tnldotdev/tnl/internal/failure"
)

func TestConnectionMachineErrorsAreOwnedAndSafeWithoutOutputFlag(t *testing.T) {
	var output bytes.Buffer
	err := run(t.Context(), []string{"runtime", "connections", "status", "--handle", "/missing/secret-handle"}, &output, &output)
	var machine *machineCommandError
	if !errors.As(err, &machine) {
		t.Fatal("machine command returned a human error", err)
	}
	writeCommandError(&output, err)
	var diagnostic map[string]any
	if json.Unmarshal(output.Bytes(), &diagnostic) != nil || diagnostic["reason"] != string(failure.ConnectionHandleInvalid) || bytes.Contains(output.Bytes(), []byte("secret-handle")) {
		t.Fatal("unsafe machine diagnostic", output.String())
	}
	if connector.Reason(syscall.EADDRINUSE) != failure.ConnectionPortInUse {
		t.Fatal("port collision lost its boundary")
	}
}

func TestLocalConnectionCommandNeedsNoLoginOrClientState(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "absent-client-state")
	t.Setenv("TNL_STATE_DIR", state)
	t.Setenv("TNL_CONFIG", "")
	configuration := `{"version":1,"tnl":{"services":{"db":{"protocol":"postgres","target":{"type":"address","address":"127.0.0.1:15432"}}}}}`
	if err := os.WriteFile(filepath.Join(root, "tnl.json"), []byte(configuration), 0600); err != nil {
		t.Fatal(err)
	}
	var output, diagnostics bytes.Buffer
	err := run(t.Context(), []string{"runtime", "connections", "local", "--directory", root, "--service", "db", "--protocol", "postgres"}, &output, &diagnostics)
	if err != nil {
		t.Fatal(err)
	}
	var connection connector.LocalConnection
	if err := json.Unmarshal(output.Bytes(), &connection); err != nil || connection.Schema != 1 || connection.Protocol != "postgres" || connection.Port != 15432 || connection.Host != "127.0.0.1" || connection.SSL != nil || len(connection.Binding) != 64 {
		t.Fatalf("local connection response: %+v %v", connection, err)
	}
	if diagnostics.Len() != 0 {
		t.Fatal("local selection printed diagnostics", diagnostics.String())
	}
	if _, err := os.Stat(state); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("local selection created client state", err)
	}
}

func TestLocalConnectionCommandRejectsRemoteTargetsWithoutLeakingThem(t *testing.T) {
	root := t.TempDir()
	t.Setenv("TNL_CONFIG", "")
	configuration := `{"version":1,"tnl":{"services":{"db":{"protocol":"postgres","target":{"type":"address","address":"private-customer-db.internal:5432"}}}}}`
	if err := os.WriteFile(filepath.Join(root, "tnl.json"), []byte(configuration), 0600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	err := run(t.Context(), []string{"runtime", "connections", "local", "--directory", root, "--service", "db", "--protocol", "postgres"}, &output, &output)
	var machine *machineCommandError
	if !errors.As(err, &machine) {
		t.Fatal("local selection returned a human error", err)
	}
	writeCommandError(&output, err)
	var diagnostic map[string]any
	if json.Unmarshal(output.Bytes(), &diagnostic) != nil || diagnostic["reason"] != string(failure.TargetUnavailable) || bytes.Contains(output.Bytes(), []byte("private-customer")) {
		t.Fatal("unsafe local connection diagnostic", output.String())
	}
}
