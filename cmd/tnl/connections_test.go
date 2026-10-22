package main

import (
	"bytes"
	"encoding/json"
	"errors"
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
