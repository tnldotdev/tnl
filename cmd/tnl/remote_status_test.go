package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"path/filepath"
	"testing"

	"github.com/tnldotdev/tnl/internal/failure"
)

func TestRemoteStatusAndWaitUsePublicPathWithoutProjectOrSignIn(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("TNL_STATE_DIR", filepath.Join(t.TempDir(), "missing-state"))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for range 2 {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			_, _ = io.WriteString(connection, "SSH-2.0-device\r\n")
			_ = connection.Close()
		}
	}()
	for _, command := range []string{"status", "wait"} {
		var output, diagnostics bytes.Buffer
		args := []string{"--no-telemetry", command, "--remote", listener.Addr().String(), "--protocol", "ssh", "--output", "json"}
		if err := run(t.Context(), args, &output, &diagnostics); err != nil {
			t.Fatalf("remote %s: %v", command, err)
		}
		var result struct {
			State     string `json:"state"`
			Reachable bool   `json:"reachable"`
			Protocol  string `json:"protocol"`
		}
		if err := json.Unmarshal(output.Bytes(), &result); err != nil || result.State != "reachable" || !result.Reachable || result.Protocol != "ssh" {
			t.Fatalf("remote %s output = %s, %v", command, output.String(), err)
		}
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	var output, diagnostics bytes.Buffer
	if err := run(t.Context(), []string{"--no-telemetry", "status", "--remote", listener.Addr().String(), "--protocol", "ssh", "--output", "json"}, &output, &diagnostics); err != nil {
		t.Fatal(err)
	}
	var absent struct {
		State     string `json:"state"`
		Reachable bool   `json:"reachable"`
	}
	if err := json.Unmarshal(output.Bytes(), &absent); err != nil || absent.State != "not reachable" || absent.Reachable {
		t.Fatalf("stopped publisher status = %s, %v", output.String(), err)
	}
	output.Reset()
	if err := run(t.Context(), []string{"--no-telemetry", "wait", "--remote", listener.Addr().String(), "--protocol", "ssh", "--timeout", "20ms", "--output", "json"}, &output, &diagnostics); err == nil {
		t.Fatal("remote wait accepted a closed visitor path")
	} else if reason, _, ok := failure.Describe(err); !ok || reason != failure.AppReadinessTimeout {
		t.Fatalf("remote wait timeout = %v", err)
	}
	if err := json.Unmarshal(output.Bytes(), &absent); err != nil || absent.State != "not reachable" || absent.Reachable {
		t.Fatalf("timed out remote wait = %s, %v", output.String(), err)
	}
}
