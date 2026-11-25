package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	"github.com/tnldotdev/tnl/internal/failure"
)

func TestRuntimeConnectionsStopRequiresJoinedCleanup(t *testing.T) {
	for _, tc := range []struct {
		name, record string
		expired      bool
		want         failure.Reason
	}{
		{name: "missing handle and record", want: failure.ConnectionCleanupFailed},
		{name: "expired handle and missing record", expired: true, want: failure.ConnectionCleanupFailed},
		{name: "failed cleanup", record: `{"schema":1,"clean":false}`, want: failure.ConnectionCleanupFailed},
		{name: "joined cleanup", record: `{"schema":1,"clean":true}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, err := connectorruntime.NewDirectory(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			handle := filepath.Join(dir, "handle.json")
			if tc.expired {
				if err := connectorruntime.WriteHandle(handle, connectorruntime.Handle{
					Schema: 1, Directory: dir, URL: "http://127.0.0.1:1",
					Key:          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					ConfigDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
					ExpiresAt:    time.Now().Add(-time.Minute),
				}); err != nil {
					t.Fatal(err)
				}
			}
			if tc.record != "" {
				if err := os.WriteFile(filepath.Join(dir, "stopped.json"), []byte(tc.record), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			const receipt = "{\"schema\":1,\"state\":\"stopped\"}\n"
			var out, diagnostics bytes.Buffer
			err = run(t.Context(), []string{"runtime", "connections", "stop", "--handle", handle}, &out, &diagnostics)
			if tc.want == "" {
				if err != nil || out.String() != receipt {
					t.Fatalf("joined stop: output %q, error %v", &out, err)
				}
			} else if reason, _ := failure.ReasonOf(err); reason != tc.want || out.Len() != 0 {
				t.Fatalf("unconfirmed stop: output %q, reason %q, error %v", &out, reason, err)
			}
			if tc.record == "" {
				out.Reset()
				if err := run(t.Context(), []string{"runtime", "connections", "recover", "--handle", handle}, &out, &diagnostics); err != nil || out.String() != receipt {
					t.Fatalf("owner without a lock should be replaceable: output %q, error %v", &out, err)
				}
			}
		})
	}
}
