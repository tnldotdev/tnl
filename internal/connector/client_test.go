package connector

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestForegroundClientStartsOnceAndJoinsConnector(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "runs")
	var out bytes.Buffer
	joined := false
	err := foregroundClient(t.Context(), "", []string{"sh", "-c", `echo run >> "$1"; printf %s "$TNL_CONNECTION_PROFILE"; exit 23`, "sh", marker}, nil, &out, io.Discard, func(ctx context.Context, ready func(Profile) error) error {
		for range 2 {
			if err := ready(Profile{Schema: 1, Hostname: "orders.example"}); err != nil {
				return err
			}
		}
		<-ctx.Done()
		joined = true
		return ctx.Err()
	})
	var exit *ClientExit
	data, readErr := os.ReadFile(marker)
	if !joined || !errors.As(err, &exit) || exit.Code != 23 || string(data) != "run\n" || readErr != nil || !strings.Contains(out.String(), `"hostname":"orders.example"`) {
		t.Fatalf("joined=%t, runs=%q, stdout=%q, err=%v", joined, data, out.String(), err)
	}
}

func TestForegroundClientStopsOnFailureOrInterrupt(t *testing.T) {
	for _, interrupt := range []bool{false, true} {
		ctx, cancel := context.WithCancel(t.Context())
		fault := errors.New("connector failed")
		err := foregroundClient(ctx, "", []string{"sleep", "60"}, nil, io.Discard, io.Discard, func(ctx context.Context, ready func(Profile) error) error {
			if err := ready(Profile{}); err != nil {
				return err
			}
			if interrupt {
				cancel()
				return ctx.Err()
			}
			return fault
		})
		cancel()
		if interrupt && !errors.Is(err, context.Canceled) || !interrupt && !errors.Is(err, fault) {
			t.Fatal(err)
		}
	}
	err := foregroundClient(t.Context(), "", []string{"tnl-missing-client-executable"}, nil, io.Discard, io.Discard, func(_ context.Context, ready func(Profile) error) error { return ready(Profile{}) })
	if !errors.Is(err, exec.ErrNotFound) {
		t.Fatal(err)
	}
}

func TestDumpUsesVerifiedLibpqProfile(t *testing.T) {
	p := Profile{Protocol: "postgres", Command: []string{"psql", "postgresql://orders.example:15432/?hostaddr=127.0.0.1&sslmode=verify-full"}}
	argv, err := clientArgv(p, "pg_dump", []string{"--schema-only"})
	if err != nil || len(argv) != 4 || argv[1] != "--dbname" || argv[2] != p.Command[1] || argv[3] != "--schema-only" {
		t.Fatal(argv, err)
	}
	if _, err := clientArgv(p, "nc", nil); err == nil {
		t.Fatal("accepted incompatible adapter")
	}
}
