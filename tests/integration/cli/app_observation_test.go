package cli_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	"github.com/tnldotdev/tnl/internal/testutil"
)

func TestIntegrationCLIAppObservations(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	var env []string
	if keychain := testutil.UseClientKeychain(t); keychain != "" {
		env = append(env, "TNL_STATE_KEYCHAIN="+keychain)
	}
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "tnl.json")
	if err := os.WriteFile(config, []byte(`{
		"version": 1,
		"tnl": {
			"services": {"accounts": {}, "api": {}, "another": {}},
			"deployments": {"local": {"targets": {"accounts": {}, "api": {}, "another": {}}}}
		}
	}`), 0600); err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(dir, "state")
	state, err := clientstate.Open(t.Context(), stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	snapshot, err := publisherapp.ReadSnapshotFrom(t.Context(), state, dir)
	if err != nil {
		t.Fatal(err)
	}
	after := snapshot.Cursor
	for _, name := range []string{"api", "accounts", "another"} {
		if err := publisherapp.CommitSnapshot(t.Context(), state, &snapshot, "service.registered", new(publisherapp.Service{Name: name})); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("watch one matching event", func(t *testing.T) {
		got := runBuiltCLI(t, dir, env, "--config", config, "watch", "accounts", "--after", after,
			"--state-dir", stateDir, "--count", "1", "--timeout", "2s", "--output", "ndjson")
		var event publisherapp.Event
		if got.exit != 0 || got.stderr != "" || json.Unmarshal([]byte(got.stdout), &event) != nil ||
			event.Service == nil || event.Service.Name != "accounts" || event.Cursor == after || event.Cursor == snapshot.Cursor {
			t.Fatalf("expected exactly the middle event: %+v", got)
		}
		timedOut := runBuiltCLI(t, dir, env, "--config", config, "watch", "accounts", "--after", event.Cursor,
			"--state-dir", stateDir, "--count", "1", "--timeout", "100ms", "--output", "ndjson")
		if timedOut.stdout != "" {
			t.Fatalf("unrelated event became stdout: %+v", timedOut)
		}
		checkObservationFailure(t, timedOut, "TNL_CLIENT_APP_WATCH_TIMEOUT")
	})
	t.Run("expired cursor keeps the watch scope", func(t *testing.T) {
		got := runBuiltCLI(t, dir, env, "--config", config, "watch", "accounts", "--after", "expired",
			"--state-dir", stateDir, "--count", "1", "--timeout", "2s", "--output", "ndjson")
		checkObservationFailure(t, got, "TNL_CLIENT_APP_CURSOR_EXPIRED")
		var problem struct{ Command []string }
		want := []string{"tnl", "--config", config, "watch", "--service", "accounts", "--count", "1", "--timeout", "2s", "--state-dir", stateDir, "--output", "ndjson"}
		if err := json.Unmarshal([]byte(got.stderr), &problem); err != nil || !reflect.DeepEqual(problem.Command, want) || got.stdout != "" {
			t.Fatalf("expected scoped recovery without the expired cursor, got %+v (%v)", got, err)
		}
	})
	t.Run("wait for several services", func(t *testing.T) {
		got := runBuiltCLI(t, dir, env, "--config", config, "wait", "accounts", "api",
			"--state-dir", stateDir, "--timeout", "100ms", "--output", "json")
		checkObservationFailure(t, got, "TNL_CLIENT_APP_READINESS_TIMEOUT")
		var result struct {
			State    string
			Services []publisherapp.Service
		}
		if err := json.Unmarshal([]byte(got.stdout), &result); err != nil || result.State != "timed out" {
			t.Fatalf("expected the final timeout observation: %+v (%v)", got, err)
		}
		var selected []string
		for _, s := range result.Services {
			if s.Ready {
				t.Fatalf("recorded state was not a fresh check: %+v", s)
			}
			selected = append(selected, s.Name)
		}
		if !reflect.DeepEqual(selected, []string{"accounts", "api"}) {
			t.Fatalf("unexpected wait selection %v", selected)
		}
	})
	t.Run("configuration-free invocation is not a service selector", func(t *testing.T) {
		got := runBuiltCLI(t, dir, env, "--no-config", "wait", "--service", "ivk_0123456789abcdefghijkl",
			"--state-dir", stateDir, "--output", "json")
		if got.stdout != "" {
			t.Fatalf("unexpected output for an unsupported selection: %+v", got)
		}
		checkObservationFailure(t, got, "TNL_CLIENT_PROJECT_CONFIG_MISSING")
	})
}

func checkObservationFailure(t *testing.T, got cliResult, code string) {
	t.Helper()
	var problem struct{ Type, Code string }
	if got.exit != 1 || json.Unmarshal([]byte(got.stderr), &problem) != nil || problem.Type != "error" || problem.Code != code {
		t.Fatalf("expected one diagnostic %s on stderr: %+v", code, got)
	}
}
