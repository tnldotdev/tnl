package detached

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/connector"
)

func TestDetachedLaunchReadsConnectionThroughLongSymlinkedAncestor(t *testing.T) {
	// the canonical socket path must fit even when the requested ancestor does not.
	short, err := os.MkdirTemp("/tmp", "tnl-detached-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(short) })
	short, err = filepath.EvalSymlinks(short)
	if err != nil {
		t.Fatal(err)
	}
	ancestor := filepath.Join(t.TempDir(), strings.Repeat("long-ancestor-", 12))
	if err := os.Mkdir(ancestor, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(ancestor, "alias")
	if err := os.Symlink(short, alias); err != nil {
		t.Fatal(err)
	}
	root, canonical := filepath.Join(alias, "state"), filepath.Join(short, "state")
	const id = "abcdef0123456789abcdef01"
	t.Cleanup(func() { _, _ = Request(canonical, id, "stop") })
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"-test.run=^TestDetachedChildProcess$", "-tnl-detached-child-root=" + root, "-tnl-detached-child-mode=connection-postgres"}
	var readyPID string
	err = launchWithOptions(t.Context(), root, id, binary, args, clientstate.OpenOptions{Protection: clientstate.ProtectionFile}, func(root, pid string) error {
		readyPID = pid
		if root != canonical {
			return fmt.Errorf("ready callback root = %q, want %q", root, canonical)
		}
		data, err := ReadConnection(root, id)
		if err != nil {
			return fmt.Errorf("read prepared connection: %w", err)
		}
		var profile connector.Profile
		if err := json.Unmarshal(data, &profile); err != nil {
			return err
		}
		if profile.Protocol != "postgres" || profile.Host != "127.0.0.1" || profile.Port != 15432 || !profile.ConnectorRequired {
			return fmt.Errorf("unexpected prepared connection: %+v", profile)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if readyPID == "" {
		t.Fatal("launch did not report readiness")
	}
	if state, pid, err := Status(canonical, id); err != nil || state != "ready" || pid != readyPID {
		t.Fatal("reading the prepared connection stopped or replaced the ready child", state, pid, err)
	}
	if _, err := Request(canonical, id, "stop"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 3*time.Second, func() bool {
		_, err := os.Lstat(filepath.Join(canonical, "d", id))
		return os.IsNotExist(err)
	})
}
