package detached

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDetachedStartupFailureJoinsChild(t *testing.T) {
	for _, cancelWait := range []bool{false, true} {
		t.Run(map[bool]string{false: "presentation failed", true: "caller canceled"}[cancelWait], func(t *testing.T) {
			root, err := os.MkdirTemp("/tmp", "tnl-detached-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(root) })
			root, err = filepath.EvalSymlinks(root)
			if err != nil {
				t.Fatal(err)
			}
			root = filepath.Join(root, "state")
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			mode := "ready"
			if cancelWait {
				mode = "pending"
			}
			child, err := startDetachedProcess(binary, []string{"-test.run=^TestDetachedChildProcess$", "-tnl-detached-child-root=" + root, "-tnl-detached-child-mode=" + mode})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			failure := errors.New("presentation unavailable")
			want := failure
			if cancelWait {
				cancel()
				want = context.Canceled
			}
			const id = "abcdef0123456789abcdef01"
			err = awaitDetachedCommandReady(ctx, child, root, id, 5*time.Second, func(string) error { return failure })
			if !errors.Is(err, want) || child.ProcessState == nil {
				t.Fatal("startup failure did not preserve its cause and join the child", err)
			}
			if _, err := os.Lstat(filepath.Join(root, "d", id)); !os.IsNotExist(err) {
				t.Fatal("failed startup left its control socket", err)
			}
		})
	}
}
