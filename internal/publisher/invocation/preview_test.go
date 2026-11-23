package invocation

import (
	"context"
	"os/exec"
	"path/filepath"
	"testing"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type previewControlStub struct {
	id   string
	keys []string
}

func (c *previewControlStub) CreatePreview(_ context.Context, teamID, key string) (controlv1.Preview, error) {
	c.keys = append(c.keys, key)
	return controlv1.Preview{Id: c.id, TeamId: teamID}, nil
}

func TestEnsurePreviewPersistsServerIdentityForCheckout(t *testing.T) {
	ctx := t.Context()
	state, err := clientstate.Open(ctx, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	server := "https://control.example.test"
	store, err := state.Server(ctx, server)
	if err != nil {
		t.Fatal(err)
	}
	id, err := opaqueid.New(opaqueid.PreviewPrefix)
	if err != nil {
		t.Fatal(err)
	}
	control := &previewControlStub{id: id}
	parent := t.TempDir()
	main, checkout, moved := filepath.Join(parent, "main"), filepath.Join(parent, "perf"), filepath.Join(parent, "faster")
	git := func(args ...string) {
		t.Helper()
		if out, err := exec.CommandContext(ctx, "git", args...).CombinedOutput(); err != nil {
			t.Fatalf("git: %v: %s", err, out)
		}
	}
	localKey := func(root string) string {
		t.Helper()
		tree, err := clientproject.ResolveWorktree(ctx, root)
		if err != nil {
			t.Fatal(err)
		}
		p, err := (clientproject.Project{Root: root, Worktree: tree}).BindLocalIdentity(ctx, state)
		if err != nil {
			t.Fatal(err)
		}
		return p.LocalWorktreeKey()
	}
	git("init", "-q", main)
	git("-C", main, "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "--allow-empty", "-qm", "initial")
	git("-C", main, "worktree", "add", "-q", "--detach", checkout)
	usePreview := func(worktreeKey string) {
		t.Helper()
		got, err := ensurePreview(ctx, state, store, control, server, "team_1", worktreeKey)
		if err != nil || got != id {
			t.Fatalf("preview identity = %q, %v", got, err)
		}
	}
	usePreview(localKey(checkout))
	git("-C", main, "worktree", "move", checkout, moved)
	movedKey := localKey(moved)
	usePreview(movedKey)
	if len(control.keys) != 2 || control.keys[0] != control.keys[1] || control.keys[0] == "" {
		t.Fatalf("create requests did not share a stable idempotency key: %v", control.keys)
	}
	saved, found, err := store.PreviewID(ctx, "team_1", movedKey)
	if err != nil || !found || saved != id {
		t.Fatalf("saved preview = %q, %v, %v", saved, found, err)
	}
	other, err := opaqueid.New(opaqueid.PreviewPrefix)
	if err != nil {
		t.Fatal(err)
	}
	control.id = other
	if _, err := ensurePreview(ctx, state, store, control, server, "team_1", movedKey); err == nil {
		t.Fatal("server reassigned an existing checkout to another preview")
	}
	git("-C", main, "worktree", "add", "-q", "--detach", checkout)
	newKey := localKey(checkout)
	if _, found, err := store.PreviewID(ctx, "team_1", newKey); err != nil || found {
		t.Fatalf("new checkout inherited the original preview: %v, %v", found, err)
	}
	if got, err := ensurePreview(ctx, state, store, control, server, "team_1", newKey); err != nil || got != other || control.keys[3] == control.keys[0] {
		t.Fatalf("new checkout did not get a separate preview: %q, %v", got, err)
	}
}
