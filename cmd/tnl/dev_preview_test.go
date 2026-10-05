package main

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type previewControlStub struct {
	id   string
	keys []string
}

func (c *previewControlStub) CreateWorktreePreview(_ context.Context, teamID, key string) (controlv1.WorktreePreview, error) {
	c.keys = append(c.keys, key)
	return controlv1.WorktreePreview{Id: c.id, TeamId: teamID}, nil
}

func (*previewControlStub) AddWorktreePreviewPublicURL(_ context.Context, _, _ string) (controlv1.WorktreePreview, error) {
	panic("not called")
}

func TestEnsureWorktreePreviewPersistsServerIdentityForCheckout(t *testing.T) {
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
	id, err := opaqueid.New(opaqueid.WorktreePreviewPrefix)
	if err != nil {
		t.Fatal(err)
	}
	control := &previewControlStub{id: id}
	for range 2 {
		got, err := ensureWorktreePreview(ctx, state, store, control, server, "team_1", "/project/checkout")
		if err != nil || got != id {
			t.Fatalf("preview identity = %q, %v", got, err)
		}
	}
	if len(control.keys) != 2 || control.keys[0] != control.keys[1] || control.keys[0] == "" {
		t.Fatalf("create requests did not share a stable idempotency key: %v", control.keys)
	}
	saved, found, err := store.WorktreePreviewID(ctx, "team_1", "/project/checkout")
	if err != nil || !found || saved != id {
		t.Fatalf("saved preview = %q, %v, %v", saved, found, err)
	}
	other, err := opaqueid.New(opaqueid.WorktreePreviewPrefix)
	if err != nil {
		t.Fatal(err)
	}
	control.id = other
	if _, err := ensureWorktreePreview(ctx, state, store, control, server, "team_1", "/project/checkout"); err == nil {
		t.Fatal("server reassigned an existing checkout to another preview")
	}
}
