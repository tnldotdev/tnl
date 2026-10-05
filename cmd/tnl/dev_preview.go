package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type worktreePreviewControl interface {
	CreateWorktreePreview(context.Context, string, string) (controlv1.WorktreePreview, error)
	AddWorktreePreviewPublicURL(context.Context, string, string) (controlv1.WorktreePreview, error)
}

func ensureWorktreePreview(ctx context.Context, state *clientstate.Database, store *clientstate.Store, control worktreePreviewControl, server, teamID, projectRoot string) (string, error) {
	if teamID == "" || projectRoot == "" || server == "" {
		return "", errors.New("worktree preview requires one server, team, and project")
	}
	salt, err := state.WorktreeHashSalt(ctx)
	if err != nil {
		return "", err
	}
	hash := hmac.New(sha256.New, salt[:])
	_, _ = hash.Write([]byte(server + "\x00" + teamID + "\x00" + projectRoot))
	key := hex.EncodeToString(hash.Sum(nil))
	preview, err := control.CreateWorktreePreview(ctx, teamID, key)
	if err != nil {
		return "", fmt.Errorf("create worktree preview: %w", err)
	}
	if !opaqueid.Valid(preview.Id, opaqueid.WorktreePreviewPrefix) || preview.TeamId != teamID {
		return "", errors.New("server returned an invalid worktree preview")
	}
	if saved, found, err := store.WorktreePreviewID(ctx, teamID, projectRoot); err != nil {
		return "", err
	} else if found && saved != preview.Id {
		return "", errors.New("saved worktree preview differs from the server; check the selected team and client state")
	}
	if err := store.SaveWorktreePreviewID(ctx, teamID, projectRoot, preview.Id); err != nil {
		return "", err
	}
	return preview.Id, nil
}
