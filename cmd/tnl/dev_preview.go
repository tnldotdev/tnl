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

type previewControl interface {
	CreatePreview(context.Context, string, string) (controlv1.Preview, error)
	AddPreviewPublicURL(context.Context, string, string) (controlv1.Preview, error)
}

func ensurePreview(ctx context.Context, state *clientstate.Database, store *clientstate.Store, control previewControl, server, teamID, projectRoot string) (string, error) {
	if teamID == "" || projectRoot == "" || server == "" {
		return "", errors.New("preview requires one server, team, and project")
	}
	salt, err := state.WorktreeHashSalt(ctx)
	if err != nil {
		return "", err
	}
	hash := hmac.New(sha256.New, salt[:])
	_, _ = hash.Write([]byte(server + "\x00" + teamID + "\x00" + projectRoot))
	key := hex.EncodeToString(hash.Sum(nil))
	preview, err := control.CreatePreview(ctx, teamID, key)
	if err != nil {
		return "", fmt.Errorf("create preview: %w", err)
	}
	if !opaqueid.Valid(preview.Id, opaqueid.PreviewPrefix) || preview.TeamId != teamID {
		return "", errors.New("server returned an invalid preview")
	}
	if saved, found, err := store.PreviewID(ctx, teamID, projectRoot); err != nil {
		return "", err
	} else if found && saved != preview.Id {
		return "", errors.New("saved preview differs from the server; check the selected team and client state")
	}
	if err := store.SavePreviewID(ctx, teamID, projectRoot, preview.Id); err != nil {
		return "", err
	}
	return preview.Id, nil
}
