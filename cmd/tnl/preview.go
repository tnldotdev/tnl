package main

import (
	"context"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/localpublisher"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type previewControl interface {
	CreatePreview(context.Context, string, string) (controlv1.Preview, error)
}

func ensurePreview(ctx context.Context, state *clientstate.Database, store *clientstate.Store, control previewControl, server, teamID, projectRoot string) (string, error) {
	return localpublisher.EnsurePreview(ctx, state, store, control, server, teamID, projectRoot)
}
