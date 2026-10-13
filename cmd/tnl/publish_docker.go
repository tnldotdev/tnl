package main

import (
	"context"

	"github.com/tnldotdev/tnl/internal/localpublisher"
)

type dockerPublishResolver struct{ *localpublisher.DockerResolver }

func newDockerPublishResolver(ctx context.Context, root string, selected dockerPublishTarget, http bool) *dockerPublishResolver {
	return &dockerPublishResolver{localpublisher.NewDockerResolver(ctx, root, selected.selection, selected.projectLabel, http)}
}
func (r *dockerPublishResolver) initial() (string, error) { return r.Initial() }
func (r *dockerPublishResolver) target() string           { return r.Target() }
