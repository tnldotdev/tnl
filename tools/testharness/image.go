package main

import (
	"context"
	"fmt"

	"github.com/containerd/errdefs"
	"github.com/moby/moby/client"
	"github.com/testcontainers/testcontainers-go"
)

// testcontainers v0.44 drains pull progress without decoding daemon errors.
// finish the pull here so a registry failure cannot become a later "no such
// image" at container creation. use the same digest and never retry the tests.
func prepareFixtureImage(ctx context.Context, image string) error {
	cli, err := testcontainers.NewDockerClientWithOpts(ctx)
	if err != nil {
		return fmt.Errorf("connect to disposable service Docker host: %w", err)
	}
	defer cli.Close()
	return prepareImage(ctx, cli.Client, image)
}

func prepareImage(ctx context.Context, cli *client.Client, image string) error {
	if _, err := cli.ImageInspect(ctx, image); err == nil {
		return nil
	} else if !errdefs.IsNotFound(err) {
		return fmt.Errorf("inspect disposable service image %s: %w", image, err)
	}
	pull, err := cli.ImagePull(ctx, image, client.ImagePullOptions{})
	if err != nil {
		return fmt.Errorf("pull disposable service image %s: %w", image, err)
	}
	if err := pull.Wait(ctx); err != nil {
		return fmt.Errorf("finish pulling disposable service image %s: %w", image, err)
	}
	if _, err := cli.ImageInspect(ctx, image); err != nil {
		return fmt.Errorf("verify disposable service image %s after pull: %w", image, err)
	}
	return nil
}
