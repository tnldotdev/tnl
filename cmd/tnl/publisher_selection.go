package main

import (
	"context"
	"time"
)

var selectDockerPublisher = dockerPublisherClient

func selectedPublisherClient(ctx context.Context, project projectConfiguration, timeout time.Duration) (namedPublisherClient, error) {
	return selectDockerPublisher(ctx, project, timeout)
}
