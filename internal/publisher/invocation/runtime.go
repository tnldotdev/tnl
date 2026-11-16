package invocation

import (
	"context"
	"sync"
	"time"

	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
)

// startDeployedPublisher belongs to the foreground publication, after preflight.
// installed jobs and named groups own this boundary in their runtime loops.
func startDeployedPublisher(ctx context.Context, n *publisheridentity.Native, server string, deadline func() time.Time) (func() error, error) {
	runtime, err := n.RemoteRuntime(server)
	if err != nil {
		return nil, err
	}
	if _, err = runtime.Renew(ctx); err != nil {
		return nil, err
	}
	n.WithRuntime(runtime)
	return func() error {
		finish, cancel := context.WithDeadline(context.WithoutCancel(ctx), deadline())
		defer cancel()
		return runtime.Stop(finish)
	}, nil
}

// publicationShutdown owns the foreground operation's first stop. beginning its
// deadline also stops sibling integrations; final local and remote work share it.
func publicationShutdown(parent context.Context) (context.Context, func() time.Time, func()) {
	ctx, cancel := context.WithCancel(parent)
	deadline := sync.OnceValue(func() time.Time {
		until := time.Now().Add(10 * time.Second)
		cancel()
		return until
	})
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(done); deadline() })
	return ctx, deadline, func() {
		cancel()
		if !stop() {
			<-done
		}
	}
}
