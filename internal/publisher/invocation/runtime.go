package invocation

import (
	"context"
	"time"

	nativeauth "github.com/tnldotdev/tnl/internal/publisher/identity"
)

// startDeployedPublisher belongs to the foreground publication, after preflight.
// installed jobs and named groups own this boundary in their runtime loops.
func startDeployedPublisher(ctx context.Context, n *nativeauth.Native, server string) (func(), error) {
	runtime, err := n.RemoteRuntime(server)
	if err != nil {
		return nil, err
	}
	if _, err = runtime.Renew(ctx); err != nil {
		return nil, err
	}
	n.WithRuntime(runtime)
	return func() {
		finish, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = runtime.Stop(finish)
	}, nil
}
