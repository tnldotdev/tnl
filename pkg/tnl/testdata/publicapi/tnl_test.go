// package publicapi_test compiles an application using only public imports.
package publicapi_test

import (
	"context"
	"net/http"

	"github.com/tnldotdev/tnl/pkg/tnl"
)

// applications may prepare one identity and reuse it across publications without
// access to its key, control client, or internal lifecycle methods.
func publish(ctx context.Context, handler http.Handler, options tnl.Options) (*tnl.Tunnel, error) {
	identity, err := tnl.PreparePublisherIdentity(ctx, options)
	if err != nil {
		return nil, err
	}
	return tnl.Open(ctx, handler, tnl.Options{PublisherIdentity: identity, Namespace: options.Namespace, StateDir: options.StateDir, Directory: options.Directory, Binary: options.Binary})
}

func registeredSource(ctx context.Context, handler http.Handler, server, namespace string, source tnl.RegisteredKeySource) (*tnl.Tunnel, error) {
	identity, err := tnl.PreparePublisherIdentity(ctx, tnl.Options{ServerURL: server, RegisteredKeySource: &source})
	if err != nil {
		return nil, err
	}
	return tnl.Open(ctx, handler, tnl.Options{PublisherIdentity: identity, Namespace: namespace})
}
