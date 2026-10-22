package identity

import (
	"context"

	publisherruntime "github.com/tnldotdev/tnl/internal/publisher/runtime"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// RemoteRuntime is called only by an actual deployed runtime owner, never while
// provisioning, importing or verifying a key. local app adapters do not call it.
func (n *Native) RemoteRuntime(server string) (*publisherruntime.Owner, error) {
	control, ok := n.NativeControl.(publisherruntime.Control)
	if !ok {
		return nil, ErrScope
	}
	return publisherruntime.New(control, server, n.identity.clientID, n.identity.keyID, n.identity.grantID, n.private)
}

func (n *Native) WithRuntime(owner *publisherruntime.Owner) { n.runtime = owner }

func (n *Native) renewRuntime(ctx context.Context) error {
	if n.runtime == nil {
		return nil
	}
	_, err := n.runtime.Renew(ctx)
	return err
}

func (n *Native) HeartbeatPublishRun(ctx context.Context, id string, number uint64, token credentials.PublishRunToken) (controlv1.PublishRunHeartbeat, error) {
	r, err := n.NativeControl.HeartbeatPublishRun(ctx, id, number, token)
	if err == nil {
		err = n.renewRuntime(ctx)
	}
	return r, err
}
