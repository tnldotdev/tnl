package stream

import (
	"context"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// ControlConfig supplies background native authority operations, never ingress
// assignments. application arrivals consume the already prepared connection.
type ControlConfig struct {
	Signer       func(context.Context, string) (Signer, error)
	Resolve      func(context.Context, string) (Run, error)
	Pair         func(context.Context, string, controlv1.NativePeerPairRequest) (controlv1.NativePeerPair, error)
	Permission   func(context.Context, string) (controlv1.VisitorTokenResponse, error)
	Close        func() error
	CloseContext func(context.Context) error
}

func (ControlConfig) String() string   { return "private connector control configuration" }
func (ControlConfig) GoString() string { return "private connector control configuration" }

type configuredControl struct{ config ControlConfig }

func NewControlWithConfig(config ControlConfig) (Control, error) {
	if config.Signer == nil || config.Resolve == nil || config.Pair == nil || config.Permission == nil || config.Close == nil {
		return nil, ErrServiceConnection
	}
	return &configuredControl{config}, nil
}
func (c *configuredControl) ConnectorSigner(ctx context.Context, id string) (Signer, error) {
	return c.config.Signer(ctx, id)
}
func (c *configuredControl) ResolveService(ctx context.Context, id string) (Run, error) {
	return c.config.Resolve(ctx, id)
}
func (c *configuredControl) PrepareNativePeerPair(ctx context.Context, id string, body controlv1.NativePeerPairRequest) (controlv1.NativePeerPair, error) {
	return c.config.Pair(ctx, id, body)
}
func (c *configuredControl) VisitorPermission(ctx context.Context, id string) (controlv1.VisitorTokenResponse, error) {
	return c.config.Permission(ctx, id)
}
func (c *configuredControl) Close() error { return c.config.Close() }
func (c *configuredControl) CloseContext(ctx context.Context) error {
	if c.config.CloseContext != nil {
		return c.config.CloseContext(ctx)
	}
	return c.config.Close()
}
