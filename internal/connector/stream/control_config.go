package stream

import (
	"context"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// ControlConfig provides subject-bound hooks for native connection owners.
// assignments are one-use; a failed slot must not release its healthy sibling.
type ControlConfig struct {
	Signer       func(context.Context, string) (Signer, error)
	Assignment   func(context.Context, string, tunnelv1.VisitorSubject, uint8) (Assignment, error)
	Resolve      func(context.Context, string) (Run, error)
	Release      func(context.Context, string) error
	Close        func() error
	CloseContext func(context.Context) error
	PreparePeer  func(context.Context, string, tunnelv1.VisitorSubject, controlv1.NativePeerPairRequest) (controlv1.NativePeerPair, error)
}

func (ControlConfig) String() string   { return "private connector control configuration" }
func (ControlConfig) GoString() string { return "private connector control configuration" }

type configuredControl struct{ config ControlConfig }

func NewControlWithConfig(config ControlConfig) (Control, error) {
	if config.Signer == nil || config.Assignment == nil || config.Resolve == nil || config.Release == nil || config.Close == nil {
		return nil, ErrServiceConnection
	}
	return &configuredControl{config}, nil
}

func (c *configuredControl) ConnectorSigner(ctx context.Context, identity string) (Signer, error) {
	return c.config.Signer(ctx, identity)
}
func (c *configuredControl) ConnectorAssignment(ctx context.Context, service string, subject tunnelv1.VisitorSubject, slot uint8) (Assignment, error) {
	return c.config.Assignment(ctx, service, subject, slot)
}
func (c *configuredControl) ResolveService(ctx context.Context, service string) (Run, error) {
	return c.config.Resolve(ctx, service)
}
func (c *configuredControl) ReleaseConnectorAssignment(ctx context.Context, session string) error {
	return c.config.Release(ctx, session)
}
func (c *configuredControl) Close() error { return c.config.Close() }

func (c *configuredControl) preparePeer(ctx context.Context, service string, subject tunnelv1.VisitorSubject, request controlv1.NativePeerPairRequest) (controlv1.NativePeerPair, error) {
	if c.config.PreparePeer == nil {
		return controlv1.NativePeerPair{}, ErrServiceConnection
	}
	return c.config.PreparePeer(ctx, service, subject, request)
}
func (c *configuredControl) CloseContext(ctx context.Context) error {
	if c.config.CloseContext != nil {
		return c.config.CloseContext(ctx)
	}
	return c.config.Close()
}
