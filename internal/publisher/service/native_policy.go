package service

import (
	"context"
	"sync"

	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type nativePolicyControl interface {
	ReadPublisherVisitorPolicy(context.Context, controlv1.PublisherVisitorPolicyRequest, string) (controlv1.VisitorPolicyUpdate, error)
}

// PrepareNativePolicy installs the run-owned background policy before any peer
// can be bound. arrivals cannot fetch policy or extend a failed refresh bound.
func (b *Bound) PrepareNativePolicy(ctx context.Context, control nativePolicyControl, token credentials.ServiceRunToken) error {
	if b == nil || b.boundState == nil {
		return ErrPrivateStream
	}
	lease, closeOwner, err := publisher.PrepareServiceVisitorPolicy(ctx, control, b.prepared.Preparation.ServiceId, b.prepared.Preparation.ServiceRunId, b.prepared.Preparation.RunNumber, token.String())
	if err != nil {
		return err
	}
	view, enabled, _ := lease.Current()
	b.mu.Lock()
	if b.closed || b.prepared.policy != nil || !enabled || view.MetadataRevision != b.prepared.metadataRevision || view.Hostname != b.prepared.managedHostname || view.Port != b.prepared.servicePort {
		b.mu.Unlock()
		closeOwner()
		return ErrPrivateStream
	}
	b.prepared.policy = lease
	b.closePolicy = sync.OnceFunc(closeOwner)
	b.mu.Unlock()
	return nil
}
