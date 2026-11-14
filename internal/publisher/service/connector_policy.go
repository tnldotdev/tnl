package service

import (
	"context"
	"sync"

	"github.com/tnldotdev/tnl/internal/policy/serviceendpoint"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type connectorPolicyControl interface {
	ReadPublisherVisitorPolicy(context.Context, controlv1.PublisherVisitorPolicyRequest, string) (controlv1.VisitorPolicyUpdate, error)
}

// PrepareConnectorPolicy installs the run-owned background policy before any peer
// can be bound. arrivals cannot fetch policy or extend a failed refresh bound.
func (b *Bound) PrepareConnectorPolicy(ctx context.Context, control connectorPolicyControl, token credentials.ServiceRunToken) error {
	if b == nil || b.boundState == nil {
		return ErrPrivateStream
	}
	owner, err := httpaccess.PreparePolicy(ctx, control, visitorscope.Scope{Kind: visitorscope.Service, ID: b.prepared.Preparation.ServiceId}, b.prepared.Preparation.ServiceRunId, b.prepared.Preparation.RunNumber, token.String(), nil)
	if err != nil {
		return err
	}
	lease := owner.Lease()
	view, enabled, _ := lease.Current()
	b.mu.Lock()
	if b.closed || b.prepared.policy != nil || !enabled || view.MetadataRevision != b.prepared.metadataRevision || view.Hostname != b.prepared.managedHostname || view.Port != serviceendpoint.PermissionPort(string(b.prepared.managedProtocol)) {
		b.mu.Unlock()
		owner.Close()
		return ErrPrivateStream
	}
	b.prepared.policy = lease
	b.closePolicy = sync.OnceFunc(owner.Close)
	b.mu.Unlock()
	return nil
}
