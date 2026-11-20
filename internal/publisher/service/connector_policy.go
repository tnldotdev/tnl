package service

import (
	"context"
	"errors"
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

// PrepareConnectorPolicy binds peers to the run's policy. HTTP shares the owner
// already prepared for browser access; other protocols prepare it here.
// arrivals cannot fetch policy or extend a failed refresh bound.
func (b *Bound) PrepareConnectorPolicy(ctx context.Context, control connectorPolicyControl, token credentials.ServiceRunToken) error {
	if b == nil || b.boundState == nil {
		return ErrPrivateStream
	}
	lease := b.prepared.policy
	closePolicy := func() {}
	var refresh func(context.Context) error
	if lease == nil {
		owner, err := httpaccess.PreparePolicy(ctx, control, visitorscope.Scope{Kind: visitorscope.Service, ID: b.prepared.Preparation.ServiceId}, b.prepared.Preparation.ServiceRunId, b.prepared.Preparation.RunNumber, token.String(), nil)
		if err != nil {
			return err
		}
		lease, closePolicy = owner.Lease(), owner.Close
		refresh = owner.Refresh
	}
	view, enabled, _ := lease.Current()
	b.mu.Lock()
	if b.closed || !enabled || view.MetadataRevision != b.prepared.metadataRevision || view.Hostname != b.prepared.managedHostname || view.Port != serviceendpoint.PermissionPort(string(b.prepared.managedProtocol)) {
		b.mu.Unlock()
		closePolicy()
		return ErrPrivateStream
	}
	b.prepared.policy = lease
	if refresh != nil {
		b.prepared.refreshPolicies = append(b.prepared.refreshPolicies, refresh)
	}
	if b.closePolicy == nil {
		b.closePolicy = sync.OnceFunc(closePolicy)
	}
	b.mu.Unlock()
	return nil
}

// all owners are installed before the watch starts. each fetch checks its
// own hostname and applies the authenticated snapshot before returning.
func (b *Bound) refreshWatchedPolicies(ctx context.Context) error {
	var result error
	for _, refresh := range b.prepared.refreshPolicies {
		result = errors.Join(result, refresh(ctx))
	}
	return result
}
