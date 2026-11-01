package workload

import (
	"context"
	"slices"
	"time"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// PrepareConnectorPeerPair keeps the current credential inside the adapter. the
// caller signs a stable owner key and repeats exact proofs after uncertain replies.
func (c *Client) PrepareConnectorPeerPair(ctx context.Context, service string, body controlv1.ConnectorPeerPairRequest) (controlv1.ConnectorPeerPair, error) {
	r, err := c.Session()
	if err != nil {
		return controlv1.ConnectorPeerPair{}, err
	}
	if !r.LeaseExpiresAt.After(time.Now()) || !r.ExpiresAt.After(time.Now()) {
		return controlv1.ConnectorPeerPair{}, ErrSessionExpired
	}
	if !slices.Contains(r.ServiceIds, service) {
		return controlv1.ConnectorPeerPair{}, invalidSession()
	}
	if body.Action == "renew" && body.PreviousPairId != nil {
		return c.control.RenewWorkloadConnectorPeerPair(ctx, service, *body.PreviousPairId, r.Credential, body)
	}
	if body.Action == "create" || body.Action == "replace" {
		return c.control.PrepareWorkloadConnectorPeerPair(ctx, service, r.Credential, body)
	}
	return controlv1.ConnectorPeerPair{}, invalidSession()
}
