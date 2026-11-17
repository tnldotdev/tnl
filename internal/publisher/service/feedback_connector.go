package service

import (
	"context"
	"net/netip"
	"time"

	servicestream "github.com/tnldotdev/tnl/internal/publisher/service/stream"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
)

// HTTPAuthorization snapshots the accepted permission and its binding under the
// same lock as CheckUse and renewal. it never reconstructs proof from HTTP input.
func (a *connectorAdmission) HTTPAuthorization(ctx context.Context) (servicestream.ConnectorHTTPAuthorization, error) {
	b := a.peer.bound
	b.mu.Lock()
	defer b.mu.Unlock()
	until, err := a.checkUseLocked(ctx)
	if err != nil {
		return servicestream.ConnectorHTTPAuthorization{}, err
	}
	entry := a.entry
	source, err := netip.ParseAddr(entry.SourceIP)
	identity := a.peer.identity
	if err != nil || !source.IsValid() || source.IsUnspecified() || source.Zone() != "" || !until.After(time.Now()) ||
		entry.PairID != identity.pairID || entry.ServiceID != identity.serviceID || entry.ServiceRunID != identity.runID ||
		entry.RunNumber != identity.number || entry.DeliveryGeneration < 1 || entry.Permission.Token == "" || !a.permission.Valid() {
		return servicestream.ConnectorHTTPAuthorization{}, ErrPrivateStream
	}
	return servicestream.ConnectorHTTPAuthorization{
		ServiceID: identity.serviceID, RunID: identity.runID, RunNumber: identity.number,
		PairID: entry.PairID, DeliveryGeneration: entry.DeliveryGeneration, Source: source.Unmap(),
		PermissionToken: visitortoken.Token(entry.Permission.Token), Permission: a.permission, ValidUntil: until,
	}, nil
}

var _ servicestream.ConnectorHTTPProof = (*connectorAdmission)(nil)
