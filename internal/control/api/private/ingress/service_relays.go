package ingress

import (
	"context"
	"errors"
	"net/http"
	"net/netip"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
)

func (s *service) privateStateError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, controlstate.ErrServiceAccess) {
		return serviceapi.NewProblemError(http.StatusForbidden, "forbidden", "direct visitor authorization is not current")
	}
	return s.storeError(ctx, err)
}

func privateSource(source string) (netip.Addr, bool) {
	ip, err := netip.ParseAddr(source)
	return ip, err == nil && ip.IsValid() && ip.Zone() == "" && ip.String() == source
}

func privateRelayResponses(rows []controlstate.ServiceRelay) []ingressv1.ServiceRelay {
	relays := make([]ingressv1.ServiceRelay, 0, len(rows))
	for _, relay := range rows {
		relays = append(relays, ingressv1.ServiceRelay{PublisherConnectionId: relay.PublisherConnectionID,
			TlsServerName: relay.TLSServerName, ConnectionSlot: int(relay.ConnectionSlot), RelayServiceId: relay.RelayServiceID,
			RelayId: relay.RelayID, RelayRunId: relay.RelayRunID, RelayLeaseRevision: relay.RelayLeaseRevision,
			ConnectionAssignmentRevision: relay.ConnectionAssignmentRevision, InternalRelayAddress: relay.InternalRelayAddress,
			LeaseExpiresAt: relay.LeaseExpiresAt})
	}
	return relays
}
