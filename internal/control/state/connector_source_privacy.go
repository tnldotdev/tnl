package state

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/netip"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/policy/ippolicy"
)

const connectorSourceIPKeyPurpose = "connector-source-binding"

func connectorSourceContext(pair string, generation int64, slot int16) string {
	return fmt.Sprintf("connector-source/%s/%d/%d", pair, generation, slot)
}

// live claim sources remain recoverable only for current-policy checks and
// authenticated publisher delivery. audit history never receives this envelope.
func (d *Database) openConnectorSource(ctx context.Context, q *controlstatedb.Queries, service string, claim controlstatedb.ControlConnectorPeerPairLegClaim) (netip.Addr, error) {
	raw, _, err := d.storageKey.Open(claim.SourceStorageKeyID, connectorSourceContext(claim.PairID, claim.DeliveryGeneration, claim.ConnectionSlot), claim.SourceCiphertext)
	if err != nil {
		return netip.Addr{}, err
	}
	defer clear(raw)
	source, ok := netip.AddrFromSlice(raw)
	if !ok {
		return netip.Addr{}, ErrServiceAccess
	}
	source, err = ippolicy.NormalizeAddress(source)
	if err != nil {
		return netip.Addr{}, ErrServiceAccess
	}
	digest, err := d.readServiceIPDigest(ctx, q, service, connectorSourceIPKeyPurpose, source)
	if err != nil {
		return netip.Addr{}, err
	}
	if subtle.ConstantTimeCompare([]byte(digest), []byte(claim.SourceDigest)) != 1 {
		return netip.Addr{}, ErrServiceAccess
	}
	return source, nil
}
