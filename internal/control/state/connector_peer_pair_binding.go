package state

import (
	"context"
	"encoding/json"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

// connectorPeerBinding is transaction-local checked state shared by delivery,
// installation reporting, and observation. it contains no delivery secret.
type connectorPeerBinding struct {
	subject                             VisitorSubject
	relays                              [2]ConnectorPeerPairRelay
	source                              netip.Addr
	claimsCurrent                       bool
	expiresAt, preparedUntil, recheckAt time.Time
}

// connectorPeerPairBinding never renews a pair, claim, or installation. callers hold
// service admission and the run/pair lock, then recheck its deadlines before commit.
func (d *Database) connectorPeerPairBinding(ctx context.Context, tx pgx.Tx, run controlstatedb.ControlServiceRun, pair controlstatedb.ControlConnectorPeerPair, now time.Time) (b connectorPeerBinding, err error) {
	publication, err := d.connectorPairPublication(ctx, tx, ConnectorPeerPairRequest{ServiceID: run.ServiceID, ServiceRunID: run.ID,
		RunNumber: run.RunNumber, PublisherIdentityID: run.PublisherIdentityID, Action: "renew"}, now)
	if err != nil {
		return b, err
	}
	return d.connectorPeerPublicationBinding(ctx, tx, publication, pair, now)
}

func (d *Database) connectorPeerPublicationBinding(ctx context.Context, tx pgx.Tx, publication connectorPeerPublication, pair controlstatedb.ControlConnectorPeerPair, now time.Time) (b connectorPeerBinding, err error) {
	started := time.Now()
	checkedNow := func() time.Time { return now.Add(time.Since(started)) }
	subject, _, sessionUntil, err := d.connectorPeerPublicationAuthority(ctx, tx, publication, pair, now)
	if err != nil {
		return b, err
	}
	if publication.state != "ready" {
		return b, ErrServiceAccess
	}
	b.subject = subject
	ready, leaseUntil, err := publication.readyRelays(ctx, tx, now, false)
	if err != nil {
		return b, err
	}
	if ready == nil || ready.PublisherIdentityID != publication.publisherID || json.Unmarshal(pair.Slots, &b.relays) != nil || b.relays != ready.Relays {
		return b, ErrServiceAccess
	}
	q := controlstatedb.New(tx)
	b.expiresAt = sessionUntil
	b.recheckAt = minTime(b.expiresAt, leaseUntil)
	claims, err := q.ReadConnectorPeerBindingClaims(ctx, controlstatedb.ReadConnectorPeerBindingClaimsParams{PairID: pair.ID, DeliveryGeneration: pair.DeliveryGeneration})
	if err != nil {
		return b, err
	}
	b.claimsCurrent = len(claims) == 2
	claimUntil := b.expiresAt
	var seen [2]bool
	for _, claim := range claims {
		slot := int(claim.ConnectionSlot)
		if slot < 0 || slot >= len(b.relays) || seen[slot] {
			return connectorPeerBinding{}, ErrServiceAccess
		}
		seen[slot] = true
		lease := b.relays[slot].RelayLease
		if claim.RelayID != lease.RelayID || claim.RelayRunID != lease.RelayRunID ||
			claim.RelayLeaseRevision != int64(lease.RelayLeaseRevision) || !claim.SourceIp.IsValid() || claim.SourceIp.Zone() != "" ||
			claim.SourceIp != claim.SourceIp.Unmap() || b.source.IsValid() && claim.SourceIp != b.source {
			return connectorPeerBinding{}, ErrServiceAccess
		}
		b.source = claim.SourceIp
		if claim.CheckedAt.Time.After(checkedNow()) || !claim.ConfirmedUntil.Time.After(checkedNow()) {
			b.claimsCurrent = false
		}
		claimUntil = minTime(claimUntil, claim.ConfirmedUntil.Time)
	}
	if b.source.IsValid() {
		sourceUntil, err := d.connectorPeerSourceDeadline(ctx, tx, publication, b.source, checkedNow())
		if err != nil {
			return connectorPeerBinding{}, err
		}
		b.expiresAt = minTime(b.expiresAt, sourceUntil)
		b.recheckAt = minTime(b.recheckAt, sourceUntil)
		claimUntil = minTime(claimUntil, sourceUntil)
	}
	if b.claimsCurrent {
		b.expiresAt = claimUntil
		b.recheckAt = minTime(b.recheckAt, claimUntil)
		if pair.PublisherPreparedUntil.Valid && pair.PublisherPreparedUntil.Time.After(now) {
			b.preparedUntil = minTime(pair.PublisherPreparedUntil.Time, b.expiresAt)
			b.recheckAt = minTime(b.recheckAt, b.preparedUntil)
		}
	}
	return b, nil
}
