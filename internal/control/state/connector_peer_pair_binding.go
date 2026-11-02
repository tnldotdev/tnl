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
	started := time.Now()
	checkedNow := func() time.Time { return now.Add(time.Since(started)) }
	if pair.ServiceID != run.ServiceID || pair.ServiceRunID != run.ID || pair.RunNumber != run.RunNumber ||
		pair.PublisherIdentityID != run.PublisherIdentityID || !pair.ExpiresAt.Time.After(now) || pair.LastAuthorizedAt.Time.After(now) ||
		run.State != "ready" || !run.Healthy || !activeServiceRun(run, now) || !run.CertificateExpiresAt.Valid || !run.CertificateExpiresAt.Time.After(now) {
		return b, ErrServiceAccess
	}
	publisherUntil, err := connectorPeerPublisherAuthority(ctx, tx, run, now)
	if err != nil {
		return b, err
	}
	subject, _, subjectUntil, err := connectorPeerPairSubjectKey(ctx, tx, pair, now)
	if err != nil {
		return b, err
	}
	b.subject = subject
	ready, err := connectorPairReadySelection(ctx, tx, run.ID, run.ServiceID, run.RunNumber, now)
	if err != nil {
		return b, err
	}
	if ready == nil || ready.PublisherIdentityID != run.PublisherIdentityID || json.Unmarshal(pair.Slots, &b.relays) != nil || b.relays != ready.Relays {
		return b, ErrServiceAccess
	}
	q := controlstatedb.New(tx)
	leases, err := q.ReadConnectorPeerObservationRelayBounds(ctx, controlstatedb.ReadConnectorPeerObservationRelayBoundsParams{
		ServiceRunID: run.ID, ServiceID: run.ServiceID, Now: timestamptz(now),
	})
	if err != nil {
		return b, err
	}
	if len(leases) != 2 || leases[0].ConnectionSlot != 0 || leases[1].ConnectionSlot != 1 {
		return b, ErrServiceAccess
	}
	for i, lease := range leases {
		if lease.RelayAddress != b.relays[i].RelayAddress || lease.TlsServerName != b.relays[i].TLSServerName {
			return b, ErrServiceAccess
		}
	}
	b.expiresAt = minTime(pair.ExpiresAt.Time, minTime(publisherUntil, subjectUntil))
	b.recheckAt = minTime(b.expiresAt, minTime(leases[0].LeaseExpiresAt.Time, leases[1].LeaseExpiresAt.Time))
	claims, err := q.ReadConnectorPeerClaimBounds(ctx, pair.ID)
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
		if err := d.serviceHTTPSourceAllowed(ctx, q, run.ServiceID, b.source); err != nil {
			return connectorPeerBinding{}, err
		}
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
