package state

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/security/credentials"
)

// saveConnectorPeerAuditBinding records only checked installation facts. it cannot
// hold delivery keys, authorize a visitor, or transfer authority to a replacement.
func (d *Database) saveConnectorPeerAuditBinding(ctx context.Context, tx pgx.Tx, pair controlstatedb.ControlConnectorPeerPair, binding connectorPeerBinding, until time.Time) error {
	if !connectorPeerPairUnretired(pair) {
		return ErrServiceAuditAccess
	}
	q := controlstatedb.New(tx)
	source, err := d.serviceIPDigest(ctx, q, pair.ServiceID, "connector-audit-binding", binding.source)
	if err != nil {
		return err
	}
	count, err := q.SaveConnectorPeerAuditBinding(ctx, controlstatedb.SaveConnectorPeerAuditBindingParams{
		PairID: pair.ID, ServiceID: pair.ServiceID, ServiceRunID: pair.ServiceRunID, RunNumber: pair.RunNumber,
		PublisherIdentityID: pair.PublisherIdentityID, IdentityID: nullableText(binding.subject.IdentityID),
		DeviceID: nullableText(binding.subject.DeviceID), SourceDigest: source, CreatedAt: pair.CreatedAt,
		ExpiresAt: timestamptz(until), DeliveryGeneration: pair.DeliveryGeneration,
	})
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrServiceAuditAccess
	}
	return nil
}

// IngestServiceRunObservations accepts facts from the owning publisher, not a
// connector or relay. connector identity and source come from control's installed
// pair; HTTP observations carry no actor identity. reports never renew authority.
func (d *Database) IngestServiceRunObservations(ctx context.Context, serviceID, runID, token string, number int64, batch serviceaudit.Batch, now time.Time) (result ServiceObservationResult, retErr error) {
	if err := validateObservationBatch(batch, now); err != nil {
		return result, err
	}
	digest, err := credentials.ParseServiceRunToken(credentials.ServiceRunToken(token))
	if err != nil || number < 1 {
		return result, ErrServiceAccess
	}
	select {
	case d.publisherAuditSlots <- struct{}{}:
		defer func() { <-d.publisherAuditSlots }()
	case <-ctx.Done():
		return result, context.Cause(ctx)
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "ingest native service audit", &retErr)()
	// audit inserts retain foreign keys to the owner. take that parent before
	// the run, as heartbeat and closure do, even for a report after service deletion.
	if err := lockServiceOwner(ctx, tx, serviceID); err != nil {
		return result, err
	}
	// a report reads the saved service but does not change it. queue behind
	// publication writers and allow heartbeats for other runs to proceed.
	if err := queueRunReader(ctx, tx, serviceID); err != nil {
		return result, err
	}
	var retained string
	if err := tx.QueryRow(ctx, `SELECT id FROM control.services WHERE id=$1 FOR SHARE`, serviceID).Scan(&retained); err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	q := controlstatedb.New(tx)
	run, err := q.LockServiceRun(ctx, controlstatedb.LockServiceRunParams{ID: runID, ServiceID: serviceID})
	if errors.Is(err, pgx.ErrNoRows) {
		return result, ErrServiceAccess
	}
	if err != nil {
		return result, err
	}
	if run.RunNumber != number || !bytes.Equal(digest[:], run.RunTokenDigest) || !run.ReadyAt.Valid {
		return result, ErrServiceAccess
	}
	until := run.PublisherExpiresAt.Time
	if run.ClosedAt.Valid {
		until = minTime(until, run.ClosedAt.Time)
	}
	err = tx.QueryRow(ctx, `SELECT LEAST($4::timestamptz,p.revoked_at,g.revoked_at,g.expires_at)
		FROM control.publisher_identities p JOIN control.publisher_grants g ON g.publisher_identity_id=p.id
		WHERE p.id=$1 AND g.id=$2 AND p.team_id IS NOT DISTINCT FROM $3::text
		AND p.guest_id IS NOT DISTINCT FROM $5::text`,
		run.PublisherIdentityID, run.PublisherGrantID, run.TeamID, until, run.GuestID).Scan(&until)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, ErrServiceAccess
	}
	if err != nil {
		return result, err
	}
	if now.After(until.Add(serviceObservationDeliveryGrace)) {
		return result, ErrServiceAccess
	}
	events := make([]serviceaudit.Event, 0, len(batch.Events))
	for _, o := range batch.Events {
		if o.ServiceKind != "service" || o.ServiceID != serviceID || o.RunID != runID || o.RunNumber != number {
			return ServiceObservationResult{}, ErrServiceAuditAccess
		}
		e := observationEvent(o)
		e.TeamID, e.PublisherIdentityID = run.TeamID.String, run.PublisherIdentityID
		if run.Protocol == "http" && o.PairID == "" {
			// the HTTP frontend reports requests and public connection lifetime
			// under its exact run credential. it supplies no actor identity.
			deadline := until
			if o.EventType == "connection.close" || o.EventType == "connection.open" && o.Outcome != "allowed" {
				deadline = deadline.Add(serviceObservationDeliveryGrace)
			}
			if o.DeliveryGeneration != 0 || o.OccurredAt.Before(run.CreatedAt.Time.Add(-time.Second)) || o.OccurredAt.After(deadline) {
				return ServiceObservationResult{}, ErrServiceAuditAccess
			}
			events = append(events, e)
			continue
		}
		if o.EventType == "http.decision" {
			return ServiceObservationResult{}, ErrServiceAuditAccess
		}
		if o.PairID == "" || o.EventType != "connection.open" && o.EventType != "connection.close" {
			return ServiceObservationResult{}, ErrServiceAuditAccess
		}
		var created, expires time.Time
		var retired pgtype.Timestamptz
		source, err := netip.ParseAddr(o.SourceIP)
		if err != nil {
			return ServiceObservationResult{}, ErrServiceAuditAccess
		}
		sourceDigest, err := d.serviceIPDigest(ctx, q, serviceID, "connector-audit-binding", source)
		if err != nil {
			return ServiceObservationResult{}, err
		}
		// installation checked both claims and their immutable source agreement.
		// its credential-free audit scope survives replacing or removing the pair.
		err = tx.QueryRow(ctx, `SELECT created_at,expires_at,identity_id,device_id,retired_at
			FROM control.connector_peer_audit_bindings
			WHERE pair_id=$1 AND service_id=$2 AND service_run_id=$3 AND run_number=$4
			AND publisher_identity_id=$5 AND source_digest=$6 AND delivery_generation=$7`,
			o.PairID, serviceID, runID, number, run.PublisherIdentityID, sourceDigest, o.DeliveryGeneration).
			Scan(&created, &expires, (*nullableAuditString)(&e.ActorIdentityID), (*nullableAuditString)(&e.DeviceID), &retired)
		if errors.Is(err, pgx.ErrNoRows) {
			return ServiceObservationResult{}, ErrServiceAuditAccess
		}
		if err != nil {
			return ServiceObservationResult{}, err
		}
		deadline := minTime(until, expires)
		if retired.Valid && o.EventType == "connection.open" && o.Outcome == "allowed" {
			deadline = minTime(deadline, retired.Time)
		}
		if o.EventType == "connection.close" || o.Outcome != "allowed" {
			if retired.Valid {
				deadline = until
			}
			// physical cleanup and denial can follow the authority deadline;
			// neither event claims permission to send application bytes.
			deadline = deadline.Add(serviceObservationDeliveryGrace)
		}
		if o.OccurredAt.Before(created.Add(-time.Second)) || o.OccurredAt.After(deadline) {
			return ServiceObservationResult{}, ErrServiceAuditAccess
		}
		events = append(events, e)
	}
	result, err = d.insertServiceObservationBatch(ctx, tx, events, now)
	if err != nil {
		return ServiceObservationResult{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return ServiceObservationResult{}, err
	}
	d.activity.metrics.Load().ServiceAuditCount("accepted", uint64(result.Accepted))
	d.activity.metrics.Load().ServiceAuditCount("duplicate", uint64(result.Duplicates))
	return result, nil
}
