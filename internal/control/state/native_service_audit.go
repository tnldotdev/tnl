package state

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/security/credentials"
)

// saveNativePeerAuditBinding records only checked installation facts. it cannot
// hold delivery keys, authorize a visitor, or transfer authority to a replacement.
func saveNativePeerAuditBinding(ctx context.Context, tx pgx.Tx, pair controlstatedb.ControlNativePeerPair, binding nativePeerBinding, until time.Time) error {
	result, err := tx.Exec(ctx, `INSERT INTO control.native_peer_audit_bindings
		(pair_id,service_id,service_run_id,run_number,publisher_identity_id,identity_id,device_id,source_ip,created_at,expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT (pair_id) DO UPDATE SET expires_at=EXCLUDED.expires_at
		WHERE control.native_peer_audit_bindings.service_id=EXCLUDED.service_id
		AND control.native_peer_audit_bindings.service_run_id=EXCLUDED.service_run_id
		AND control.native_peer_audit_bindings.run_number=EXCLUDED.run_number
		AND control.native_peer_audit_bindings.publisher_identity_id=EXCLUDED.publisher_identity_id
		AND control.native_peer_audit_bindings.identity_id IS NOT DISTINCT FROM EXCLUDED.identity_id
		AND control.native_peer_audit_bindings.device_id IS NOT DISTINCT FROM EXCLUDED.device_id
		AND control.native_peer_audit_bindings.source_ip=EXCLUDED.source_ip
		AND control.native_peer_audit_bindings.created_at=EXCLUDED.created_at`,
		pair.ID, pair.ServiceID, pair.ServiceRunID, pair.RunNumber, pair.PublisherIdentityID,
		nullableText(binding.subject.IdentityID), nullableText(binding.subject.DeviceID), binding.source, pair.CreatedAt.Time, until)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return ErrServiceAuditAccess
	}
	return nil
}

// IngestServiceRunObservations accepts facts from the run that owns the native
// listener, not a connector or relay. identity and source come from control's
// installed pair. this operation neither renews authority nor admits a stream.
func (d *Database) IngestServiceRunObservations(ctx context.Context, serviceID, runID, token string, number int64, batch serviceaudit.Batch, now time.Time) (result ServiceObservationResult, retErr error) {
	if err := validateObservationBatch(batch, now); err != nil {
		return result, err
	}
	digest, err := credentials.ParseServiceRunToken(credentials.ServiceRunToken(token))
	if err != nil || number < 1 {
		return result, ErrServiceAccess
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "ingest native service audit", &retErr)()
	run, err := controlstatedb.New(tx).LockServiceRun(ctx, controlstatedb.LockServiceRunParams{ID: runID, ServiceID: serviceID})
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
		WHERE p.id=$1 AND g.id=$2 AND p.team_id=$3 AND g.service_id=$5`,
		run.PublisherIdentityID, run.PublisherGrantID, run.TeamID, until, serviceID).Scan(&until)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, ErrServiceAccess
	}
	if err != nil {
		return result, err
	}
	if now.After(until.Add(serviceObservationDeliveryGrace)) {
		return result, ErrServiceAccess
	}
	for _, o := range batch.Events {
		if o.ServiceKind != "service" || o.ServiceID != serviceID || o.RunID != runID || o.RunNumber != number || o.PairID == "" || o.EventType != "connection.open" && o.EventType != "connection.close" {
			return ServiceObservationResult{}, ErrServiceAuditAccess
		}
		e := observationEvent(o)
		e.TeamID, e.PublisherIdentityID = run.TeamID, run.PublisherIdentityID
		var created, expires time.Time
		// installation checked both claims and their immutable source agreement.
		// its credential-free audit scope survives replacing or removing the pair.
		err = tx.QueryRow(ctx, `SELECT created_at,expires_at,identity_id,device_id
			FROM control.native_peer_audit_bindings
			WHERE pair_id=$1 AND service_id=$2 AND service_run_id=$3 AND run_number=$4
			AND publisher_identity_id=$5 AND host(source_ip)=$6`,
			o.PairID, serviceID, runID, number, run.PublisherIdentityID, o.SourceIP).
			Scan(&created, &expires, (*nullableAuditString)(&e.ActorIdentityID), (*nullableAuditString)(&e.DeviceID))
		if errors.Is(err, pgx.ErrNoRows) {
			return ServiceObservationResult{}, ErrServiceAuditAccess
		}
		if err != nil {
			return ServiceObservationResult{}, err
		}
		deadline := minTime(until, expires)
		if o.EventType == "connection.close" || o.Outcome != "allowed" {
			// physical cleanup and denial can follow the authority deadline;
			// neither event claims permission to send application bytes.
			deadline = deadline.Add(serviceObservationDeliveryGrace)
		}
		if o.OccurredAt.Before(created.Add(-time.Second)) || o.OccurredAt.After(deadline) {
			return ServiceObservationResult{}, ErrServiceAuditAccess
		}
		n, err := insertServiceAuditCount(ctx, tx, e, now)
		if err != nil {
			return ServiceObservationResult{}, err
		}
		result.Accepted += int(n)
		result.Duplicates += 1 - int(n)
	}
	if err = tx.Commit(ctx); err != nil {
		return ServiceObservationResult{}, err
	}
	d.activity.metrics.Load().ServiceAuditCount("accepted", uint64(result.Accepted))
	d.activity.metrics.Load().ServiceAuditCount("duplicate", uint64(result.Duplicates))
	return result, nil
}
