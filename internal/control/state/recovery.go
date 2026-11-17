package state

import (
	"bytes"
	"context"
	"errors"
	"io"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

var ErrServiceRecoveryEpisodeStale = errors.New("controlstate: service recovery episode is stale")

type ServiceRecoveryObservation struct {
	ServiceRunReference
	RecoveryEpisodeID uint64
	OpenedAt          time.Time
	ObservedAt        time.Time
	ObservedSeconds   float64
}

// callers hold the service and run locks. repeated losses share the first open
// episode; readiness alone never completes a first-publisher-byte measurement.
func openServiceRecoveryEpisode(ctx context.Context, q *controlstatedb.Queries, run controlstatedb.ControlServiceRun, now time.Time) error {
	if !run.ReadyAt.Valid || !activeServiceRun(run, now) {
		return nil
	}
	return q.OpenServiceRecoveryEpisode(ctx, controlstatedb.OpenServiceRecoveryEpisodeParams{
		ServiceID: run.ServiceID, ServiceRunID: run.ID, RunNumber: run.RunNumber, OpenedAt: timestamptz(now),
	})
}

// ingress reports only a successful write to its visitor. native admission or
// original signed source evidence binds the reporter, run and visitor.
// check the lease at delivery time, never at the sender's earlier timestamp.
func (d *Database) ObserveServiceRecovery(ctx context.Context, lease IngressLeaseIdentity, ref ServiceRunReference, visitor string, episodeID uint64, observedAt time.Time, sourceEvidence []byte, now time.Time) (result ServiceRecoveryObservation, retErr error) {
	clock := newAuthorizationClock(now)
	observedAt = observedAt.UTC().Truncate(time.Microsecond)
	if validateIngressLeaseIdentity(lease) != nil || !opaqueid.Valid(visitor, opaqueid.VisitorConnectionPrefix) ||
		observedAt.IsZero() || now.IsZero() || observedAt.After(now.Add(time.Second)) || observedAt.Before(now.Add(-serviceObservationDeliveryGrace)) || len(sourceEvidence) > 2048 {
		return result, ErrServiceRecoveryEpisodeStale
	}
	if _, err := checkedServiceRunBinding(ref.ServiceID, ref.RunID, ref.RunNumber); err != nil {
		return result, ErrServiceRecoveryEpisodeStale
	}
	id, ok := positiveInt64(episodeID)
	if !ok {
		return result, ErrServiceRecoveryEpisodeStale
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "observe service recovery", &retErr)()
	q := controlstatedb.New(tx)
	currentLease, err := lockCurrentIngressLease(ctx, q, lease, clock.current())
	if err != nil {
		return result, err
	}
	episode, err := q.LockServiceRecoveryEpisode(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, ErrServiceRecoveryEpisodeStale
	}
	if err != nil {
		return result, err
	}
	if episode.ServiceID != ref.ServiceID || episode.ServiceRunID != ref.RunID || episode.RunNumber != ref.RunNumber ||
		observedAt.Before(episode.OpenedAt.Time) || episode.State == "canceled" {
		return result, ErrServiceRecoveryEpisodeStale
	}
	var admitted bool
	if len(sourceEvidence) != 0 {
		admitted, err = verifyHTTPRecoverySource(ctx, tx, lease, ref, visitor, sourceEvidence, observedAt)
	} else {
		err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.public_service_visitors
		WHERE visitor_connection_id=$1 AND service_id=$2 AND service_run_id=$3 AND run_number=$4
		AND ingress_id=$5 AND ingress_run_id=$6 AND ingress_lease_revision=$7
		AND created_at<=$8 AND valid_until>=$8)`, visitor, ref.ServiceID, ref.RunID, ref.RunNumber,
			lease.IngressID, lease.IngressRunID, int64(lease.IngressLeaseRevision), observedAt).Scan(&admitted)
	}
	if err != nil {
		return result, err
	}
	if !admitted {
		return result, ErrServiceRecoveryEpisodeStale
	}
	committed := false
	if episode.State == "open" {
		seconds := observedAt.Sub(episode.OpenedAt.Time).Seconds()
		episode, err = q.ObserveServiceRecoveryEpisode(ctx, controlstatedb.ObserveServiceRecoveryEpisodeParams{
			RecoveryEpisodeID: id, ObservedAt: timestamptz(observedAt), ObservedSeconds: float8(seconds),
		})
		if err != nil {
			return result, err
		}
		if err = q.UpdateServiceRecoveryHistogram(ctx, controlstatedb.UpdateServiceRecoveryHistogramParams{
			ObservedSeconds: seconds, UpdatedAt: timestamptz(now),
		}); err != nil {
			return result, err
		}
		committed = true
	}
	result = ServiceRecoveryObservation{ServiceRunReference: ref, RecoveryEpisodeID: episodeID,
		OpenedAt: episode.OpenedAt.Time, ObservedAt: episode.ObservedAt.Time, ObservedSeconds: episode.RecoverySeconds.Float64}
	if !currentLease.LeaseExpiresAt.Time.After(clock.current()) {
		return ServiceRecoveryObservation{}, ErrIngressLeaseStale
	}
	if err = tx.Commit(ctx); err != nil {
		return ServiceRecoveryObservation{}, err
	}
	if committed && d.activity != nil {
		d.activity.metrics.Load().ObserveRecoveryDuration(time.Duration(result.ObservedSeconds * float64(time.Second)))
	}
	return result, nil
}

func verifyHTTPRecoverySource(ctx context.Context, tx pgx.Tx, lease IngressLeaseIdentity, ref ServiceRunReference, visitor string, evidence []byte, observedAt time.Time) (bool, error) {
	metadata, remaining, err := proxyproto.Decode(bytes.NewReader(evidence))
	if err != nil || metadata.Destination.Port() != 443 || metadata.VisitorSourceProof == "" {
		return false, nil
	}
	trailing, err := io.ReadAll(remaining)
	if err != nil || len(trailing) != 0 {
		return false, nil
	}
	proof, err := tunnelv1.ReadVisitorSourceProof([]byte(metadata.VisitorSourceProof))
	if err != nil || proof.Authority.IngressID != lease.IngressID || proof.Authority.IngressRunID != lease.IngressRunID ||
		proof.Authority.IngressLeaseRevision != lease.IngressLeaseRevision {
		return false, nil
	}
	var digest []byte
	var ready time.Time
	err = tx.QueryRow(ctx, `SELECT run.run_token_digest,run.ready_at FROM control.service_runs run
		JOIN control.services service ON service.id=run.service_id AND service.protocol='http'
		WHERE run.id=$1 AND run.service_id=$2 AND run.run_number=$3 AND run.ready_at IS NOT NULL`,
		ref.RunID, ref.ServiceID, ref.RunNumber).Scan(&digest, &ready)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	master, err := visitortoken.ServiceVisitorSourceKey(digest, ref.RunID, uint64(ref.RunNumber))
	if err != nil || observedAt.Before(ready) {
		return false, nil
	}
	// a delayed first response may follow a normal routing refresh. authenticate
	// the signed original socket observation, not a backdated or renewed proof.
	// this records a measurement; it grants no access or serving deadline.
	at := time.UnixMicro(proof.ObservedAt)
	if at.Before(ready) || at.After(observedAt) {
		return false, nil
	}
	binding := tunnelv1.VisitorSourceBinding{ServiceID: ref.ServiceID, ServiceRunID: ref.RunID, RunNumber: uint64(ref.RunNumber),
		VisitorConnectionID: visitor, Source: metadata.Source, Destination: metadata.Destination}
	return visitortoken.VerifyVisitorSource(master, proof, binding, proof.Authority.VisitorPolicyRevision, at) == nil, nil
}

func float8(value float64) pgtype.Float8 {
	return pgtype.Float8{Float64: value, Valid: true}
}
