package state

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// preparation routing has a lifetime before ready_at. keep its existing
// heartbeat, connection-change and terminal projections current in that window.
func publishRunRoutingPublished(ctx context.Context, queries *controlstatedb.Queries, session controlstatedb.ControlPublishRun) (bool, error) {
	if session.ReadyAt.Valid {
		return true, nil
	}
	if !session.CertificateInstalledAt.Valid {
		return false, nil
	}
	revision, err := queries.LatestIngressRoutingEntryRevision(ctx, controlstatedb.LatestIngressRoutingEntryRevisionParams{
		PublicURLID: session.PublicURLID, PublishRunNumber: session.PublishRunNumber,
	})
	return revision > 0, err
}

func (d *Database) MarkPublishRunReady(
	ctx context.Context,
	authentication PublishRunAuthentication,
	now time.Time,
) (result PublishRunLifecycle, retErr error) {
	if err := validatePublishRunAuthentication(authentication); err != nil {
		return PublishRunLifecycle{}, err
	}
	if err := d.requireOpen(); err != nil {
		return PublishRunLifecycle{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return PublishRunLifecycle{}, fmt.Errorf("controlstate: mark publish run ready: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "mark publish run ready", &retErr)()
	queries := controlstatedb.New(tx)
	pendingEvents := pendingIngressRoutingTableEvents{}
	route, session, err := lockAuthenticatedPublishRun(ctx, queries, authentication, now)
	if err != nil {
		return PublishRunLifecycle{}, err
	}
	connections, err := validReadyPublisherConnections(ctx, queries, session.ID, now)
	if err != nil {
		return PublishRunLifecycle{}, err
	}
	newlyReady := !session.ReadyAt.Valid
	if !session.ReadyAt.Valid {
		reason, err := queries.GuestRunAllowanceSpent(ctx, controlstatedb.GuestRunAllowanceSpentParams{
			PublishRunID: text(session.ID), Now: timestamptz(now),
		})
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return PublishRunLifecycle{}, fmt.Errorf("controlstate: check guest trial expiry: %w", err)
		}
		if reason != "" {
			return PublishRunLifecycle{}, ErrGuestTrialSpent
		}
		if !session.CertificateInstalledAt.Valid || len(connections) != publishRunConnectionCount {
			return PublishRunLifecycle{}, &PublishRunNotReadyError{
				CertificateInstalled:          session.CertificateInstalledAt.Valid,
				ReadyPublisherConnectionCount: len(connections), CreatedAt: session.CreatedAt.Time,
			}
		}
		if dnsState := PublicURLDNSState(route.DnsState); dnsState != PublicURLDNSUnmanaged && dnsState != PublicURLDNSPublished {
			return PublishRunLifecycle{}, &PublishRunNotReadyError{
				CertificateInstalled: true, ReadyPublisherConnectionCount: len(connections),
				DNSState: dnsState, CreatedAt: session.CreatedAt.Time,
			}
		}
	}
	// publish the existing starting run's routing before asking ingress to
	// prepare it. this commits no ready state, guest time or ready metric.
	routing, err := queries.ReadPublishRunPreparationRouting(ctx, controlstatedb.ReadPublishRunPreparationRoutingParams{
		PublicURLID: route.ID, RunNumber: session.PublishRunNumber, Now: timestamptz(now),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		if len(connections) == 0 {
			return publishRunLifecycle(session, connections, 0, 0), ErrPublishRunNotReady
		}
		published, err := pendingEvents.addRouteEvent(ctx, queries, route, session, connections, IngressPublicURLUpsert, now)
		if err != nil {
			return PublishRunLifecycle{}, err
		}
		if err := pendingEvents.publish(ctx, queries); err != nil {
			return PublishRunLifecycle{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return PublishRunLifecycle{}, fmt.Errorf("controlstate: publish preparation routing: commit: %w", err)
		}
		return publishRunLifecycle(session, connections, published.routingTableRevision, published.entryRevision), ErrPublishRunNotReady
	}
	if err != nil {
		return PublishRunLifecycle{}, fmt.Errorf("controlstate: read preparation routing: %w", err)
	}
	// registration takes pool -> ingress; this path holds team/URL/run -> pool
	// and only reads ingress rows. no ingress holder acquires the pool here.
	// hold membership through ready_at and final routing visibility, so a new
	// receiver either participates in this check or snapshots the final fact.
	if _, err := queries.LockIngressPoolMembership(ctx, route.IngressPoolID); err != nil {
		return PublishRunLifecycle{}, fmt.Errorf("controlstate: lock readiness pool membership: %w", err)
	}
	prepared, err := queries.PublishRunServingPrepared(ctx, controlstatedb.PublishRunServingPreparedParams{
		RunID: session.ID, RunNumber: session.PublishRunNumber, Now: timestamptz(now), ProtocolVersion: tunnelv1.Version,
	})
	if err != nil {
		return PublishRunLifecycle{}, fmt.Errorf("controlstate: check serving preparation: %w", err)
	}
	if !prepared || len(connections) == 0 {
		return publishRunLifecycle(session, connections, routing.ID, routing.EntryRevision), ErrPublishRunNotReady
	}
	if newlyReady {
		session, err = queries.MarkPublishRunReady(ctx, controlstatedb.MarkPublishRunReadyParams{
			ReadyAt: timestamptz(now), PublishRunID: session.ID,
			PublicURLID: route.ID, PublishRunNumber: session.PublishRunNumber,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return PublishRunLifecycle{}, ErrPublishRunStale
		}
		if err != nil {
			return PublishRunLifecycle{}, fmt.Errorf("controlstate: mark publish run ready: update session: %w", err)
		}
		if _, err := queries.MarkGuestRunReady(ctx, controlstatedb.MarkGuestRunReadyParams{
			PublishRunID: text(session.ID), ReadyAt: timestamptz(now),
		}); err != nil {
			return PublishRunLifecycle{}, fmt.Errorf("controlstate: mark guest run ready: %w", err)
		}
		session, err = boundGuestServingAuthority(ctx, queries, session, now)
		if err != nil {
			return PublishRunLifecycle{}, err
		}
		// this final projection tells future joining ingresses which saved runs
		// they must prepare before health. existing receivers already prepared
		// the same routing and setup, so visitor access need not wait for it.
		published, err := pendingEvents.addRouteEvent(ctx, queries, route, session, connections, IngressPublicURLUpsert, now)
		if err != nil {
			return PublishRunLifecycle{}, err
		}
		if err := pendingEvents.publish(ctx, queries); err != nil {
			return PublishRunLifecycle{}, err
		}
		routing.ID, routing.EntryRevision = published.routingTableRevision, published.entryRevision
	}
	if err := tx.Commit(ctx); err != nil {
		return PublishRunLifecycle{}, fmt.Errorf("controlstate: mark publish run ready: commit: %w", err)
	}
	if newlyReady {
		d.activity.metrics.Load().ObservePublishRunReady(route.Purpose)
	}
	return publishRunLifecycle(session, connections, routing.ID, routing.EntryRevision), nil
}
