package state

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

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
	var publishedEvent *publishedIngressRoutingTableEvent
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
	if len(connections) == 0 {
		return publishRunLifecycle(session, connections, 0, 0), ErrPublishRunNotReady
	}
	// expose preparation only after the publisher has installed its serving
	// state. ingress installs this run independently of its healthy siblings.
	routing, err := queries.ReadPublishRunPreparationRouting(ctx, controlstatedb.ReadPublishRunPreparationRoutingParams{
		PublicURLID: route.ID, PublishRunNumber: session.PublishRunNumber,
	})
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (routing.EventKind != string(IngressPublicURLUpsert) || !routing.PublicUrlExpiresAt.Time.After(now)) {
		if _, err := pendingEvents.addRouteEvent(ctx, queries, route, session, connections, IngressPublicURLUpsert, now); err != nil {
			return PublishRunLifecycle{}, err
		}
		if err := pendingEvents.publish(ctx, queries); err != nil {
			return PublishRunLifecycle{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return PublishRunLifecycle{}, fmt.Errorf("publish preparation routing: %w", err)
		}
		return publishRunLifecycle(session, connections, 0, 0), ErrPublishRunNotReady
	}
	if err != nil {
		return PublishRunLifecycle{}, fmt.Errorf("read preparation routing: %w", err)
	}
	// registration takes pool -> ingress. keep membership fixed through the
	// final ready projection, without taking ingress locks beneath run locks.
	if err := queries.LockIngressPoolMembership(ctx, route.IngressPoolID); err != nil {
		return PublishRunLifecycle{}, fmt.Errorf("lock readiness pool membership: %w", err)
	}
	prepared, err := queries.PublishRunServingPrepared(ctx, controlstatedb.PublishRunServingPreparedParams{
		IngressPoolID: route.IngressPoolID, PublishRunID: session.ID, PublishRunNumber: session.PublishRunNumber,
		EntryRevision: routing.EntryRevision, Now: timestamptz(now),
	})
	if err != nil {
		return PublishRunLifecycle{}, fmt.Errorf("check serving preparation: %w", err)
	}
	if !prepared.Valid || !prepared.Bool {
		return publishRunLifecycle(session, connections, routing.ID, routing.EntryRevision), ErrPublishRunNotReady
	}
	if !session.ReadyAt.Valid {
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
		publishedEvent, err = pendingEvents.addRouteEvent(
			ctx, queries, route, session, connections, "public_url_upsert", now,
		)
		if err != nil {
			return PublishRunLifecycle{}, err
		}
	}
	if err := pendingEvents.publish(ctx, queries); err != nil {
		return PublishRunLifecycle{}, err
	}
	var routingTableRevision, publicURLEntryRevision int64
	if publishedEvent != nil {
		routingTableRevision = publishedEvent.routingTableRevision
		publicURLEntryRevision = publishedEvent.entryRevision
	}
	if err := tx.Commit(ctx); err != nil {
		return PublishRunLifecycle{}, fmt.Errorf("controlstate: mark publish run ready: commit: %w", err)
	}
	if publishedEvent != nil {
		d.activity.metrics.Load().ObservePublishRunReady(route.Purpose)
	}
	return publishRunLifecycle(session, connections, routingTableRevision, publicURLEntryRevision), nil
}

// preparation projections have the same heartbeat, connection and closure
// owners as ready projections, but must not start ready metrics or guest time.
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
