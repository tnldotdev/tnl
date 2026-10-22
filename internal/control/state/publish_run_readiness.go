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
