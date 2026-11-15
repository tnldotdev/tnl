package state

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/credentials"
)

// publisher authentication authorizes the exact prepared run and captured
// endpoint. the service's WebPKI certificate authenticates connector visitor TLS.
func (d *Database) StartServiceRun(ctx context.Context, service, id string, number int64, publisher PublisherIdentity, now time.Time) (result ServiceRunState, retErr error) {
	clock := newAuthorizationClock(now)
	if _, err := checkedServiceRunBinding(service, id, number); err != nil || !servicePublisherSelectionMatches(publisher, service) {
		return result, ErrServiceAccess
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "start service run", &retErr)()
	if err = lockServiceAdmission(ctx, tx, service); err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	endpoint, err := q.LockService(ctx, service)
	if err != nil {
		return result, err
	}
	if err = d.guestServiceSource(ctx, q, endpoint.GuestID.String, publisherRequestSource(ctx), clock.current()); err != nil {
		return result, err
	}
	run, err := q.LockServiceRun(ctx, controlstatedb.LockServiceRunParams{ID: id, ServiceID: service})
	if err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	if run.RunNumber != number || run.PublisherIdentityID != publisher.ID || run.PublisherGrantID != publisher.GrantID || run.PublisherKeyID != publisher.KeyID || run.ClosedAt.Valid || len(run.CertificateIdentifiers) == 0 || !run.PublisherExpiresAt.Time.After(clock.current()) {
		return result, ErrServiceAccess
	}
	if run.CertificateHostname != endpoint.CertificateHostname || run.CertificateDomainID != endpoint.DomainID || run.RequirePostQuantum != endpoint.RequirePostQuantum {
		return result, ErrServiceAccess
	}
	prepared := serviceRunLifecycleState(run.State) == serviceRunPrepared
	plan, err := serviceCertificatePlan(ctx, tx, endpoint, publisher.ID, publisher.GrantID, clock.current())
	if err != nil || plan.CacheKey != run.CertificateCacheKey || plan.Scope != run.CertificateScope || !slices.Equal(plan.Identifiers, run.CertificateIdentifiers) {
		return result, errors.Join(ErrServiceAccess, err)
	}
	if _, err = q.GetServiceRunPublisherIdentity(ctx, controlstatedb.GetServiceRunPublisherIdentityParams{ID: id, ServiceID: service, RunNumber: number, PublisherIdentityID: publisher.ID, PublisherGrantID: publisher.GrantID, PublisherKeyID: publisher.KeyID, Now: timestamptz(clock.current())}); err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	permission, err := serviceRunPublisherPermission(ctx, tx, run, clock.current())
	if err != nil {
		return result, err
	}
	seed, err := d.serviceAssignmentSeed(run)
	if err != nil {
		return result, err
	}
	token, digest, err := credentials.NewServiceRunToken()
	if err != nil {
		return result, err
	}
	until := now.Add(45 * time.Second)
	if permission.Valid {
		until = minTime(until, permission.Time)
	}
	if !until.After(clock.current()) {
		return result, ErrServiceAccess
	}
	if prepared {
		key, err := q.GetPublisherKey(ctx, controlstatedb.GetPublisherKeyParams{ID: publisher.KeyID, PublisherIdentityID: publisher.ID})
		if err != nil || key.RetiredAt.Valid || !run.PreparationExpiresAt.Time.After(clock.current()) {
			return result, errors.Join(ErrServiceAccess, err)
		}
		if err := requireNewServiceWork(ctx, q, MaintenanceControlServiceRunCreation); err != nil {
			return result, err
		}
		placements, err := selectRelayServicePlacements(ctx, q, clock.current(), run.PreferredRegions...)
		if err != nil {
			return result, err
		}
		if err = insertServiceRunSlots(ctx, q, seed, run, placements, now); err != nil {
			return result, err
		}
		run.State = string(serviceRunStarting)
	} else if !serviceRunLifecycleState(run.State).active() {
		return result, ErrServiceAccess
	}
	if _, err = tx.Exec(ctx, `UPDATE control.service_runs SET run_token_digest=$2,publisher_expires_at=$3,state=$4,started_at=COALESCE(started_at,$5) WHERE id=$1`, id, digest[:], until, run.State, now); err != nil {
		return result, err
	}
	run.PublisherExpiresAt = timestamptz(until)
	run, err = boundGuestServingAuthority(ctx, q, run, clock.current())
	if err != nil {
		return result, err
	}
	until = run.PublisherExpiresAt.Time
	connections, err := privateAssignments(ctx, q, seed, run)
	if err != nil {
		return result, err
	}
	if _, err = tx.Exec(ctx, "SET CONSTRAINTS ALL IMMEDIATE"); err != nil {
		return result, err
	}
	if _, err = serviceRunPublisherPermission(ctx, tx, run, clock.current()); err != nil {
		return result, err
	}
	if err = d.guestServiceSource(ctx, q, run.GuestID.String, publisherRequestSource(ctx), clock.current()); err != nil {
		return result, err
	}
	if !until.After(clock.current()) || !run.PublisherExpiresAt.Time.After(clock.current()) || prepared && !run.PreparationExpiresAt.Time.After(clock.current()) {
		return result, ErrServiceAccess
	}
	result = ServiceRunState{ServiceID: service, RunID: id, RunNumber: number, Token: token.String(), State: run.State, ExpiresAt: until, Connections: connections}
	return result, tx.Commit(ctx)
}

func insertServiceRunSlots(ctx context.Context, q *controlstatedb.Queries, seed credentials.AssignmentSeed, run controlstatedb.ControlServiceRun, placements [2]relayServicePlacement, now time.Time) error {
	if _, err := checkedServiceRunBinding(run.ServiceID, run.ID, run.RunNumber); err != nil {
		return err
	}
	for index, placement := range placements {
		id, err := opaqueid.New(opaqueid.PublisherConnectionPrefix)
		if err != nil {
			return err
		}
		_, digest, err := credentials.DeriveAssignmentCredential(seed, publisherConnectionCredentialContext(id, 1))
		if err != nil {
			return err
		}
		if _, err = q.InsertServiceConnectionSlot(ctx, controlstatedb.InsertServiceConnectionSlotParams{PublisherConnectionID: id, ServiceRunID: run.ID, ServiceID: run.ServiceID, RunNumber: run.RunNumber, ConnectionSlot: int16(index), ConnectionAssignmentRevision: 1, RelayServiceID: placement.relayServiceID, RelayAddress: placement.relayAddress, TlsServerName: placement.tlsServerName, CredentialDigest: digest[:], CredentialExpiresAt: timestamptz(now.Add(2 * time.Minute)), AssignedAt: timestamptz(now)}); err != nil {
			return err
		}
	}
	return nil
}
