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
	if _, err := checkedServiceRunBinding(service, id, number); err != nil || !servicePublisherMatches(publisher, service) {
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
	run, err := q.LockServiceRun(ctx, controlstatedb.LockServiceRunParams{ID: id, ServiceID: service})
	if err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	if run.RunNumber != number || run.PublisherIdentityID != publisher.ID || run.PublisherGrantID != publisher.GrantID || run.PublisherKeyID != publisher.KeyID || run.ClosedAt.Valid || len(run.CertificateIdentifiers) == 0 || !run.PublisherExpiresAt.Time.After(now) {
		return result, ErrServiceAccess
	}
	if run.CertificateHostname != endpoint.CertificateHostname || run.CertificateDomainID != endpoint.DomainID || run.ServicePort != endpoint.ServicePort {
		return result, ErrServiceAccess
	}
	plan, err := serviceCertificatePlan(ctx, tx, endpoint, publisher.ID, now)
	if err != nil || plan.CacheKey != run.CertificateCacheKey || plan.Scope != run.CertificateScope || !slices.Equal(plan.Identifiers, run.CertificateIdentifiers) {
		return result, errors.Join(ErrServiceAccess, err)
	}
	if _, err = q.GetServiceRunPublisherIdentity(ctx, controlstatedb.GetServiceRunPublisherIdentityParams{ID: id, ServiceID: service, RunNumber: number, PublisherIdentityID: publisher.ID, PublisherGrantID: publisher.GrantID, PublisherKeyID: publisher.KeyID, Now: timestamptz(now)}); err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	seed, err := d.serviceAssignmentSeed(run)
	if err != nil {
		return result, err
	}
	token, digest, err := credentials.NewServiceRunToken()
	if err != nil {
		return result, err
	}
	if serviceRunLifecycleState(run.State) == serviceRunPrepared {
		key, err := q.GetPublisherKey(ctx, controlstatedb.GetPublisherKeyParams{ID: publisher.KeyID, PublisherIdentityID: publisher.ID})
		if err != nil || key.RetiredAt.Valid || !run.PreparationExpiresAt.Time.After(now) {
			return result, errors.Join(ErrServiceAccess, err)
		}
		placements, err := selectRelayServicePlacements(ctx, q, now)
		if err != nil {
			return result, err
		}
		if err = insertServiceRunSlots(ctx, q, seed, run, placements, now); err != nil {
			return result, err
		}
		if _, err = tx.Exec(ctx, `UPDATE control.service_runs SET state='starting',started_at=$2,run_token_digest=$3,publisher_expires_at=$4 WHERE id=$1`, id, now, digest[:], now.Add(45*time.Second)); err != nil {
			return result, err
		}
		run.State = string(serviceRunStarting)
	} else if !serviceRunLifecycleState(run.State).active() {
		return result, ErrServiceAccess
	}
	if _, err = tx.Exec(ctx, `UPDATE control.service_runs SET run_token_digest=$2,publisher_expires_at=$3 WHERE id=$1`, id, digest[:], now.Add(45*time.Second)); err != nil {
		return result, err
	}
	connections, err := privateAssignments(ctx, q, seed, run)
	if err != nil {
		return result, err
	}
	result = ServiceRunState{ServiceID: service, RunID: id, RunNumber: number, Token: token.String(), State: run.State, ExpiresAt: now.Add(45 * time.Second), Connections: connections}
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
