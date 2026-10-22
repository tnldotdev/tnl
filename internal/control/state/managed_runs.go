package controlstate

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
// endpoint. the service's WebPKI certificate authenticates native visitor TLS.
func (d *Database) StartManagedServiceRun(ctx context.Context, service, id string, number int64, publisher PublisherIdentity, now time.Time) (result PrivateRunState, retErr error) {
	if _, err := checkedPrivateRunBinding(service, id, number); err != nil || !privatePublisherMatches(publisher, service) {
		return result, ErrPrivateServiceAccess
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "start managed service run", &retErr)()
	if err = lockPrivateAdmission(ctx, tx, service); err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	endpoint, err := q.LockPrivateService(ctx, service)
	if err != nil {
		return result, err
	}
	run, err := q.LockPrivateServiceRun(ctx, controlstatedb.LockPrivateServiceRunParams{ID: id, PrivateServiceID: service})
	if err != nil {
		return result, publisherLookupError(err, ErrPrivateServiceAccess)
	}
	if run.RunNumber != number || run.PublisherIdentityID != publisher.ID || run.PublisherGrantID != publisher.GrantID || run.PublisherKeyID != publisher.KeyID || run.ClosedAt.Valid || len(run.CertificateIdentifiers) == 0 || !run.PublisherExpiresAt.Time.After(now) {
		return result, ErrPrivateServiceAccess
	}
	if run.CertificateHostname != endpoint.CertificateHostname || run.CertificateDomainID != endpoint.DomainID || run.ServicePort != endpoint.ServicePort {
		return result, ErrPrivateServiceAccess
	}
	plan, err := privateServiceCertificatePlan(ctx, tx, endpoint, publisher.ID, now)
	if err != nil || plan.CacheKey != run.CertificateCacheKey || plan.Scope != run.CertificateScope || !slices.Equal(plan.Identifiers, run.CertificateIdentifiers) {
		return result, errors.Join(ErrPrivateServiceAccess, err)
	}
	if _, err = q.GetPrivateRunPublisherIdentity(ctx, controlstatedb.GetPrivateRunPublisherIdentityParams{ID: id, PrivateServiceID: service, RunNumber: number, PublisherIdentityID: publisher.ID, PublisherGrantID: publisher.GrantID, PublisherKeyID: publisher.KeyID, Now: timestamptz(now)}); err != nil {
		return result, publisherLookupError(err, ErrPrivateServiceAccess)
	}
	seed, err := d.privateAssignmentSeed(run)
	if err != nil {
		return result, err
	}
	token, digest, err := credentials.NewManagedRunToken()
	if err != nil {
		return result, err
	}
	if privateRunLifecycleState(run.State) == privateRunPrepared {
		key, err := q.GetPublisherKey(ctx, controlstatedb.GetPublisherKeyParams{ID: publisher.KeyID, PublisherIdentityID: publisher.ID})
		if err != nil || key.RetiredAt.Valid || !run.PreparationExpiresAt.Time.After(now) {
			return result, errors.Join(ErrPrivateServiceAccess, err)
		}
		placements, err := selectRelayServicePlacements(ctx, q, now)
		if err != nil {
			return result, err
		}
		if err = insertManagedRunSlots(ctx, q, seed, run, placements, now); err != nil {
			return result, err
		}
		if _, err = tx.Exec(ctx, `UPDATE control.private_service_runs SET state='starting',started_at=$2,run_token_digest=$3,publisher_expires_at=$4 WHERE id=$1`, id, now, digest[:], now.Add(45*time.Second)); err != nil {
			return result, err
		}
		run.State = string(privateRunStarting)
	} else if !privateRunLifecycleState(run.State).active() {
		return result, ErrPrivateServiceAccess
	}
	if _, err = tx.Exec(ctx, `UPDATE control.private_service_runs SET run_token_digest=$2,publisher_expires_at=$3 WHERE id=$1`, id, digest[:], now.Add(45*time.Second)); err != nil {
		return result, err
	}
	connections, err := privateAssignments(ctx, q, seed, run)
	if err != nil {
		return result, err
	}
	result = PrivateRunState{ServiceID: service, RunID: id, RunNumber: number, Token: token.String(), ManagedToken: token, State: run.State, ExpiresAt: now.Add(45 * time.Second), Connections: connections}
	return result, tx.Commit(ctx)
}

func insertManagedRunSlots(ctx context.Context, q *controlstatedb.Queries, seed credentials.AssignmentSeed, run controlstatedb.ControlPrivateServiceRun, placements [2]relayServicePlacement, now time.Time) error {
	if _, err := checkedPrivateRunBinding(run.PrivateServiceID, run.ID, run.RunNumber); err != nil {
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
		if _, err = q.InsertPrivateServiceConnectionSlot(ctx, controlstatedb.InsertPrivateServiceConnectionSlotParams{PublisherConnectionID: id, PrivateRunID: run.ID, PrivateServiceID: run.PrivateServiceID, RunNumber: run.RunNumber, ConnectionSlot: int16(index), ConnectionAssignmentRevision: 1, RelayServiceID: placement.relayServiceID, RelayAddress: placement.relayAddress, TlsServerName: placement.tlsServerName, CredentialDigest: digest[:], CredentialExpiresAt: timestamptz(now.Add(2 * time.Minute)), AssignedAt: timestamptz(now)}); err != nil {
			return err
		}
	}
	return nil
}
