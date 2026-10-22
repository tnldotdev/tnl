package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/security/certificateidentity"
	"github.com/tnldotdev/tnl/internal/security/credentials"
)

type ServiceRunPreparation struct {
	ServiceID, TeamID, RunID, PublisherIdentityID, PublisherGrantID, PublisherKeyID, IdempotencyKey string
	RunNumber                                                                                       int64
	ExpiresAt                                                                                       time.Time
	CertificatePlan                                                                                 CertificatePlan
	Hostname, DomainID                                                                              string
	ServicePort                                                                                     int
}

type ServiceRunAssignment struct {
	PublisherConnectionID, RelayServiceID, RelayAddress, TLSServerName, Credential, State string
	ConnectionSlot                                                                        int16
	Revision                                                                              int64
	CredentialExpiresAt                                                                   time.Time
}

type ServiceRunState struct {
	ServiceID, RunID, Token, State  string
	RunNumber                       int64
	ExpiresAt                       time.Time
	Connections                     []ServiceRunAssignment
	Healthy                         bool
	StreamCapacity, ReportedStreams int32
}

type ServiceRunHealth struct {
	Healthy                       bool
	StreamCapacity, ActiveStreams int32
}

func serviceAssignmentSeedContext(id string) string { return "service-slot-seed/" + id }

func serviceRunPreparation(r controlstatedb.ControlServiceRun) ServiceRunPreparation {
	return ServiceRunPreparation{ServiceID: r.ServiceID, TeamID: r.TeamID, RunID: r.ID,
		PublisherIdentityID: r.PublisherIdentityID, PublisherGrantID: r.PublisherGrantID,
		PublisherKeyID: r.PublisherKeyID, IdempotencyKey: r.IdempotencyKey,
		RunNumber: r.RunNumber, ExpiresAt: r.PreparationExpiresAt.Time,
		Hostname: r.CertificateHostname, DomainID: r.CertificateDomainID.String, ServicePort: int(r.ServicePort.Int32),
		CertificatePlan: CertificatePlan{CacheKey: r.CertificateCacheKey, Scope: r.CertificateScope, Identifiers: slices.Clone(r.CertificateIdentifiers), ChallengeMethod: certificateidentity.ChallengeDNS01}}
}

func servicePublisherMatches(p PublisherIdentity, serviceID string) bool {
	return opaqueid.Valid(serviceID, opaqueid.ServicePrefix) && p.Kind != "guest" &&
		p.Scope.Kind == "service" && p.Scope.ServiceID == serviceID &&
		opaqueid.Valid(p.ID, opaqueid.PublisherIdentityPrefix) &&
		opaqueid.Valid(p.KeyID, opaqueid.PublisherIdentityKeyPrefix) &&
		opaqueid.Valid(p.GrantID, opaqueid.PublisherGrantPrefix)
}

func (d *Database) PrepareServiceRun(ctx context.Context, serviceID string, p PublisherIdentity, key string, now time.Time, metadata ServiceMetadata) (result ServiceRunPreparation, retErr error) {
	if !servicePublisherMatches(p, serviceID) || len(key) == 0 || len(key) > 128 {
		return result, ErrServiceAccess
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "prepare service run", &retErr)()
	if err = lockServiceAdmission(ctx, tx, serviceID); err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	service, err := q.SelectServiceForPublisher(ctx, controlstatedb.SelectServiceForPublisherParams{
		ServiceID: serviceID, PublisherIdentityID: p.ID, PublisherGrantID: p.GrantID, Now: timestamptz(now),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return result, ErrServiceAccess
	}
	if err != nil {
		return result, err
	}
	saved, err := checkedServiceMetadata(service)
	if err != nil {
		return result, err
	}
	if metadata.Validate() != nil || metadata.TrustRevision != service.TrustRevision || !serviceMetadataMatches(saved, metadata) {
		return result, ErrServiceConflict
	}
	keyRecord, err := q.GetPublisherKey(ctx, controlstatedb.GetPublisherKeyParams{ID: p.KeyID, PublisherIdentityID: p.ID})
	if errors.Is(err, pgx.ErrNoRows) {
		return result, ErrServiceAccess
	}
	if err != nil {
		return result, err
	}
	if keyRecord.RetiredAt.Valid || len(keyRecord.PublicKey) != ed25519.PublicKeySize {
		return result, ErrServiceAccess
	}
	digest := sha256.Sum256([]byte(serviceID + "\x00" + p.ID + "\x00" + p.GrantID + "\x00" + p.KeyID))
	var existingID string
	err = tx.QueryRow(ctx, `SELECT id FROM control.service_runs WHERE service_id=$1 AND idempotency_key=$2 AND publisher_identity_id=$3`, serviceID, key, p.ID).Scan(&existingID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return result, err
	}
	if existingID != "" {
		run, err := q.LockServiceRun(ctx, controlstatedb.LockServiceRunParams{ID: existingID, ServiceID: serviceID})
		if err != nil {
			return result, err
		}
		if serviceRunLifecycleState(run.State) != serviceRunPrepared || run.ClosedAt.Valid || !run.PreparationExpiresAt.Time.After(now) || !bytes.Equal(run.RequestDigest, digest[:]) || run.PublisherIdentityID != p.ID || run.PublisherGrantID != p.GrantID || run.PublisherKeyID != p.KeyID {
			return result, ErrServiceConflict
		}
		if err = tx.Commit(ctx); err != nil {
			return result, err
		}
		return serviceRunPreparation(run), nil
	}
	var activeID string
	err = tx.QueryRow(ctx, `SELECT id FROM control.service_runs WHERE service_id=$1 AND closed_at IS NULL
        AND (publisher_identity_id=$2 OR NOT (SELECT publisher_pool FROM control.services WHERE id=$1))
        ORDER BY run_number LIMIT 1 FOR UPDATE`, serviceID, p.ID).Scan(&activeID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return result, err
	}
	if activeID != "" {
		active, err := q.LockServiceRun(ctx, controlstatedb.LockServiceRunParams{ID: activeID, ServiceID: serviceID})
		if err != nil {
			return result, err
		}
		if !serviceRunLifecycleState(active.State).valid() {
			return result, ErrServiceAccess
		}
		if active.PublisherExpiresAt.Time.After(now) && (serviceRunLifecycleState(active.State) != serviceRunPrepared || active.PreparationExpiresAt.Time.After(now)) {
			return result, ErrServiceConflict
		}
		if _, err = q.CloseServiceRun(ctx, controlstatedb.CloseServiceRunParams{
			ID: active.ID, ServiceID: serviceID, RunNumber: active.RunNumber, Now: timestamptz(now),
		}); err != nil {
			return result, err
		}
		if err = serviceRunRoutingTombstone(ctx, q, serviceID, active.ID, active.RunNumber, now); err != nil {
			return result, err
		}
	}
	id, err := opaqueid.New(opaqueid.ServiceRunPrefix)
	if err != nil {
		return result, err
	}
	seed, err := credentials.NewAssignmentSeed()
	if err != nil {
		return result, err
	}
	ciphertext, err := d.storageKey.Seal(serviceAssignmentSeedContext(id), []byte(seed))
	if err != nil {
		return result, err
	}
	if _, err = nextPrivateRevision(service.NextRunNumber); err != nil {
		return result, err
	}
	number, err := q.AdvanceServiceRunNumber(ctx, controlstatedb.AdvanceServiceRunNumberParams{ID: serviceID, Now: timestamptz(now)})
	if err != nil {
		return result, err
	}
	plan, err := serviceCertificatePlan(ctx, tx, service, p.ID, now)
	if err != nil {
		return result, err
	}
	run, err := q.PrepareServiceRun(ctx, controlstatedb.PrepareServiceRunParams{
		ID: id, ServiceID: serviceID, TeamID: service.TeamID, RunNumber: int64(number),
		PublisherIdentityID: p.ID, PublisherGrantID: p.GrantID, PublisherKeyID: p.KeyID, IdempotencyKey: key,
		RequestDigest: digest[:], PreparationExpiresAt: timestamptz(now.Add(2 * time.Minute)),
		AssignmentSeedCiphertext: ciphertext, AssignmentSeedStorageKeyID: d.storageKey.CurrentID(),
		CertificateCacheKey: plan.CacheKey, CertificateScope: plan.Scope, CertificateIdentifiers: plan.Identifiers, CertificateDomainID: service.DomainID, CertificateHostname: service.CertificateHostname, ServicePort: service.ServicePort,
		Now: timestamptz(now), PublisherExpiresAt: timestamptz(now.Add(2 * time.Minute)),
	})
	if err != nil {
		return result, err
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	return serviceRunPreparation(run), nil
}

func (d *Database) serviceAssignmentSeed(run controlstatedb.ControlServiceRun) (credentials.AssignmentSeed, error) {
	seed, _, err := d.storageKey.Open(run.AssignmentSeedStorageKeyID, serviceAssignmentSeedContext(run.ID), run.AssignmentSeedCiphertext)
	if err != nil {
		return "", err
	}
	if err = credentials.ParseAssignmentSeed(credentials.AssignmentSeed(seed)); err != nil {
		return "", err
	}
	return credentials.AssignmentSeed(seed), nil
}

func privateAssignments(ctx context.Context, q *controlstatedb.Queries, seed credentials.AssignmentSeed, run controlstatedb.ControlServiceRun) ([]ServiceRunAssignment, error) {
	rows, err := q.ListServiceConnectionSlots(ctx, run.ID)
	if err != nil {
		return nil, err
	}
	if len(rows) != 2 {
		return nil, ErrServiceAccess
	}
	result := make([]ServiceRunAssignment, 0, 2)
	for index, slot := range rows {
		binding, err := checkedPrivateAssignmentBinding(slot.ServiceID, slot.ServiceRunID, slot.PublisherConnectionID, slot.RunNumber, slot.ConnectionAssignmentRevision)
		if err != nil || !binding.serviceRunBinding.matches(run) || int(slot.ConnectionSlot) != index {
			return nil, ErrServiceAccess
		}
		state, err := privateAssignmentState(slot.State)
		if err != nil {
			return nil, err
		}
		credential, hash, err := credentials.DeriveAssignmentCredential(seed,
			publisherConnectionCredentialContext(slot.PublisherConnectionID, slot.ConnectionAssignmentRevision))
		if err != nil || !credentials.SecretHashMatches(slot.CredentialDigest, hash) {
			return nil, ErrServiceAccess
		}
		result = append(result, ServiceRunAssignment{PublisherConnectionID: slot.PublisherConnectionID,
			RelayServiceID: slot.RelayServiceID, RelayAddress: slot.RelayAddress,
			TLSServerName: slot.TlsServerName, Credential: string(credential), State: string(state),
			ConnectionSlot: slot.ConnectionSlot, Revision: slot.ConnectionAssignmentRevision,
			CredentialExpiresAt: slot.CredentialExpiresAt.Time})
	}
	return result, nil
}

func serviceRunAuthorization(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, serviceID, runID, token string, now time.Time) (controlstatedb.ControlServiceRun, error) {
	if !opaqueid.Valid(runID, opaqueid.ServiceRunPrefix) {
		return controlstatedb.ControlServiceRun{}, ErrServiceAccess
	}
	digest, err := credentials.ParseServiceRunToken(credentials.ServiceRunToken(token))
	if err != nil {
		return controlstatedb.ControlServiceRun{}, ErrServiceAccess
	}
	run, err := q.LockServiceRun(ctx, controlstatedb.LockServiceRunParams{ID: runID, ServiceID: serviceID})
	if errors.Is(err, pgx.ErrNoRows) {
		return run, ErrServiceAccess
	}
	if err != nil {
		return run, err
	}
	binding, err := checkedServiceRunBinding(serviceID, runID, run.RunNumber)
	if err != nil || !binding.matches(run) {
		return run, ErrServiceAccess
	}
	if !activeServiceRun(run, now) || !bytes.Equal(digest[:], run.RunTokenDigest) {
		return run, ErrServiceAccess
	}
	var current bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.publisher_grants grant_record
		JOIN control.publisher_identities publisher ON publisher.id=grant_record.publisher_identity_id
		JOIN control.publisher_identity_keys key ON key.id=$3 AND key.publisher_identity_id=publisher.id
		WHERE grant_record.id=$1 AND publisher.id=$2 AND grant_record.kind='service'
		AND grant_record.service_id=$4 AND grant_record.revoked_at IS NULL
		AND (grant_record.expires_at IS NULL OR grant_record.expires_at > $5)
		AND publisher.revoked_at IS NULL)`, run.PublisherGrantID, run.PublisherIdentityID, run.PublisherKeyID, serviceID, now).Scan(&current); err != nil {
		return run, err
	}
	if !current {
		return run, ErrServiceAccess
	}
	observability.AuthenticatedServerScope(ctx, observability.Identity{TeamID: run.TeamID, PublisherIdentityID: run.PublisherIdentityID, ServiceID: run.ServiceID}, observability.Fields{Component: "control"})
	return run, nil
}

func privateConnectedRelays(ctx context.Context, tx pgx.Tx, runID string, now time.Time) ([]ServiceRelay, time.Time, error) {
	rows, err := tx.Query(ctx, `SELECT slot.publisher_connection_id, slot.connection_slot, slot.connection_assignment_revision, slot.relay_service_id,
		lease.relay_id, lease.relay_run_id, lease.relay_lease_revision, lease.internal_relay_address, lease.lease_expires_at,service.tls_server_name
		FROM control.service_connection_slots slot
		JOIN control.relay_services service ON service.relay_service_id=slot.relay_service_id
		JOIN control.relay_leases lease ON lease.relay_id=slot.relay_id
			AND lease.relay_run_id=slot.relay_run_id AND lease.relay_lease_revision=slot.relay_lease_revision
			AND lease.relay_service_id=slot.relay_service_id
		WHERE slot.service_run_id=$1 AND slot.state='ready' AND slot.session_open
			AND lease.lease_expires_at > $2 AND NOT lease.draining
		ORDER BY slot.connection_slot FOR SHARE OF lease`, runID, now)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer rows.Close()
	relays := make([]ServiceRelay, 0, 2)
	var lastRelayExpiry time.Time
	for rows.Next() {
		var relay ServiceRelay
		if err = rows.Scan(&relay.PublisherConnectionID, &relay.ConnectionSlot, &relay.ConnectionAssignmentRevision, &relay.RelayServiceID,
			&relay.RelayID, &relay.RelayRunID, &relay.RelayLeaseRevision,
			&relay.InternalRelayAddress, &relay.LeaseExpiresAt, &relay.TLSServerName); err != nil {
			return nil, time.Time{}, err
		}
		if !opaqueid.Valid(relay.PublisherConnectionID, opaqueid.PublisherConnectionPrefix) || relay.ConnectionSlot < 0 || relay.ConnectionSlot > 1 || relay.ConnectionAssignmentRevision < 1 || relay.RelayLeaseRevision < 1 {
			return nil, time.Time{}, ErrServiceAccess
		}
		if relay.LeaseExpiresAt.After(lastRelayExpiry) {
			lastRelayExpiry = relay.LeaseExpiresAt
		}
		relays = append(relays, relay)
	}
	if err = rows.Err(); err != nil {
		return nil, time.Time{}, err
	}
	rows.Close()
	return relays, lastRelayExpiry, nil
}

func serviceRoutingUpsert(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, run controlstatedb.ControlServiceRun, now time.Time) error {
	relays, lastRelayExpiry, err := privateConnectedRelays(ctx, tx, run.ID, now)
	if err != nil {
		return err
	}
	expires := run.PublisherExpiresAt.Time
	if lastRelayExpiry.Before(expires) {
		expires = lastRelayExpiry
	}
	if serviceRunLifecycleState(run.State) != serviceRunReady || !run.ReadyAt.Valid || len(relays) < 1 || len(relays) > 2 || !expires.After(now) {
		return ErrServiceAccess
	}
	encoded, err := json.Marshal(relays)
	if err != nil {
		return err
	}
	clock, err := q.LockServiceRoutingClock(ctx)
	if err != nil {
		return err
	}
	event, err := q.InsertServiceRoutingEvent(ctx, controlstatedb.InsertServiceRoutingEventParams{
		ServiceID: run.ServiceID, ServiceRunID: text(run.ID),
		RunNumber: pgtype.Int8{Int64: run.RunNumber, Valid: true}, Kind: "upsert", Projection: encoded,
		ExpiresAt: timestamptz(expires), Now: timestamptz(now),
	})
	if err != nil {
		return err
	}
	if event.Revision <= clock {
		return ErrServiceConflict
	}
	_, err = q.AdvanceServiceRoutingClock(ctx, controlstatedb.AdvanceServiceRoutingClockParams{
		Revision: event.Revision, Now: timestamptz(now),
	})
	return err
}

func replenishServiceConnections(ctx context.Context, q *controlstatedb.Queries, seed credentials.AssignmentSeed, run controlstatedb.ControlServiceRun, now time.Time) error {
	stale, err := q.ListServiceConnectionSlotsNeedingReplacement(ctx, controlstatedb.ListServiceConnectionSlotsNeedingReplacementParams{
		ServiceRunID: run.ID, Now: timestamptz(now),
	})
	if err != nil {
		return err
	}
	var replaced []controlstatedb.ControlServiceConnectionSlot
	used := make(map[string]bool, 2)
	for _, slot := range stale {
		if PublisherConnectionState(slot.State) == PublisherConnectionReady || PublisherConnectionState(slot.State) == PublisherConnectionConnected {
			if _, err = q.ExpireServiceConnectionSlot(ctx, controlstatedb.ExpireServiceConnectionSlotParams{
				PublisherConnectionID: slot.PublisherConnectionID, ServiceRunID: run.ID, Now: timestamptz(now),
			}); err != nil {
				return err
			}
		}
	}
	rows, err := q.ListServiceConnectionSlots(ctx, run.ID)
	if err != nil {
		return err
	}
	for _, slot := range rows {
		state, err := privateAssignmentState(slot.State)
		if err != nil {
			return err
		}
		if state == PublisherConnectionClosed || state == PublisherConnectionAssigned && !slot.CredentialExpiresAt.Time.After(now) {
			replaced = append(replaced, slot)
		} else {
			used[slot.RelayServiceID] = true
		}
	}
	if len(replaced) == 0 {
		return nil
	}
	services, _, err := availableRelayServicePlacements(ctx, q, now)
	if err != nil {
		return err
	}
	free := make(map[string]int64, len(replaced))
	for _, old := range replaced {
		if PublisherConnectionState(old.State) == PublisherConnectionAssigned {
			free[old.RelayServiceID]++
		}
	}
	reserved := make(map[string]int64, len(replaced))
	choices := make([]relayServicePlacement, 0, len(replaced))
	for range replaced {
		var choice *relayServicePlacement
		for i := range services {
			id := services[i].relayServiceID
			if !used[id] && services[i].assignments-free[id]+reserved[id] < services[i].capacity {
				choice = &services[i]
				break
			}
		}
		if choice == nil {
			// failed placement must not roll back the surviving publisher
			// connection or its one-relay routing projection.
			return nil
		}
		used[choice.relayServiceID] = true
		reserved[choice.relayServiceID]++
		choices = append(choices, *choice)
	}
	for index, old := range replaced {
		binding, err := checkedPrivateAssignmentBinding(old.ServiceID, old.ServiceRunID, old.PublisherConnectionID, old.RunNumber, old.ConnectionAssignmentRevision)
		if err != nil || !binding.serviceRunBinding.matches(run) {
			return ErrServiceAccess
		}
		revision, err := nextPrivateRevision(binding.revision)
		if err != nil {
			return err
		}
		count, err := q.DeleteServiceConnectionSlot(ctx, controlstatedb.DeleteServiceConnectionSlotParams{
			PublisherConnectionID: old.PublisherConnectionID, ServiceRunID: run.ID, Now: timestamptz(now),
		})
		if err != nil {
			return err
		}
		if count != 1 {
			return ErrServiceAccess
		}
		choice := choices[index]
		id, err := opaqueid.New(opaqueid.PublisherConnectionPrefix)
		if err != nil {
			return err
		}
		_, digest, err := credentials.DeriveAssignmentCredential(seed,
			publisherConnectionCredentialContext(id, revision))
		if err != nil {
			return err
		}
		_, err = q.InsertServiceConnectionSlot(ctx, controlstatedb.InsertServiceConnectionSlotParams{
			PublisherConnectionID: id, ServiceRunID: run.ID, ServiceID: run.ServiceID,
			RunNumber: run.RunNumber, ConnectionSlot: old.ConnectionSlot,
			ConnectionAssignmentRevision: revision,
			RelayServiceID:               choice.relayServiceID, RelayAddress: choice.relayAddress,
			TlsServerName: choice.tlsServerName, CredentialDigest: digest[:],
			CredentialExpiresAt: timestamptz(now.Add(2 * time.Minute)),
			AssignedAt:          timestamptz(now),
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func (d *Database) HeartbeatServiceRun(ctx context.Context, serviceID, runID, token string, now time.Time, reports ...ServiceRunHealth) (result ServiceRunState, retErr error) {
	if len(reports) > 1 {
		return result, ErrServiceAccess
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "heartbeat service run", &retErr)()
	if err = lockServiceAdmission(ctx, tx, serviceID); err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	run, err := serviceRunAuthorization(ctx, tx, q, serviceID, runID, token, now)
	if err != nil {
		return result, err
	}
	if len(reports) == 1 {
		report := reports[0]
		if report.StreamCapacity < 1 || report.StreamCapacity > 1<<20 || report.ActiveStreams < 0 {
			return result, ErrServiceAccess
		}
		if _, err = tx.Exec(ctx, `UPDATE control.service_runs SET healthy=$2,stream_capacity=$3,reported_streams=$4 WHERE id=$1`, runID, report.Healthy, report.StreamCapacity, report.ActiveStreams); err != nil {
			return result, err
		}
		run.Healthy, run.StreamCapacity, run.ReportedStreams = report.Healthy, report.StreamCapacity, report.ActiveStreams
	}
	run, err = q.RenewServiceRun(ctx, controlstatedb.RenewServiceRunParams{
		ID: runID, ServiceID: serviceID, RunNumber: run.RunNumber,
		RunTokenDigest: run.RunTokenDigest, PublisherExpiresAt: timestamptz(now.Add(45 * time.Second)), Now: timestamptz(now),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return result, ErrServiceAccess
	}
	if err != nil {
		return result, err
	}
	ready, err := countReadyServiceConnections(ctx, tx, runID, now)
	if err != nil {
		return result, err
	}
	certificateReady := run.CertificateExpiresAt.Valid && run.CertificateExpiresAt.Time.After(now)
	demoted := (ready == 0 || !run.Healthy || !certificateReady) && serviceRunLifecycleState(run.State) == serviceRunReady
	if demoted {
		if _, err = q.DemoteServiceRun(ctx, controlstatedb.DemoteServiceRunParams{
			ID: runID, ServiceID: serviceID, RunNumber: run.RunNumber,
		}); err != nil {
			return result, err
		}
		run.State = string(serviceRunStarting)
	}
	seed, err := d.serviceAssignmentSeed(run)
	if err != nil {
		return result, err
	}
	if ready < 2 {
		if err = replenishServiceConnections(ctx, q, seed, run, now); err != nil {
			return result, err
		}
	}
	if run.Healthy && certificateReady && ready > 0 && (ready == 2 || run.ReadyAt.Valid) {
		if serviceRunLifecycleState(run.State) == serviceRunStarting {
			run, err = q.ReadyServiceRun(ctx, controlstatedb.ReadyServiceRunParams{
				ID: runID, ServiceID: serviceID, RunNumber: run.RunNumber, Now: timestamptz(now),
			})
			if errors.Is(err, pgx.ErrNoRows) {
				return result, ErrServiceAccess
			}
			if err != nil {
				return result, err
			}
		}
		if err = serviceRoutingUpsert(ctx, tx, q, run, now); err != nil {
			return result, err
		}
	} else if demoted {
		if err = serviceRunRoutingTombstone(ctx, q, serviceID, run.ID, run.RunNumber, now); err != nil {
			return result, err
		}
	}
	connections, err := privateAssignments(ctx, q, seed, run)
	if err != nil {
		return result, err
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	return ServiceRunState{ServiceID: serviceID, RunID: runID, RunNumber: run.RunNumber,
		Healthy: run.Healthy, StreamCapacity: run.StreamCapacity, ReportedStreams: run.ReportedStreams,
		State: run.State, ExpiresAt: run.PublisherExpiresAt.Time,
		Connections: connections}, nil
}

func (d *Database) CloseServiceRun(ctx context.Context, serviceID, runID, token string, now time.Time) (retErr error) {
	digest, err := credentials.ParseServiceRunToken(credentials.ServiceRunToken(token))
	if err != nil || !opaqueid.Valid(runID, opaqueid.ServiceRunPrefix) {
		return ErrServiceAccess
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "close service run", &retErr)()
	if err = lockServiceAdmission(ctx, tx, serviceID); err != nil {
		return err
	}
	q := controlstatedb.New(tx)
	run, err := q.LockServiceRun(ctx, controlstatedb.LockServiceRunParams{ID: runID, ServiceID: serviceID})
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrServiceAccess
	}
	if err != nil {
		return err
	}
	if _, err = checkedServiceRunBinding(serviceID, runID, run.RunNumber); err != nil {
		return err
	}
	if !bytes.Equal(digest[:], run.RunTokenDigest) || run.ClosedAt.Valid || !serviceRunLifecycleState(run.State).active() {
		return ErrServiceAccess
	}
	count, err := q.CloseServiceRun(ctx, controlstatedb.CloseServiceRunParams{
		ID: runID, ServiceID: serviceID, RunNumber: run.RunNumber, Now: timestamptz(now),
	})
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrServiceAccess
	}
	if err = serviceRunRoutingTombstone(ctx, q, serviceID, run.ID, run.RunNumber, now); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
