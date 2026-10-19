package controlstate

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
	"github.com/tnldotdev/tnl/internal/certificateidentity"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

type PrivateRunPreparation struct {
	ServiceID, TeamID, RunID, PublisherIdentityID, PublisherGrantID, PublisherKeyID, IdempotencyKey string
	RunNumber                                                                                       int64
	ExpiresAt                                                                                       time.Time
	CertificatePlan                                                                                 CertificatePlan
	Hostname, DomainID                                                                              string
	ServicePort                                                                                     int
}

type PrivateRunAssignment struct {
	PublisherConnectionID, RelayServiceID, RelayAddress, TLSServerName, Credential, State string
	ConnectionSlot                                                                        int16
	Revision                                                                              int64
	CredentialExpiresAt                                                                   time.Time
}

type PrivateRunState struct {
	ServiceID, RunID, Token, State  string
	RunNumber                       int64
	ExpiresAt                       time.Time
	Connections                     []PrivateRunAssignment
	Healthy                         bool
	StreamCapacity, ReportedStreams int32
}

type PrivateRunHealth struct {
	Healthy                       bool
	StreamCapacity, ActiveStreams int32
}

func privateAssignmentSeedContext(id string) string { return "private-slot-seed/" + id }

func privateRunPreparation(r controlstatedb.ControlPrivateServiceRun) PrivateRunPreparation {
	return PrivateRunPreparation{ServiceID: r.PrivateServiceID, TeamID: r.TeamID, RunID: r.ID,
		PublisherIdentityID: r.PublisherIdentityID, PublisherGrantID: r.PublisherGrantID,
		PublisherKeyID: r.PublisherKeyID, IdempotencyKey: r.IdempotencyKey,
		RunNumber: r.RunNumber, ExpiresAt: r.PreparationExpiresAt.Time,
		Hostname: r.CertificateHostname, DomainID: r.CertificateDomainID.String, ServicePort: int(r.ServicePort.Int32),
		CertificatePlan: CertificatePlan{CacheKey: r.CertificateCacheKey, Scope: r.CertificateScope, Identifiers: slices.Clone(r.CertificateIdentifiers), ChallengeMethod: certificateidentity.ChallengeDNS01}}
}

func privatePublisherMatches(p PublisherIdentity, serviceID string) bool {
	return opaqueid.Valid(serviceID, opaqueid.PrivateServicePrefix) && p.Kind != "guest" &&
		p.Scope.Kind == "private_service" && p.Scope.PrivateServiceID == serviceID &&
		opaqueid.Valid(p.ID, opaqueid.PublisherIdentityPrefix) &&
		opaqueid.Valid(p.KeyID, opaqueid.PublisherIdentityKeyPrefix) &&
		opaqueid.Valid(p.GrantID, opaqueid.PublisherGrantPrefix)
}

func (d *Database) PreparePrivateServiceRun(ctx context.Context, serviceID string, p PublisherIdentity, key string, now time.Time, declared ...PrivateServiceMetadata) (result PrivateRunPreparation, retErr error) {
	if !privatePublisherMatches(p, serviceID) || len(key) == 0 || len(key) > 128 {
		return result, ErrPrivateServiceAccess
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "prepare private service run", &retErr)()
	if err = lockPrivateAdmission(ctx, tx, serviceID); err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	service, err := q.SelectPrivateServiceForPublisher(ctx, controlstatedb.SelectPrivateServiceForPublisherParams{
		PrivateServiceID: serviceID, PublisherIdentityID: p.ID, PublisherGrantID: p.GrantID, Now: timestamptz(now),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return result, ErrPrivateServiceAccess
	}
	if err != nil {
		return result, err
	}
	metadata := PrivateServiceMetadata{Protocol: "tcp", TrustRevision: 1}
	if len(declared) > 1 {
		return result, ErrPrivateServiceConflict
	}
	if len(declared) == 1 {
		metadata = declared[0]
	}
	if metadata.Validate() != nil || metadata.TrustRevision != service.TrustRevision || !privateMetadataMatches(privateMetadata(service), metadata) {
		return result, ErrPrivateServiceConflict
	}
	keyRecord, err := q.GetPublisherKey(ctx, controlstatedb.GetPublisherKeyParams{ID: p.KeyID, PublisherIdentityID: p.ID})
	if errors.Is(err, pgx.ErrNoRows) {
		return result, ErrPrivateServiceAccess
	}
	if err != nil {
		return result, err
	}
	if keyRecord.RetiredAt.Valid || len(keyRecord.PublicKey) != ed25519.PublicKeySize {
		return result, ErrPrivateServiceAccess
	}
	digest := sha256.Sum256([]byte(serviceID + "\x00" + p.ID + "\x00" + p.GrantID + "\x00" + p.KeyID))
	var existingID string
	err = tx.QueryRow(ctx, `SELECT id FROM control.private_service_runs WHERE private_service_id=$1 AND idempotency_key=$2 AND publisher_identity_id=$3`, serviceID, key, p.ID).Scan(&existingID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return result, err
	}
	if existingID != "" {
		run, err := q.LockPrivateServiceRun(ctx, controlstatedb.LockPrivateServiceRunParams{ID: existingID, PrivateServiceID: serviceID})
		if err != nil {
			return result, err
		}
		if run.State != "prepared" || run.ClosedAt.Valid || !run.PreparationExpiresAt.Time.After(now) || !bytes.Equal(run.RequestDigest, digest[:]) || run.PublisherIdentityID != p.ID || run.PublisherGrantID != p.GrantID || run.PublisherKeyID != p.KeyID {
			return result, ErrPrivateServiceConflict
		}
		if err = tx.Commit(ctx); err != nil {
			return result, err
		}
		return privateRunPreparation(run), nil
	}
	var activeID string
	err = tx.QueryRow(ctx, `SELECT id FROM control.private_service_runs WHERE private_service_id=$1 AND closed_at IS NULL
        AND (publisher_identity_id=$2 OR NOT (SELECT publisher_pool FROM control.private_services WHERE id=$1))
        ORDER BY run_number LIMIT 1 FOR UPDATE`, serviceID, p.ID).Scan(&activeID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return result, err
	}
	if activeID != "" {
		active, err := q.LockPrivateServiceRun(ctx, controlstatedb.LockPrivateServiceRunParams{ID: activeID, PrivateServiceID: serviceID})
		if err != nil {
			return result, err
		}
		if active.PublisherExpiresAt.Time.After(now) && (active.State != "prepared" || active.PreparationExpiresAt.Time.After(now)) {
			return result, ErrPrivateServiceConflict
		}
		if _, err = q.ClosePrivateServiceRun(ctx, controlstatedb.ClosePrivateServiceRunParams{
			ID: active.ID, PrivateServiceID: serviceID, RunNumber: active.RunNumber, Now: timestamptz(now),
		}); err != nil {
			return result, err
		}
		if err = privateRunRoutingTombstone(ctx, q, serviceID, active.ID, active.RunNumber, now); err != nil {
			return result, err
		}
	}
	id, err := opaqueid.New(opaqueid.PrivateRunPrefix)
	if err != nil {
		return result, err
	}
	seed, _, _, err := credentials.NewPublishRunToken()
	if err != nil {
		return result, err
	}
	ciphertext, err := d.storageKey.Seal(privateAssignmentSeedContext(id), []byte(seed))
	if err != nil {
		return result, err
	}
	number, err := q.AdvancePrivateServiceRunNumber(ctx, controlstatedb.AdvancePrivateServiceRunNumberParams{ID: serviceID, Now: timestamptz(now)})
	if err != nil {
		return result, err
	}
	plan, err := privateServiceCertificatePlan(ctx, tx, service, p.ID, now)
	if err != nil {
		return result, err
	}
	run, err := q.PreparePrivateServiceRun(ctx, controlstatedb.PreparePrivateServiceRunParams{
		ID: id, PrivateServiceID: serviceID, TeamID: service.TeamID, RunNumber: int64(number),
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
	return privateRunPreparation(run), nil
}

func (d *Database) privateAssignmentSeed(run controlstatedb.ControlPrivateServiceRun) (credentials.PublishRunToken, error) {
	seed, _, err := d.storageKey.Open(run.AssignmentSeedStorageKeyID, privateAssignmentSeedContext(run.ID), run.AssignmentSeedCiphertext)
	if err != nil {
		return "", err
	}
	if _, _, err = credentials.ParsePublishRunToken(credentials.PublishRunToken(seed)); err != nil {
		return "", err
	}
	return credentials.PublishRunToken(seed), nil
}

func privateAssignments(ctx context.Context, q *controlstatedb.Queries, seed credentials.PublishRunToken, runID string) ([]PrivateRunAssignment, error) {
	rows, err := q.ListPrivateServiceConnectionSlots(ctx, runID)
	if err != nil {
		return nil, err
	}
	if len(rows) != 2 {
		return nil, ErrPrivateServiceAccess
	}
	result := make([]PrivateRunAssignment, 0, 2)
	for index, slot := range rows {
		if int(slot.ConnectionSlot) != index || slot.ConnectionAssignmentRevision <= 0 {
			return nil, ErrPrivateServiceAccess
		}
		credential, hash, err := credentials.DerivePublisherConnectionCredential(seed,
			publisherConnectionCredentialContext(slot.PublisherConnectionID, slot.ConnectionAssignmentRevision))
		if err != nil || !credentials.SecretHashMatches(slot.CredentialDigest, hash) {
			return nil, ErrPrivateServiceAccess
		}
		result = append(result, PrivateRunAssignment{PublisherConnectionID: slot.PublisherConnectionID,
			RelayServiceID: slot.RelayServiceID, RelayAddress: slot.RelayAddress,
			TLSServerName: slot.TlsServerName, Credential: string(credential), State: slot.State,
			ConnectionSlot: slot.ConnectionSlot, Revision: slot.ConnectionAssignmentRevision,
			CredentialExpiresAt: slot.CredentialExpiresAt.Time})
	}
	return result, nil
}

func privateRunAuthorization(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, serviceID, runID, token string, now time.Time) (controlstatedb.ControlPrivateServiceRun, error) {
	if !opaqueid.Valid(runID, opaqueid.PrivateRunPrefix) {
		return controlstatedb.ControlPrivateServiceRun{}, ErrPrivateServiceAccess
	}
	digest, err := privateSecretDigest(token)
	if err != nil {
		return controlstatedb.ControlPrivateServiceRun{}, err
	}
	run, err := q.LockPrivateServiceRun(ctx, controlstatedb.LockPrivateServiceRunParams{ID: runID, PrivateServiceID: serviceID})
	if errors.Is(err, pgx.ErrNoRows) {
		return run, ErrPrivateServiceAccess
	}
	if err != nil {
		return run, err
	}
	if run.ClosedAt.Valid || !run.PublisherExpiresAt.Time.After(now) || !bytes.Equal(digest, run.RunTokenDigest) || run.State != "starting" && run.State != "ready" {
		return run, ErrPrivateServiceAccess
	}
	var current bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.publisher_grants grant_record
		JOIN control.publisher_identities publisher ON publisher.id=grant_record.publisher_identity_id
		JOIN control.publisher_identity_keys key ON key.id=$3 AND key.publisher_identity_id=publisher.id
		WHERE grant_record.id=$1 AND publisher.id=$2 AND grant_record.kind='private_service'
		AND grant_record.private_service_id=$4 AND grant_record.revoked_at IS NULL
		AND (grant_record.expires_at IS NULL OR grant_record.expires_at > $5)
		AND publisher.revoked_at IS NULL)`, run.PublisherGrantID, run.PublisherIdentityID, run.PublisherKeyID, serviceID, now).Scan(&current); err != nil {
		return run, err
	}
	if !current {
		return run, ErrPrivateServiceAccess
	}
	return run, nil
}

func privateConnectedRelays(ctx context.Context, tx pgx.Tx, runID string, now time.Time) ([]PrivateServiceRelay, time.Time, error) {
	rows, err := tx.Query(ctx, `SELECT slot.publisher_connection_id, slot.connection_slot, slot.connection_assignment_revision, slot.relay_service_id,
		lease.relay_id, lease.relay_run_id, lease.relay_lease_revision, lease.internal_relay_address, lease.lease_expires_at,service.tls_server_name
		FROM control.private_service_connection_slots slot
		JOIN control.relay_services service ON service.relay_service_id=slot.relay_service_id
		JOIN control.relay_leases lease ON lease.relay_id=slot.relay_id
			AND lease.relay_run_id=slot.relay_run_id AND lease.relay_lease_revision=slot.relay_lease_revision
			AND lease.relay_service_id=slot.relay_service_id
		WHERE slot.private_run_id=$1 AND slot.state='ready' AND slot.session_open
			AND lease.lease_expires_at > $2 AND NOT lease.draining
		ORDER BY slot.connection_slot FOR SHARE OF lease`, runID, now)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer rows.Close()
	relays := make([]PrivateServiceRelay, 0, 2)
	var lastRelayExpiry time.Time
	for rows.Next() {
		var relay PrivateServiceRelay
		if err = rows.Scan(&relay.PublisherConnectionID, &relay.ConnectionSlot, &relay.ConnectionAssignmentRevision, &relay.RelayServiceID,
			&relay.RelayID, &relay.RelayRunID, &relay.RelayLeaseRevision,
			&relay.InternalRelayAddress, &relay.LeaseExpiresAt, &relay.TLSServerName); err != nil {
			return nil, time.Time{}, err
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

func privateRoutingUpsert(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, run controlstatedb.ControlPrivateServiceRun, now time.Time) error {
	relays, lastRelayExpiry, err := privateConnectedRelays(ctx, tx, run.ID, now)
	if err != nil {
		return err
	}
	expires := run.PublisherExpiresAt.Time
	if lastRelayExpiry.Before(expires) {
		expires = lastRelayExpiry
	}
	if run.State != "ready" || !run.ReadyAt.Valid || len(relays) < 1 || len(relays) > 2 || !expires.After(now) {
		return ErrPrivateServiceAccess
	}
	encoded, err := json.Marshal(relays)
	if err != nil {
		return err
	}
	clock, err := q.LockPrivateServiceRoutingClock(ctx)
	if err != nil {
		return err
	}
	event, err := q.InsertPrivateServiceRoutingEvent(ctx, controlstatedb.InsertPrivateServiceRoutingEventParams{
		PrivateServiceID: run.PrivateServiceID, PrivateRunID: text(run.ID),
		RunNumber: pgtype.Int8{Int64: run.RunNumber, Valid: true}, Kind: "upsert", Projection: encoded,
		ExpiresAt: timestamptz(expires), Now: timestamptz(now),
	})
	if err != nil {
		return err
	}
	if event.Revision <= clock {
		return ErrPrivateServiceConflict
	}
	_, err = q.AdvancePrivateServiceRoutingClock(ctx, controlstatedb.AdvancePrivateServiceRoutingClockParams{
		Revision: event.Revision, Now: timestamptz(now),
	})
	return err
}

func replenishPrivateConnections(ctx context.Context, q *controlstatedb.Queries, seed credentials.PublishRunToken, run controlstatedb.ControlPrivateServiceRun, now time.Time) error {
	stale, err := q.ListPrivateServiceConnectionSlotsNeedingReplacement(ctx, controlstatedb.ListPrivateServiceConnectionSlotsNeedingReplacementParams{
		PrivateRunID: run.ID, Now: timestamptz(now),
	})
	if err != nil {
		return err
	}
	var replaced []controlstatedb.ControlPrivateServiceConnectionSlot
	used := make(map[string]bool, 2)
	for _, slot := range stale {
		if slot.State == "ready" || slot.State == "connected" {
			if _, err = q.ExpirePrivateServiceConnectionSlot(ctx, controlstatedb.ExpirePrivateServiceConnectionSlotParams{
				PublisherConnectionID: slot.PublisherConnectionID, PrivateRunID: run.ID, Now: timestamptz(now),
			}); err != nil {
				return err
			}
		}
	}
	rows, err := q.ListPrivateServiceConnectionSlots(ctx, run.ID)
	if err != nil {
		return err
	}
	for _, slot := range rows {
		if slot.State == "closed" || slot.State == "assigned" && !slot.CredentialExpiresAt.Time.After(now) {
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
		if old.State == "assigned" {
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
		count, err := q.DeletePrivateServiceConnectionSlot(ctx, controlstatedb.DeletePrivateServiceConnectionSlotParams{
			PublisherConnectionID: old.PublisherConnectionID, PrivateRunID: run.ID, Now: timestamptz(now),
		})
		if err != nil {
			return err
		}
		if count != 1 {
			return ErrPrivateServiceAccess
		}
		choice := choices[index]
		id, err := opaqueid.New(opaqueid.PublisherConnectionPrefix)
		if err != nil {
			return err
		}
		_, digest, err := credentials.DerivePublisherConnectionCredential(seed,
			publisherConnectionCredentialContext(id, old.ConnectionAssignmentRevision+1))
		if err != nil {
			return err
		}
		_, err = q.InsertPrivateServiceConnectionSlot(ctx, controlstatedb.InsertPrivateServiceConnectionSlotParams{
			PublisherConnectionID: id, PrivateRunID: run.ID, PrivateServiceID: run.PrivateServiceID,
			RunNumber: run.RunNumber, ConnectionSlot: old.ConnectionSlot,
			ConnectionAssignmentRevision: old.ConnectionAssignmentRevision + 1,
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

func (d *Database) HeartbeatPrivateServiceRun(ctx context.Context, serviceID, runID, token string, now time.Time, reports ...PrivateRunHealth) (result PrivateRunState, retErr error) {
	if len(reports) > 1 {
		return result, ErrPrivateServiceAccess
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "heartbeat private service run", &retErr)()
	if err = lockPrivateAdmission(ctx, tx, serviceID); err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	run, err := privateRunAuthorization(ctx, tx, q, serviceID, runID, token, now)
	if err != nil {
		return result, err
	}
	if len(reports) == 1 {
		report := reports[0]
		if report.StreamCapacity < 1 || report.StreamCapacity > 1<<20 || report.ActiveStreams < 0 {
			return result, ErrPrivateServiceAccess
		}
		if _, err = tx.Exec(ctx, `UPDATE control.private_service_runs SET healthy=$2,stream_capacity=$3,reported_streams=$4 WHERE id=$1`, runID, report.Healthy, report.StreamCapacity, report.ActiveStreams); err != nil {
			return result, err
		}
		run.Healthy, run.StreamCapacity, run.ReportedStreams = report.Healthy, report.StreamCapacity, report.ActiveStreams
	}
	run, err = q.RenewPrivateServiceRun(ctx, controlstatedb.RenewPrivateServiceRunParams{
		ID: runID, PrivateServiceID: serviceID, RunNumber: run.RunNumber,
		RunTokenDigest: run.RunTokenDigest, PublisherExpiresAt: timestamptz(now.Add(45 * time.Second)), Now: timestamptz(now),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return result, ErrPrivateServiceAccess
	}
	if err != nil {
		return result, err
	}
	var ready int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM control.private_service_connection_slots slot
		JOIN control.relay_leases lease ON lease.relay_id=slot.relay_id AND lease.relay_run_id=slot.relay_run_id
			AND lease.relay_lease_revision=slot.relay_lease_revision AND lease.relay_service_id=slot.relay_service_id
		WHERE slot.private_run_id=$1 AND slot.state='ready' AND slot.session_open
			AND lease.lease_expires_at > $2 AND NOT lease.draining`, runID, now).Scan(&ready); err != nil {
		return result, err
	}
	certificateReady := run.CertificateExpiresAt.Valid && run.CertificateExpiresAt.Time.After(now)
	demoted := (ready == 0 || !run.Healthy || !certificateReady) && run.State == "ready"
	if demoted {
		if _, err = q.DemotePrivateServiceRun(ctx, controlstatedb.DemotePrivateServiceRunParams{
			ID: runID, PrivateServiceID: serviceID, RunNumber: run.RunNumber,
		}); err != nil {
			return result, err
		}
		run.State = "starting"
	}
	seed, err := d.privateAssignmentSeed(run)
	if err != nil {
		return result, err
	}
	if ready < 2 {
		if err = replenishPrivateConnections(ctx, q, seed, run, now); err != nil {
			return result, err
		}
	}
	if run.Healthy && certificateReady && ready > 0 && (ready == 2 || run.ReadyAt.Valid) {
		if run.State == "starting" {
			run, err = q.ReadyPrivateServiceRun(ctx, controlstatedb.ReadyPrivateServiceRunParams{
				ID: runID, PrivateServiceID: serviceID, RunNumber: run.RunNumber, Now: timestamptz(now),
			})
			if errors.Is(err, pgx.ErrNoRows) {
				return result, ErrPrivateServiceAccess
			}
			if err != nil {
				return result, err
			}
		}
		if err = privateRoutingUpsert(ctx, tx, q, run, now); err != nil {
			return result, err
		}
	} else if demoted {
		if err = privateRunRoutingTombstone(ctx, q, serviceID, run.ID, run.RunNumber, now); err != nil {
			return result, err
		}
	}
	connections, err := privateAssignments(ctx, q, seed, runID)
	if err != nil {
		return result, err
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	return PrivateRunState{ServiceID: serviceID, RunID: runID, RunNumber: run.RunNumber,
		Healthy: run.Healthy, StreamCapacity: run.StreamCapacity, ReportedStreams: run.ReportedStreams,
		State: run.State, ExpiresAt: run.PublisherExpiresAt.Time,
		Connections: connections}, nil
}

func (d *Database) ClosePrivateServiceRun(ctx context.Context, serviceID, runID, token string, now time.Time) (retErr error) {
	digest, err := privateSecretDigest(token)
	if err != nil || !opaqueid.Valid(runID, opaqueid.PrivateRunPrefix) {
		return ErrPrivateServiceAccess
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "close private service run", &retErr)()
	if err = lockPrivateAdmission(ctx, tx, serviceID); err != nil {
		return err
	}
	q := controlstatedb.New(tx)
	run, err := q.LockPrivateServiceRun(ctx, controlstatedb.LockPrivateServiceRunParams{ID: runID, PrivateServiceID: serviceID})
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrPrivateServiceAccess
	}
	if err != nil {
		return err
	}
	if !bytes.Equal(digest, run.RunTokenDigest) || run.ClosedAt.Valid {
		return ErrPrivateServiceAccess
	}
	count, err := q.ClosePrivateServiceRun(ctx, controlstatedb.ClosePrivateServiceRunParams{
		ID: runID, PrivateServiceID: serviceID, RunNumber: run.RunNumber, Now: timestamptz(now),
	})
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrPrivateServiceAccess
	}
	if err = privateRunRoutingTombstone(ctx, q, serviceID, run.ID, run.RunNumber, now); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
