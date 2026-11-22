package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
	"github.com/tnldotdev/tnl/internal/region"
	"github.com/tnldotdev/tnl/internal/security/certificateidentity"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type ServiceRunPreparation struct {
	ServiceID, TeamID, GuestID, RunID, PublisherIdentityID, PublisherGrantID, PublisherKeyID, IdempotencyKey string
	Token                                                                                                    string
	RunNumber                                                                                                int64
	ExpiresAt                                                                                                time.Time
	CertificatePlan                                                                                          CertificatePlan
	Hostname, DomainID                                                                                       string
	RunHostname                                                                                              string
	Traffic                                                                                                  trafficlimits.Limits
	RequirePostQuantum                                                                                       bool
}

// ServiceRunRequest separates run-local selections from saved target trust.
type ServiceRunRequest struct {
	Metadata                        ServiceMetadata
	PreferredRegions                []string
	TrafficSelection                *trafficlimits.Selection
	TrafficDefaults, TrafficCeiling trafficlimits.Limits
}

type ServiceRunAssignment struct {
	PublisherConnectionID, RelayServiceID, RelayAddress, TLSServerName, Credential, State string
	ConnectionSlot                                                                        int16
	Revision                                                                              int64
	CredentialExpiresAt                                                                   time.Time
}

type ServiceRunState struct {
	PolicyConfirmation              *controlv1.PublisherPolicyConfirmation
	AliasPolicyConfirmation         *controlv1.PublisherPolicyConfirmation
	ServiceID, RunID, Token, State  string
	RunNumber                       int64
	EndpointRevision                int64
	PublicEndpointReady             bool
	RunHostname                     string
	RunAliasReady                   bool
	ExpiresAt                       time.Time
	ObservedAt, ServingUntil        time.Time
	Connections                     []ServiceRunAssignment
	VisitorSourceKey                [32]byte
	Healthy                         bool
	StreamCapacity, ReportedStreams int32
}

type ServiceRunHealth struct {
	Healthy                       bool
	StreamCapacity, ActiveStreams int32
}

func serviceAssignmentSeedContext(id string) string { return "service-slot-seed/" + id }

func serviceRunPreparation(r controlstatedb.ControlServiceRun) (ServiceRunPreparation, error) {
	traffic, err := decodeRunTraffic(r.TrafficLimits)
	if err != nil {
		return ServiceRunPreparation{}, err
	}
	return ServiceRunPreparation{ServiceID: r.ServiceID, TeamID: r.TeamID.String, GuestID: r.GuestID.String, RunID: r.ID,
		PublisherIdentityID: r.PublisherIdentityID, PublisherGrantID: r.PublisherGrantID,
		PublisherKeyID: r.PublisherKeyID, IdempotencyKey: r.IdempotencyKey,
		RunNumber: r.RunNumber, ExpiresAt: minTime(r.PreparationExpiresAt.Time, r.PublisherExpiresAt.Time),
		Hostname: r.CertificateHostname, DomainID: r.CertificateDomainID.String,
		RunHostname:        r.RunHostname,
		Traffic:            traffic,
		RequirePostQuantum: r.RequirePostQuantum,
		CertificatePlan:    CertificatePlan{CacheKey: r.CertificateCacheKey, Scope: r.CertificateScope, Identifiers: slices.Clone(r.CertificateIdentifiers), ChallengeMethod: certificateidentity.ChallengeDNS01}}, nil
}

func (d *Database) serviceRunPreparation(run controlstatedb.ControlServiceRun) (ServiceRunPreparation, error) {
	preparation, err := serviceRunPreparation(run)
	if err != nil {
		return ServiceRunPreparation{}, err
	}
	seed, err := d.serviceAssignmentSeed(run)
	if err != nil {
		return ServiceRunPreparation{}, err
	}
	token, _ := serviceRunCredential(seed, run.ID)
	preparation.Token = token.String()
	return preparation, nil
}

func (d *Database) PrepareServiceRun(ctx context.Context, serviceID string, p PublisherIdentity, key string, now time.Time, request ServiceRunRequest) (result ServiceRunPreparation, retErr error) {
	ctx, finish := d.observeOperation(ctx, observability.OpCreateServiceRun)
	defer func() { finish(retErr) }()
	clock := newAuthorizationClock(now)
	preferred, retErr := region.Preferences(request.PreferredRegions)
	if retErr != nil {
		return result, retErr
	}
	if !servicePublisherSelectionMatches(p, serviceID) || len(key) == 0 || len(key) > 128 {
		return result, ErrServiceAccess
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "prepare service run", &retErr)()
	if err = lockServiceForPublication(ctx, tx, serviceID); err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	service, err := q.SelectServiceForPublisher(ctx, controlstatedb.SelectServiceForPublisherParams{
		ServiceID: serviceID, PublisherIdentityID: p.ID, PublisherGrantID: p.GrantID, Now: timestamptz(clock.current()),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return result, ErrServiceAccess
	}
	if err != nil {
		return result, err
	}
	if err = d.guestServiceSource(ctx, q, service.GuestID.String, publisherRequestSource(ctx), clock.current()); err != nil {
		return result, err
	}
	saved, err := checkedServiceMetadata(service)
	if err != nil {
		return result, err
	}
	if request.Metadata.Validate() != nil || request.Metadata.TrustRevision != service.TrustRevision || !serviceMetadataMatches(saved, request.Metadata) {
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
	permission, err := publisherServicePermission(ctx, tx, p.ID, p.GrantID, p.KeyID, serviceID, clock.current())
	if err != nil {
		return result, err
	}
	digest := sha256.Sum256([]byte(serviceID + "\x00" + p.ID + "\x00" + p.GrantID + "\x00" + p.KeyID))
	declaration, err := d.serviceConfiguration(ctx, q, serviceID)
	if err != nil {
		return result, err
	}
	workerSelection := request.TrafficSelection
	if declaration != nil && declaration.Traffic != nil {
		request.TrafficSelection = declaration.Traffic
	}
	base := digest
	digest, err = runTrafficDigest(digest, request.TrafficSelection)
	if err != nil {
		return result, err
	}
	if declaration != nil && declaration.Traffic != nil && workerSelection != nil {
		workerDigest, err := runTrafficDigest(base, workerSelection)
		if err != nil {
			return result, err
		}
		if workerDigest != digest {
			return result, ErrServiceConflict
		}
	}
	digest = regionRequestDigest(digest, preferred)
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
		if serviceRunLifecycleState(run.State) != serviceRunPrepared || run.ClosedAt.Valid || !run.PreparationExpiresAt.Time.After(clock.current()) || !bytes.Equal(run.RequestDigest, digest[:]) || run.PublisherIdentityID != p.ID || run.PublisherGrantID != p.GrantID || run.PublisherKeyID != p.KeyID {
			return result, ErrServiceConflict
		}
		result, err = d.serviceRunPreparation(run)
		if err != nil {
			return result, err
		}
		if _, err = serviceRunPublisherPermission(ctx, tx, run, clock.current()); err != nil {
			return ServiceRunPreparation{}, err
		}
		if !result.ExpiresAt.After(clock.current()) {
			return ServiceRunPreparation{}, ErrServiceAccess
		}
		if _, err = tx.Exec(ctx, "SET CONSTRAINTS ALL IMMEDIATE"); err != nil {
			return ServiceRunPreparation{}, err
		}
		if err = d.guestServiceSource(ctx, q, run.GuestID.String, publisherRequestSource(ctx), clock.current()); err != nil {
			return ServiceRunPreparation{}, err
		}
		if !run.PublisherExpiresAt.Time.After(clock.current()) || !run.PreparationExpiresAt.Time.After(clock.current()) {
			return ServiceRunPreparation{}, ErrServiceAccess
		}
		if err = tx.Commit(ctx); err != nil {
			return result, err
		}
		return result, nil
	}
	if err := requireNewServiceWork(ctx, q, MaintenanceControlServiceRunCreation); err != nil {
		return result, err
	}
	traffic, err := resolveRunTraffic(request.TrafficSelection, request.TrafficDefaults, request.TrafficCeiling)
	if err != nil {
		return result, err
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
		if active.PublisherExpiresAt.Time.After(clock.current()) && (serviceRunLifecycleState(active.State) != serviceRunPrepared || active.PreparationExpiresAt.Time.After(clock.current())) {
			return result, ErrServiceConflict
		}
		if _, err = settleServiceRun(ctx, q, active, clock.current()); err != nil {
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
	plan, err := serviceCertificatePlan(ctx, tx, service, p.ID, p.GrantID, clock.current())
	if err != nil {
		return result, err
	}
	runHostname, aliasParent := "", ""
	if service.Public && service.RunAliasParent != "" {
		if service.Protocol != "http" || service.GuestID.Valid {
			return result, ErrServiceAccess
		}
		aliasParent = service.RunAliasParent
		runHostname, err = servicePublisherHostname(ctx, tx, service, p.ID)
		if err != nil {
			return result, err
		}
	}
	plan = certificatePlanWithRunAlias(plan, service.CertificateHostname, runHostname)
	until := now.Add(2 * time.Minute)
	if permission.Valid {
		until = minTime(until, permission.Time)
	}
	if !until.After(clock.current()) {
		return result, ErrServiceAccess
	}
	run, err := q.PrepareServiceRun(ctx, controlstatedb.PrepareServiceRunParams{
		PreferredRegions: preferred,
		TrafficLimits:    traffic,
		ID:               id, ServiceID: serviceID, TeamID: service.TeamID, RunNumber: int64(number),
		PublisherIdentityID: p.ID, PublisherGrantID: p.GrantID, PublisherKeyID: p.KeyID, IdempotencyKey: key,
		RequestDigest: digest[:], PreparationExpiresAt: timestamptz(until),
		AssignmentSeedCiphertext: ciphertext, AssignmentSeedStorageKeyID: d.storageKey.CurrentID(),
		CertificateCacheKey: plan.CacheKey, CertificateScope: plan.Scope, CertificateIdentifiers: plan.Identifiers, CertificateDomainID: service.DomainID, CertificateHostname: service.CertificateHostname,
		RequirePostQuantum: service.RequirePostQuantum,
		RunHostname:        runHostname, RunAliasParent: aliasParent,
		Now: timestamptz(now), PublisherExpiresAt: timestamptz(until),
	})
	if err != nil {
		return result, err
	}
	if err := bindServicePublisherAlias(ctx, tx, service, p.ID, run.ID, runHostname, clock.current()); err != nil {
		return result, err
	}
	if run.GuestID.Valid {
		count, err := q.BeginGuestServiceRun(ctx, controlstatedb.BeginGuestServiceRunParams{
			ServiceRunID: run.ID, ServiceID: serviceID, StartedAt: timestamptz(clock.current()),
		})
		if err != nil {
			return result, err
		}
		if count != 1 {
			return result, ErrGuestTrialSpent
		}
		run, err = boundGuestServingAuthority(ctx, q, run, clock.current())
		if err != nil {
			return result, err
		}
	}
	if activeID != "" {
		if err = retireUnusedServiceCertificateOrders(ctx, q, activeID, clock.current()); err != nil {
			return result, err
		}
	}
	result, err = d.serviceRunPreparation(run)
	if err != nil {
		return result, err
	}
	if _, err = tx.Exec(ctx, "SET CONSTRAINTS ALL IMMEDIATE"); err != nil {
		return ServiceRunPreparation{}, err
	}
	if _, err = serviceRunPublisherPermission(ctx, tx, run, clock.current()); err != nil {
		return ServiceRunPreparation{}, err
	}
	if err = d.guestServiceSource(ctx, q, run.GuestID.String, publisherRequestSource(ctx), clock.current()); err != nil {
		return ServiceRunPreparation{}, err
	}
	if !until.After(clock.current()) {
		return ServiceRunPreparation{}, ErrServiceAccess
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	return result, nil
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
		if err != nil || !binding.ServiceRunReference.matches(run) || int(slot.ConnectionSlot) != index {
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

func (d *Database) serviceRunAuthorization(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, serviceID, runID, token string, now time.Time) (controlstatedb.ControlServiceRun, error) {
	clock := newAuthorizationClock(now)
	digest, err := serviceRunCredentialDigest(runID, token)
	if err != nil {
		return controlstatedb.ControlServiceRun{}, err
	}
	run, err := q.LockServiceRun(ctx, controlstatedb.LockServiceRunParams{ID: runID, ServiceID: serviceID})
	if err != nil {
		return run, publisherLookupError(err, ErrServiceAccess)
	}
	return d.validateServiceRunAuthorization(ctx, tx, q, serviceID, runID, run, digest, clock)
}

// visitor certificate checks and policy observations read current run authority
// without changing it. run writers keep the exclusive serviceRunAuthorization.
func (d *Database) serviceRunObservationAuthorization(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, serviceID, runID, token string, now time.Time) (controlstatedb.ControlServiceRun, error) {
	clock := newAuthorizationClock(now)
	digest, err := serviceRunCredentialDigest(runID, token)
	if err != nil {
		return controlstatedb.ControlServiceRun{}, err
	}
	run, err := q.ObserveServiceRun(ctx, controlstatedb.ObserveServiceRunParams{ID: runID, ServiceID: serviceID})
	if err != nil {
		return run, publisherLookupError(err, ErrServiceAccess)
	}
	return d.validateServiceRunAuthorization(ctx, tx, q, serviceID, runID, run, digest, clock)
}

func serviceRunCredentialDigest(runID, token string) (credentials.SecretHash, error) {
	if !opaqueid.Valid(runID, opaqueid.ServiceRunPrefix) {
		return credentials.SecretHash{}, ErrServiceAccess
	}
	digest, err := credentials.ParseServiceRunToken(credentials.ServiceRunToken(token))
	if err != nil {
		return credentials.SecretHash{}, ErrServiceAccess
	}
	return digest, nil
}

func (d *Database) validateServiceRunAuthorization(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, serviceID, runID string, run controlstatedb.ControlServiceRun, digest credentials.SecretHash, clock authorizationClock) (controlstatedb.ControlServiceRun, error) {
	binding, err := checkedServiceRunBinding(serviceID, runID, run.RunNumber)
	if err != nil || !binding.matches(run) {
		return run, ErrServiceAccess
	}
	if !activeServiceRun(run, clock.current()) || !bytes.Equal(digest[:], run.RunTokenDigest) {
		return run, ErrServiceAccess
	}
	if _, err = serviceRunPublisherPermission(ctx, tx, run, clock.current()); err != nil {
		return run, err
	}
	if err = d.guestServiceSource(ctx, q, run.GuestID.String, publisherRequestSource(ctx), clock.current()); err != nil {
		return run, err
	}
	observability.AuthenticatedServerScope(ctx, observability.Identity{TeamID: run.TeamID.String, PublisherIdentityID: run.PublisherIdentityID, ServiceID: run.ServiceID}, observability.Fields{Component: "control"})
	return run, nil
}

func privateConnectedRelays(ctx context.Context, tx pgx.Tx, runID string, now time.Time) ([]ServiceRelay, time.Time, error) {
	rows, err := tx.Query(ctx, `SELECT slot.publisher_connection_id, slot.connection_slot, slot.connection_assignment_revision, slot.relay_service_id,
		lease.relay_id, lease.relay_run_id, lease.relay_lease_revision, lease.internal_relay_address, lease.lease_expires_at,lease.serving_until,service.tls_server_name
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
			&relay.InternalRelayAddress, &relay.LeaseExpiresAt, &relay.ServingUntil, &relay.TLSServerName); err != nil {
			return nil, time.Time{}, err
		}
		if !opaqueid.Valid(relay.PublisherConnectionID, opaqueid.PublisherConnectionPrefix) || relay.ConnectionSlot < 0 || relay.ConnectionSlot > 1 || relay.ConnectionAssignmentRevision < 1 || relay.RelayLeaseRevision < 1 {
			return nil, time.Time{}, ErrServiceAccess
		}
		if relay.ServingUntil.After(lastRelayExpiry) {
			lastRelayExpiry = relay.ServingUntil
		}
		relays = append(relays, relay)
	}
	if err = rows.Err(); err != nil {
		return nil, time.Time{}, err
	}
	rows.Close()
	return relays, lastRelayExpiry, nil
}

func replenishServiceConnections(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, seed credentials.AssignmentSeed, run controlstatedb.ControlServiceRun, now time.Time) error {
	stale, err := q.ListServiceConnectionSlotsNeedingReplacement(ctx, controlstatedb.ListServiceConnectionSlotsNeedingReplacementParams{
		ServiceRunID: run.ID, Now: timestamptz(now),
	})
	if err != nil {
		return err
	}
	var replaced []controlstatedb.ControlServiceConnectionSlot
	used := make(map[string]bool, 2)
	for _, slot := range stale {
		if PublisherConnectionState(slot.State) == PublisherConnectionReady && slot.Unexpected {
			if err := openServiceRecoveryEpisode(ctx, q, run, now); err != nil {
				return err
			}
		}
	}
	reused, err := reuseServiceConnectionReservations(ctx, tx, seed, run, stale, now)
	if err != nil || reused {
		return err
	}
	for _, slot := range stale {
		if PublisherConnectionState(slot.State) == PublisherConnectionAssigned || PublisherConnectionState(slot.State) == PublisherConnectionReady || PublisherConnectionState(slot.State) == PublisherConnectionConnected {
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
	if len(rows) != 2 {
		return ErrServiceAccess
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
	choose := func(services []relayServicePlacement) []relayServicePlacement {
		_, choices := chooseReplacementPlacements(services, replaced, used, run.ReadyAt.Valid)
		return choices
	}
	services, err := lockRankedRelayPlacements(ctx, tx, now, run.PreferredRegions, choose)
	if err != nil {
		return err
	}
	selected, choices := chooseReplacementPlacements(services, replaced, used, run.ReadyAt.Valid)
	if len(selected) == 0 {
		// retain the surviving connection when no replacement fits.
		return nil
	}
	return replaceServiceSlots(ctx, q, seed, run, selected, choices, now)
}

func chooseReplacementPlacements(services []relayServicePlacement, replaced []controlstatedb.ControlServiceConnectionSlot, used map[string]bool, established bool) ([]controlstatedb.ControlServiceConnectionSlot, []relayServicePlacement) {
	// there are at most two replacement slots. try the complete set first;
	// only an established run may make progress with a one-slot subset.
	place := func(mask uint8) ([]controlstatedb.ControlServiceConnectionSlot, []relayServicePlacement) {
		var selected []controlstatedb.ControlServiceConnectionSlot
		occupied := make(map[string]bool, 2)
		for id := range used {
			occupied[id] = true
		}
		free := make(map[string]int64, 2)
		for index, old := range replaced {
			if mask&(1<<index) == 0 {
				// closed placeholders still own their unique logical-service
				// binding even though they no longer reserve capacity.
				occupied[old.RelayServiceID] = true
				continue
			}
			selected = append(selected, old)
			if PublisherConnectionState(old.State) == PublisherConnectionAssigned {
				free[old.RelayServiceID]++
			}
		}
		available := func(service relayServicePlacement) bool {
			return !occupied[service.relayServiceID] &&
				service.assignments-free[service.relayServiceID] < service.capacity
		}
		choices := make([]relayServicePlacement, len(selected))
		if established {
			// preserve slot ownership when its own service returns. otherwise
			// the first closed slot could take the only returning service.
			for index, old := range selected {
				for _, service := range services {
					if service.relayServiceID == old.RelayServiceID && available(service) {
						choices[index] = service
						occupied[service.relayServiceID] = true
						break
					}
				}
			}
		}
		for index := range selected {
			if choices[index].relayServiceID != "" {
				continue
			}
			for _, service := range services {
				if available(service) {
					choices[index] = service
					occupied[service.relayServiceID] = true
					break
				}
			}
			if choices[index].relayServiceID == "" {
				return nil, nil
			}
		}
		return selected, choices
	}
	selected, choices := place(uint8(1<<len(replaced)) - 1)
	if len(selected) == 0 && established && len(replaced) == 2 {
		for index := range replaced {
			selected, choices = place(1 << index)
			if len(selected) != 0 {
				break
			}
		}
	}
	return selected, choices
}

func replaceServiceSlots(ctx context.Context, q *controlstatedb.Queries, seed credentials.AssignmentSeed, run controlstatedb.ControlServiceRun, selected []controlstatedb.ControlServiceConnectionSlot, choices []relayServicePlacement, now time.Time) error {
	// remove all old slots before inserting any replacements: a selected relay
	// service may still belong to another old slot in this same batch.
	for _, old := range selected {
		count, err := q.DeleteServiceConnectionSlot(ctx, controlstatedb.DeleteServiceConnectionSlotParams{
			PublisherConnectionID: old.PublisherConnectionID, ServiceRunID: run.ID, Now: timestamptz(now),
		})
		if err != nil {
			return err
		}
		if count != 1 {
			return ErrServiceAccess
		}
	}
	for index, old := range selected {
		binding, err := checkedPrivateAssignmentBinding(old.ServiceID, old.ServiceRunID, old.PublisherConnectionID, old.RunNumber, old.ConnectionAssignmentRevision)
		if err != nil {
			return err
		}
		replacement, err := serviceConnectionReplacement(seed, run, binding, old.ConnectionSlot, choices[index], now)
		if err != nil {
			return err
		}
		_, err = q.InsertServiceConnectionSlot(ctx, replacement)
		if err != nil {
			return err
		}
	}
	return nil
}

func serviceConnectionReplacement(seed credentials.AssignmentSeed, run controlstatedb.ControlServiceRun, binding privateAssignmentBinding, slot int16, placement relayServicePlacement, now time.Time) (controlstatedb.InsertServiceConnectionSlotParams, error) {
	var replacement controlstatedb.InsertServiceConnectionSlotParams
	if !binding.ServiceRunReference.matches(run) {
		return replacement, ErrServiceAccess
	}
	revision, err := nextPrivateRevision(binding.revision)
	if err != nil {
		return replacement, err
	}
	id, err := opaqueid.New(opaqueid.PublisherConnectionPrefix)
	if err != nil {
		return replacement, err
	}
	_, digest, err := credentials.DeriveAssignmentCredential(seed, publisherConnectionCredentialContext(id, revision))
	if err != nil {
		return replacement, err
	}
	return controlstatedb.InsertServiceConnectionSlotParams{
		PublisherConnectionID: id, ServiceRunID: run.ID, ServiceID: run.ServiceID,
		RunNumber: run.RunNumber, ConnectionSlot: slot,
		ConnectionAssignmentRevision: revision, RelayServiceID: placement.relayServiceID,
		RelayAddress: placement.relayAddress, TlsServerName: placement.tlsServerName,
		CredentialDigest: digest[:], CredentialExpiresAt: timestamptz(now.Add(2 * time.Minute)),
		AssignedAt: timestamptz(now),
	}, nil
}

func reuseServiceConnectionReservations(ctx context.Context, tx pgx.Tx, seed credentials.AssignmentSeed, run controlstatedb.ControlServiceRun, stale []controlstatedb.ListServiceConnectionSlotsNeedingReplacementRow, now time.Time) (bool, error) {
	for _, old := range stale {
		// never-ready claims still need a fresh placement decision and its guards.
		if !old.SessionOpen || old.State != string(PublisherConnectionReady) {
			return false, nil
		}
	}
	// ready reservations already consume capacity. replace the complete set in
	// place only after checking every service; never partially renew assignments.
	// the eventual claims still check current relay leases and process capacity.
	replacements := make([]controlstatedb.InsertServiceConnectionSlotParams, len(stale))
	for index, old := range stale {
		placement := relayServicePlacement{relayServiceID: old.RelayServiceID}
		err := tx.QueryRow(ctx, `SELECT service.relay_address,service.tls_server_name
			FROM control.relay_services service
			JOIN control.relay_service_reservations reservation USING(relay_service_id)
			WHERE service.relay_service_id=$1 AND service.enabled
				AND reservation.reserved_slot_count>0
				AND reservation.reserved_slot_count<=(SELECT COALESCE(sum(lease.connection_capacity),0)
					FROM control.relay_leases lease WHERE lease.relay_service_id=service.relay_service_id
						AND lease.lease_expires_at>$2 AND NOT lease.draining AND lease.protocol_version=1
						AND lease.connection_capacity>0 AND lease.stream_capacity>0)`,
			old.RelayServiceID, now).Scan(&placement.relayAddress, &placement.tlsServerName)
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		binding, err := checkedPrivateAssignmentBinding(old.ServiceID, old.ServiceRunID, old.PublisherConnectionID, old.RunNumber, old.ConnectionAssignmentRevision)
		if err != nil {
			return false, err
		}
		replacements[index], err = serviceConnectionReplacement(seed, run, binding, old.ConnectionSlot, placement, now)
		if err != nil {
			return false, err
		}
	}
	for index, replacement := range replacements {
		old := stale[index]
		updated, err := tx.Exec(ctx, `UPDATE control.service_connection_slots
			SET publisher_connection_id=$3,connection_assignment_revision=$4,
				relay_address=$5,tls_server_name=$6,credential_digest=$7,credential_expires_at=$8,
				assigned_at=$9,state='assigned',relay_id=NULL,relay_run_id=NULL,relay_lease_revision=NULL
			WHERE service_run_id=$1 AND publisher_connection_id=$2 AND session_open AND state='ready'`,
			run.ID, old.PublisherConnectionID, replacement.PublisherConnectionID, replacement.ConnectionAssignmentRevision,
			replacement.RelayAddress, replacement.TlsServerName, replacement.CredentialDigest, replacement.CredentialExpiresAt,
			replacement.AssignedAt)
		if err != nil {
			return false, err
		}
		if updated.RowsAffected() != 1 {
			return false, ErrServiceAccess
		}
	}
	return true, nil
}

func (d *Database) HeartbeatServiceRun(ctx context.Context, serviceID, runID, token string, now time.Time, report ServiceRunHealth) (result ServiceRunState, retErr error) {
	ctx, finish := d.observeOperation(ctx, observability.OpHeartbeatServiceRun)
	defer func() { finish(retErr) }()
	clock := newAuthorizationClock(now)
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "heartbeat service run", &retErr)()
	if err = lockServiceOwner(ctx, tx, serviceID); err != nil {
		return result, err
	}
	// siblings can renew together. the owner guard still fences revocation and
	// the shared service lock keeps endpoint edits out until this run commits.
	if err = queueRunReader(ctx, tx, serviceID); err != nil {
		return result, err
	}
	endpoint, err := lockServiceRunEndpoint(ctx, tx, serviceID)
	if err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	run, err := d.serviceRunAuthorization(ctx, tx, q, serviceID, runID, token, clock.current())
	if err != nil {
		return result, err
	}
	previousExpiration := run.ServingUntil.Time
	firstReadiness := !run.ReadyAt.Valid
	if report.StreamCapacity < 1 || report.StreamCapacity > 1<<20 || report.ActiveStreams < 0 {
		return result, ErrServiceAccess
	}
	if _, err = tx.Exec(ctx, `UPDATE control.service_runs SET healthy=$2,stream_capacity=$3,reported_streams=$4 WHERE id=$1`, runID, report.Healthy, report.StreamCapacity, report.ActiveStreams); err != nil {
		return result, err
	}
	run.Healthy, run.StreamCapacity, run.ReportedStreams = report.Healthy, report.StreamCapacity, report.ActiveStreams
	until := now.Add(45 * time.Second)
	if run.PublisherExpiresAt.Time.After(until) {
		until = run.PublisherExpiresAt.Time
	}
	servingUntil := now.Add(d.servingTolerance())
	permission, err := serviceRunPublisherPermission(ctx, tx, run, clock.current())
	if err != nil {
		return result, err
	}
	if permission.Valid {
		servingUntil = minTime(servingUntil, permission.Time)
	}
	run, err = q.RenewServiceRun(ctx, controlstatedb.RenewServiceRunParams{
		ID: runID, ServiceID: serviceID, RunNumber: run.RunNumber,
		RunTokenDigest: run.RunTokenDigest, PublisherExpiresAt: timestamptz(until), Now: timestamptz(clock.current()),
		ServingObservedAt: timestamptz(now), ServingUntil: timestamptz(servingUntil),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return result, ErrServiceAccess
	}
	if err != nil {
		return result, err
	}
	ready, err := countReadyServiceConnections(ctx, tx, runID, clock.current())
	if err != nil {
		return result, err
	}
	certificateReady := run.CertificateExpiresAt.Valid && run.CertificateExpiresAt.Time.After(clock.current())
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
	var previousConnections []controlstatedb.ControlServiceConnectionSlot
	if ready < 2 {
		previousConnections, err = q.ListServiceConnectionSlots(ctx, run.ID)
		if err != nil {
			return result, err
		}
		if err = replenishServiceConnections(ctx, tx, q, seed, run, clock.current()); err != nil {
			return result, err
		}
	}
	run, err = advanceServiceRunReadiness(ctx, tx, q, run, clock)
	if err != nil {
		return result, err
	}
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
	endpointReady, err := serviceRunPublicEndpointReady(ctx, tx, endpoint, run, clock.current())
	if err != nil {
		return result, err
	}
	aliasReady, err := serviceRunAliasReady(ctx, tx, endpoint, run, endpointReady, clock.current())
	if err != nil {
		return result, err
	}
	if !previousExpiration.After(clock.current()) || !run.PublisherExpiresAt.Time.After(clock.current()) {
		return result, ErrServiceAccess
	}
	confirmations, err := d.policyConfirmations(ctx, q, run, run.ServingObservedAt.Time)
	if err != nil {
		return result, err
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	if firstReadiness && run.ReadyAt.Valid {
		d.activity.metrics.Load().ObserveServiceRunReady()
	}
	for _, previous := range previousConnections {
		for _, current := range connections {
			if previous.ConnectionSlot != current.ConnectionSlot || previous.PublisherConnectionID == current.PublisherConnectionID {
				continue
			}
			reason := "unavailable"
			if previous.State == "ready" {
				reason = "failed_ready"
			} else if !previous.CredentialExpiresAt.Time.After(now) {
				reason = "expired"
			}
			d.activity.metrics.Load().AddAssignmentReplacements(reason, 1)
		}
	}
	return ServiceRunState{ServiceID: serviceID, RunID: runID, RunNumber: run.RunNumber,
		PolicyConfirmation: confirmations.canonical, AliasPolicyConfirmation: confirmations.alias,
		EndpointRevision: endpoint.revision, PublicEndpointReady: endpointReady,
		RunHostname: run.RunHostname, RunAliasReady: aliasReady,
		Healthy: run.Healthy, StreamCapacity: run.StreamCapacity, ReportedStreams: run.ReportedStreams,
		State: run.State, ExpiresAt: run.PublisherExpiresAt.Time, ObservedAt: run.ServingObservedAt.Time, ServingUntil: run.ServingUntil.Time,
		Connections: connections}, nil
}

func (d *Database) CloseServiceRun(ctx context.Context, serviceID, runID, token string, now time.Time) (retErr error) {
	ctx, finish := d.observeOperation(ctx, observability.OpCloseServiceRun)
	defer func() { finish(retErr) }()
	digest, err := credentials.ParseServiceRunToken(credentials.ServiceRunToken(token))
	if err != nil || !opaqueid.Valid(runID, opaqueid.ServiceRunPrefix) {
		return ErrServiceAccess
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "close service run", &retErr)()
	if err = queueRunWriter(ctx, tx, serviceID); err != nil {
		return err
	}
	q := controlstatedb.New(tx)
	service, err := q.LockService(ctx, serviceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrServiceAccess
	}
	if err != nil {
		return err
	}
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
	expected := run.RunTokenDigest
	if !run.StartedAt.Valid {
		// a never-started run has no stored serving credential. derive the
		// preparation's cleanup token even after revocation has closed it.
		seed, err := d.serviceAssignmentSeed(run)
		if err != nil {
			return err
		}
		_, preparedDigest := serviceRunCredential(seed, run.ID)
		expected = preparedDigest[:]
	}
	state := serviceRunLifecycleState(run.State)
	if !bytes.Equal(digest[:], expected) || !state.valid() || run.ClosedAt.Valid != (state == serviceRunClosed) {
		return ErrServiceAccess
	}
	if run.GuestID.Valid {
		trial, err := q.GetGuestTrialByID(ctx, run.GuestID.String)
		if err != nil {
			return err
		}
		if err = d.guestSourceAddress(trial, publisherRequestSource(ctx)); err != nil {
			return err
		}
	}
	if run.ClosedAt.Valid {
		// exact-token retries confirm only this run's terminal state. they
		// cannot change a replacement or recreate any serving authority.
		return tx.Commit(ctx)
	}
	if !service.Enabled || service.DeletedAt.Valid {
		return ErrServiceAccess
	}
	count, err := closeServiceRun(ctx, q, run, now)
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrServiceAccess
	}
	return tx.Commit(ctx)
}
