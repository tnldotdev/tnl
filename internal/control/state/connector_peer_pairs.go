package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

const maxConnectorPeerPairOwners = 64

// ConnectorPeerPairRequest is an authority request, not a visitor stream opening.
// source must be a current device control session or workload credential. the
// signature proves possession of that source's enrolled native key.
type ConnectorPeerPairRequest struct {
	ServiceID, ServiceRunID, PublisherIdentityID, IdempotencyKey string
	RunNumber                                                    int64
	Subject                                                      VisitorSubject
	Source                                                       VisitorTokenSource
	Signature                                                    []byte
	Action                                                       string
	RequestedAt                                                  time.Time
	PreviousPairID                                               string
	PreviousGeneration                                           int64
	ExpectedRelays                                               [2]ConnectorPeerPairRelay
}

type ConnectorPeerPairRelay struct {
	PublisherConnectionID string             `json:"publisher_connection_id"`
	AssignmentRevision    int64              `json:"assignment_revision"`
	RelayLease            RelayLeaseIdentity `json:"relay_lease"`
	RelayAddress          string             `json:"relay_address"`
	TLSServerName         string             `json:"tls_server_name"`
}

type ConnectorPeerPair struct {
	ID, ServiceID, ServiceRunID, PublisherIdentityID string
	Subject                                          VisitorSubject
	RunNumber, DeliveryGeneration                    int64
	Key                                              string
	DeliveryID                                       [16]byte
	Relays                                           [2]ConnectorPeerPairRelay
	ExpiresAt                                        time.Time
	ObservedAt, PublisherPreparedUntil               time.Time
	RunValidUntil                                    time.Time
	Metadata                                         ServiceMetadata
	VisitorPermission                                IssuedVisitorToken
	SessionKey, OperationID, BindingChallenge        string
	TrustRevision                                    int64
	BindingState                                     string
	SourceIP                                         netip.Addr
	PublisherProvedUntil                             time.Time
}

func (ConnectorPeerPair) String() string   { return "connector peer pair" }
func (ConnectorPeerPair) GoString() string { return "connector peer pair" }

// proof adapts durable state fields to the handwritten signing value. state
// does not define its own proof format or serialize the signature input.
func (r ConnectorPeerPairRequest) proof() tunnelv1.ConnectorPeerPairProof {
	p := tunnelv1.ConnectorPeerPairProof{ServiceID: r.ServiceID, ServiceRunID: r.ServiceRunID, RunNumber: r.RunNumber,
		PublisherIdentityID: r.PublisherIdentityID, Subject: r.Subject, Action: r.Action, IdempotencyKey: r.IdempotencyKey,
		RequestedAt: r.RequestedAt, PreviousPairID: r.PreviousPairID, PreviousGeneration: r.PreviousGeneration}
	for i, relay := range r.ExpectedRelays {
		p.ExpectedRelays[i] = tunnelv1.ConnectorPeerPairRelay{PublisherConnectionID: relay.PublisherConnectionID,
			AssignmentRevision: relay.AssignmentRevision, RelayAddress: relay.RelayAddress, TLSServerName: relay.TLSServerName,
			RelayLease: tunnelv1.ConnectorPeerRelayLease{RelayServiceID: relay.RelayLease.RelayServiceID, RelayID: relay.RelayLease.RelayID,
				RelayRunID: relay.RelayLease.RelayRunID, RelayLeaseRevision: relay.RelayLease.RelayLeaseRevision}}
	}
	return p
}

func connectorPairSubjectID(s VisitorSubject) string {
	if s.Kind == tunnelv1.VisitorHumanDevice {
		return s.DeviceID
	}
	return s.WorkloadSessionID
}

func connectorPeerPairKeyContext(id string) string { return "connector-peer-pair/" + id }

// PrepareConnectorPeerPair creates or retrieves one connector owner's delivery.
// its initial signed create key identifies the owner, independently of the
// enrolled subject. a signed replacement retains that owner's replay fence.
func (d *Database) PrepareConnectorPeerPair(ctx context.Context, r ConnectorPeerPairRequest, now time.Time) (result ConnectorPeerPair, retErr error) {
	if r.Action != "create" && r.Action != "replace" {
		return result, ErrServiceAccess
	}
	return d.authorizeConnectorPeerPair(ctx, r, "", now)
}

// RenewConnectorPeerPair rechecks current authority for an unexpired pair before
// extending its serving deadline. it never changes the delivery generation.
func (d *Database) RenewConnectorPeerPair(ctx context.Context, issuer string, r ConnectorPeerPairRequest, now time.Time) (ConnectorPeerPair, error) {
	if r.Action != "renew" {
		return ConnectorPeerPair{}, ErrServiceAccess
	}
	return d.authorizeConnectorPeerPair(ctx, r, issuer, now)
}

func (d *Database) authorizeConnectorPeerPair(ctx context.Context, r ConnectorPeerPairRequest, issuer string, now time.Time) (result ConnectorPeerPair, retErr error) {
	clock := newAuthorizationClock(now)
	started, checkedNow := clock.started, clock.current
	message, err := r.proof().Message()
	requestAt := r.RequestedAt.UTC().Truncate(time.Microsecond)
	if err != nil || len(r.Signature) != ed25519.SignatureSize || d.storageKey == nil || now.IsZero() ||
		requestAt.After(now.Add(5*time.Second)) || !requestAt.Add(5*time.Minute).After(now) {
		return result, ErrServiceAccess
	}
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: r.ServiceID}
	switch r.Source.(type) {
	case DeviceTokenSource, WorkloadTokenSource:
	default:
		return result, ErrServiceAccess
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "prepare connector peer pair", &retErr)()
	// the source reader owns current service visitor permission, including the
	// session/credential deadline. it takes the team/service admission locks.
	authority, err := d.visitorAuthorityForSource(ctx, tx, scope, r.Source, clock)
	if err != nil {
		return result, err
	}
	permission := authority.Permission
	subject, err := visitortoken.ConnectorSubject(permission.Subject)
	if err != nil || subject != r.Subject {
		return result, ErrServiceAccess
	}
	key := authority.PublicKey
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, message, r.Signature) {
		return result, ErrServiceAccess
	}
	q := controlstatedb.New(tx)
	var parentSession pgtype.Text
	if subject.Kind == tunnelv1.VisitorHumanDevice {
		principal, _ := ctx.Value(controlPrincipalKey{}).(ControlPrincipal)
		if principal.SessionID == "" {
			return result, ErrServiceAccess
		}
		parentSession = text(principal.SessionID)
	}
	run, err := q.LockServiceRun(ctx, controlstatedb.LockServiceRunParams{ID: r.ServiceRunID, ServiceID: r.ServiceID})
	if err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	retainedRun := r.Action == "renew" && run.State == "starting" && run.ReadyAt.Valid
	if run.RunNumber != r.RunNumber || run.PublisherIdentityID != r.PublisherIdentityID || (run.State != "ready" && !retainedRun) || !run.Healthy ||
		run.ClosedAt.Valid || !run.PublisherExpiresAt.Time.After(now) || !run.CertificateExpiresAt.Valid || !run.CertificateExpiresAt.Time.After(now) {
		return result, ErrServiceAccess
	}
	publisherUntil, err := connectorPeerPublisherAuthority(ctx, tx, run, now)
	if err != nil {
		return result, err
	}
	deadline := minTime(publisherUntil, minTime(permission.ExpiresAt, authority.ConnectorUntil))
	service, err := q.GetService(ctx, r.ServiceID)
	if err != nil {
		return result, err
	}
	metadata, err := checkedServiceMetadata(service)
	if err != nil {
		return result, err
	}
	// retain the entry-time serving cap. elapsed time only narrows the time left
	// to authorize; a slow database must not mint a later deadline.
	recheckUntil := minTime(deadline, requestAt.Add(5*time.Minute))
	if r.Action != "renew" {
		slots, err := q.ListServiceConnectionSlots(ctx, run.ID)
		if err != nil {
			return result, err
		}
		if len(slots) != 2 || slots[0].RelayServiceID == slots[1].RelayServiceID {
			return result, ErrServiceAccess
		}
		for i, slot := range slots {
			if int(slot.ConnectionSlot) != i || slot.ServiceID != r.ServiceID || slot.RunNumber != r.RunNumber || slot.State != "ready" || !slot.SessionOpen ||
				!opaqueid.Valid(slot.PublisherConnectionID, opaqueid.PublisherConnectionPrefix) || slot.ConnectionAssignmentRevision < 1 || !slot.RelayID.Valid || !slot.RelayRunID.Valid || !slot.RelayLeaseRevision.Valid || slot.RelayLeaseRevision.Int64 < 1 {
				return result, ErrServiceAccess
			}
			var lease RelayLeaseIdentity
			var address, serverName string
			var leaseRevision int64
			var leaseUntil time.Time
			err = tx.QueryRow(ctx, `SELECT lease.relay_service_id,lease.relay_id,lease.relay_run_id,lease.relay_lease_revision,service.relay_address,service.tls_server_name,lease.lease_expires_at
		    FROM control.relay_leases lease JOIN control.relay_services service ON service.relay_service_id=lease.relay_service_id
		    WHERE lease.relay_id=$1 AND lease.relay_run_id=$2 AND lease.relay_lease_revision=$3 AND lease.relay_service_id=$4
		    AND lease.lease_expires_at>$5 AND NOT lease.draining AND service.enabled FOR SHARE OF lease,service`, slot.RelayID.String, slot.RelayRunID.String, slot.RelayLeaseRevision.Int64, slot.RelayServiceID, now).
				Scan(&lease.RelayServiceID, &lease.RelayID, &lease.RelayRunID, &leaseRevision, &address, &serverName, &leaseUntil)
			if err != nil {
				return result, publisherLookupError(err, ErrServiceAccess)
			}
			if slot.RelayAddress != address || slot.TlsServerName != serverName {
				return ConnectorPeerPair{}, ErrServiceAccess
			}
			lease.RelayLeaseRevision = uint64(leaseRevision)
			recheckUntil = minTime(recheckUntil, leaseUntil)
			// a lease is required now and again at relay claim, but its short
			// renewal interval is not the pair's serving authority deadline.
			result.Relays[i] = ConnectorPeerPairRelay{PublisherConnectionID: slot.PublisherConnectionID, AssignmentRevision: slot.ConnectionAssignmentRevision,
				RelayLease: lease, RelayAddress: address, TLSServerName: serverName}
		}
		if !recheckUntil.After(checkedNow()) || r.ExpectedRelays != result.Relays {
			return ConnectorPeerPair{}, ErrServiceAccess
		}
	}
	requestDigest := sha256.Sum256(message)
	ownerKey := r.IdempotencyKey
	needsOwnerSlot := true
	var row controlstatedb.ControlConnectorPeerPair
	// the signed key names the owner for every action. pair IDs never select one.
	row, err = q.GetConnectorPeerPairForOwner(ctx, controlstatedb.GetConnectorPeerPairForOwnerParams{
		SubjectKind: string(subject.Kind), SubjectID: connectorPairSubjectID(subject), ServiceRunID: run.ID, OwnerKey: ownerKey})
	if r.Action == "replace" && errors.Is(err, pgx.ErrNoRows) {
		return ConnectorPeerPair{}, ErrServiceConflict
	}
	if err == nil {
		checked := checkedNow()
		var previous [2]ConnectorPeerPairRelay
		if row.ServiceID != r.ServiceID || row.ServiceRunID != r.ServiceRunID || row.RunNumber != r.RunNumber || row.PublisherIdentityID != r.PublisherIdentityID ||
			json.Unmarshal(row.Slots, &previous) != nil || row.SubjectKind != subject.Kind || row.SubjectID != connectorPairSubjectID(subject) {
			return ConnectorPeerPair{}, ErrServiceConflict
		}
		if now.Before(row.LastAuthorizedAt.Time) {
			return ConnectorPeerPair{}, ErrServiceConflict
		}
		if r.Action != "replace" && (len(row.SessionKeyCiphertext) == 0 || row.TrustRevision != metadata.TrustRevision) {
			return ConnectorPeerPair{}, ErrServiceAccess
		}
		switch r.Action {
		case "create":
			if row.ParentControlSessionID != parentSession || !row.ExpiresAt.Time.After(checked) || previous != result.Relays || !requestAt.Equal(row.LastRequestAt.Time) || !bytes.Equal(row.RequestDigest, requestDigest[:]) {
				return ConnectorPeerPair{}, ErrServiceConflict
			}
			recheckUntil = minTime(recheckUntil, row.ExpiresAt.Time)
			row, err = q.LimitConnectorPeerPair(ctx, controlstatedb.LimitConnectorPeerPairParams{ID: row.ID, Now: timestamptz(now), AuthorityExpiresAt: timestamptz(deadline)})
		case "renew":
			if row.ParentControlSessionID != parentSession || !row.ExpiresAt.Time.After(checked) || row.ID != r.PreviousPairID ||
				row.DeliveryGeneration != r.PreviousGeneration || row.IdempotencyKey != r.IdempotencyKey {
				return ConnectorPeerPair{}, ErrServiceAccess
			}
			result.Relays = previous
			// even a fresh renewal must finish before the old authority expires.
			recheckUntil = minTime(recheckUntil, row.ExpiresAt.Time)
			if requestAt.After(row.LastRequestAt.Time) && requestAt.After(row.LastAuthorizedAt.Time) && now.After(row.LastAuthorizedAt.Time) {
				row, err = q.RenewConnectorPeerPair(ctx, controlstatedb.RenewConnectorPeerPairParams{ID: row.ID, Now: timestamptz(now), RequestAt: timestamptz(requestAt), RenewalDigest: requestDigest[:], AuthorityExpiresAt: timestamptz(deadline)})
			} else if requestAt.Equal(row.LastRequestAt.Time) && bytes.Equal(row.LastRenewalDigest, requestDigest[:]) {
				row, err = q.LimitConnectorPeerPair(ctx, controlstatedb.LimitConnectorPeerPairParams{ID: row.ID, Now: timestamptz(now), AuthorityExpiresAt: timestamptz(deadline)})
			} else {
				return ConnectorPeerPair{}, ErrServiceConflict
			}
		case "replace":
			// a later renewal supersedes this reply proof; it cannot lend its bound.
			if row.ParentControlSessionID == parentSession && row.ExpiresAt.Time.After(checked) && previous == result.Relays && row.IdempotencyKey == r.IdempotencyKey && requestAt.Equal(row.LastRequestAt.Time) && bytes.Equal(row.RequestDigest, requestDigest[:]) {
				recheckUntil = minTime(recheckUntil, row.ExpiresAt.Time)
				row, err = q.LimitConnectorPeerPair(ctx, controlstatedb.LimitConnectorPeerPairParams{ID: row.ID, Now: timestamptz(now), AuthorityExpiresAt: timestamptz(deadline)})
				break
			}
			if row.ParentControlSessionID != parentSession || row.ID != r.PreviousPairID || row.DeliveryGeneration != r.PreviousGeneration ||
				r.IdempotencyKey != row.IdempotencyKey || requestAt.Before(row.LastRequestAt.Time) {
				return ConnectorPeerPair{}, ErrServiceConflict
			}
			needsOwnerSlot = !row.ExpiresAt.Time.After(now) && !row.ReplayFenceUntil.Time.After(now)
			if count, deleteErr := q.ReplaceConnectorPeerPair(ctx, row.ID); deleteErr != nil || count != 1 {
				return ConnectorPeerPair{}, errors.Join(ErrServiceConflict, deleteErr)
			}
			err = pgx.ErrNoRows
		}
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return ConnectorPeerPair{}, publisherLookupError(err, ErrServiceAccess)
		}
	}
	if err == nil {
		secret, _, err := d.storageKey.Open(row.StorageKeyID, connectorPeerPairKeyContext(row.ID), row.KeyCiphertext)
		if err != nil {
			return ConnectorPeerPair{}, err
		}
		defer clear(secret)
		digest := sha256.Sum256(secret)
		if !bytes.Equal(digest[:], row.KeyDigest) {
			return ConnectorPeerPair{}, ErrServiceAccess
		}
		result.Key = base64.RawURLEncoding.EncodeToString(secret)
	} else if errors.Is(err, pgx.ErrNoRows) {
		if r.Action == "renew" || r.Action == "replace" && row.ID == "" || r.Action == "create" && r.PreviousPairID != "" {
			return ConnectorPeerPair{}, ErrServiceAccess
		}
		if needsOwnerSlot {
			// the run lock serializes fresh owners with replacement and renewal.
			// retained replay fences consume the same bounded owner budget.
			count, err := q.CountConnectorPeerPairOwners(ctx, controlstatedb.CountConnectorPeerPairOwnersParams{
				ServiceRunID: run.ID, Now: timestamptz(now), OwnerLimit: maxConnectorPeerPairOwners})
			if err != nil {
				return ConnectorPeerPair{}, err
			}
			if count >= maxConnectorPeerPairOwners {
				return ConnectorPeerPair{}, ErrServiceConflict
			}
		}
		id, err := opaqueid.New("cpp_")
		if err != nil {
			return ConnectorPeerPair{}, err
		}
		secret := make([]byte, 32)
		if _, err = rand.Read(secret); err != nil {
			return ConnectorPeerPair{}, err
		}
		defer clear(secret)
		digest := sha256.Sum256(secret)
		sealed, err := d.storageKey.Seal(connectorPeerPairKeyContext(id), secret)
		if err != nil {
			return ConnectorPeerPair{}, err
		}
		encoded, err := json.Marshal(result.Relays)
		if err != nil {
			return ConnectorPeerPair{}, err
		}
		// a delivery identifier collision must never reuse another pair's
		// header. retry only that named constraint; other conflicts are errors.
		err = pgx.ErrNoRows
		for attempt := 0; attempt < 5; attempt++ {
			var deliveryID [16]byte
			if _, err = rand.Read(deliveryID[:]); err != nil {
				return ConnectorPeerPair{}, err
			}
			if deliveryID == [16]byte{} {
				continue
			}
			row, err = q.InsertConnectorPeerPair(ctx, controlstatedb.InsertConnectorPeerPairParams{
				ID: id, ServiceID: r.ServiceID, ServiceRunID: run.ID, RunNumber: run.RunNumber, PublisherIdentityID: run.PublisherIdentityID,
				SubjectKind: string(subject.Kind), SubjectID: connectorPairSubjectID(subject), IdempotencyKey: r.IdempotencyKey,
				ParentControlSessionID: parentSession, OwnerKey: ownerKey,
				RequestDigest: requestDigest[:], KeyDigest: digest[:], KeyCiphertext: sealed, DeliveryID: deliveryID[:], StorageKeyID: d.storageKey.CurrentID(),
				Slots: encoded, Now: timestamptz(now), RequestAt: timestamptz(requestAt), ExpiresAt: timestamptz(deadline),
			})
			if !errors.Is(err, pgx.ErrNoRows) {
				break
			}
		}
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ConnectorPeerPair{}, ErrServiceConflict
			}
			var conflict *pgconn.PgError
			if errors.As(err, &conflict) && conflict != nil && conflict.Code == "23505" &&
				(conflict.ConstraintName == "connector_peer_pairs_owner_key" || conflict.ConstraintName == "connector_peer_pairs_request_key") {
				return ConnectorPeerPair{}, errors.Join(ErrServiceConflict, err)
			}
			return ConnectorPeerPair{}, err
		}
		result.Key = base64.RawURLEncoding.EncodeToString(secret)
		sessionSecret := make([]byte, 32)
		if _, err := rand.Read(sessionSecret); err != nil {
			return ConnectorPeerPair{}, err
		}
		defer clear(sessionSecret)
		sessionSealed, err := d.storageKey.Seal(connectorPeerSessionKeyContext(row.ID), sessionSecret)
		if err != nil {
			return ConnectorPeerPair{}, err
		}
		sessionDigest := sha256.Sum256(sessionSecret)
		row, err = q.InitializeConnectorPeerSession(ctx, controlstatedb.InitializeConnectorPeerSessionParams{ID: row.ID,
			Ciphertext: sessionSealed, Digest: sessionDigest[:], StorageKeyID: text(d.storageKey.CurrentID()), TrustRevision: metadata.TrustRevision})
		if err != nil {
			return ConnectorPeerPair{}, err
		}
	} else {
		return ConnectorPeerPair{}, err
	}
	result.ID, result.ServiceID, result.ServiceRunID, result.PublisherIdentityID = row.ID, r.ServiceID, run.ID, run.PublisherIdentityID
	result.Subject, result.RunNumber, result.DeliveryGeneration = subject, run.RunNumber, row.DeliveryGeneration
	if len(row.DeliveryID) != len(result.DeliveryID) {
		return ConnectorPeerPair{}, ErrServiceAccess
	}
	copy(result.DeliveryID[:], row.DeliveryID)
	if result.DeliveryID == [16]byte{} {
		return ConnectorPeerPair{}, ErrServiceAccess
	}
	result.ExpiresAt = row.ExpiresAt.Time
	result.ObservedAt = now
	result.SessionKey, err = d.connectorPeerSessionKey(row)
	if err != nil {
		return ConnectorPeerPair{}, err
	}
	result.TrustRevision, result.OperationID, result.BindingChallenge = row.TrustRevision, row.BindingOperationID, base64.RawURLEncoding.EncodeToString(row.BindingChallenge)
	result.BindingState = "active"
	if row.PublisherProvedUntil.Valid {
		result.PublisherProvedUntil = row.PublisherProvedUntil.Time
	}
	if row.PublisherPreparedUntil.Valid && row.PublisherPreparedUntil.Time.After(now) {
		result.PublisherPreparedUntil = minTime(row.PublisherPreparedUntil.Time, result.ExpiresAt)
	}
	if r.Action == "renew" {
		// sign the permission already authenticated under these admission locks,
		// not a second source read or a later transaction. key retention rolls
		// back with pair renewal if any final authority deadline is spent.
		service, err := q.GetService(ctx, r.ServiceID)
		if err != nil {
			return ConnectorPeerPair{}, err
		}
		result.Metadata, err = checkedServiceMetadata(service)
		if err != nil {
			return ConnectorPeerPair{}, err
		}
		if result.Metadata.Endpoint == nil {
			return ConnectorPeerPair{}, ErrServiceMetadata
		}
		result.RunValidUntil = publisherUntil
		permission.ExpiresAt = minTime(permission.ExpiresAt, result.ExpiresAt).Truncate(time.Second)
		if !permission.ExpiresAt.After(checkedNow()) {
			return ConnectorPeerPair{}, ErrServiceAccess
		}
		token, err := d.signVisitorPermission(ctx, tx, issuer, permission, now)
		if err != nil {
			return ConnectorPeerPair{}, err
		}
		result.VisitorPermission = IssuedVisitorToken{Token: token, Permission: permission, ServiceTrustRevision: result.Metadata.TrustRevision}
		recheckUntil = minTime(recheckUntil, permission.ExpiresAt)
	}
	// execute deferred constraints while expiry can still roll back every write,
	// including predecessor deletion and renewal. all authority rows above remain
	// locked, so only their captured absolute deadlines can change with time.
	if _, err = tx.Exec(ctx, "SET CONSTRAINTS ALL IMMEDIATE"); err != nil {
		return ConnectorPeerPair{}, err
	}
	recheckUntil = minTime(recheckUntil, result.ExpiresAt)
	if !recheckUntil.After(checkedNow()) {
		return ConnectorPeerPair{}, ErrServiceAccess
	}
	commit, stop := context.WithDeadline(ctx, started.Add(recheckUntil.Sub(now)))
	defer stop()
	if err = tx.Commit(commit); err != nil {
		return ConnectorPeerPair{}, err
	}
	if !recheckUntil.After(checkedNow()) {
		return ConnectorPeerPair{}, ErrServiceAccess
	}
	return result, nil
}

// CleanupExpiredConnectorPeerPairs removes expired delivery material after its
// signed request can no longer be replayed. callers may repeat bounded batches.
func (d *Database) CleanupExpiredConnectorPeerPairs(ctx context.Context, now time.Time, limit int) (count int64, retErr error) {
	if now.IsZero() || limit < 1 || limit > 10000 {
		return 0, ErrServiceAccess
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer rollback(ctx, tx, "expire connector bindings", &retErr)()
	rows, err := tx.Query(ctx, `SELECT pair.id FROM control.connector_peer_pairs pair JOIN control.connector_peer_pending_bindings pending ON pending.pair_id=pair.id
		WHERE pending.pending_until<=$1 OR pair.expires_at<=$1 ORDER BY pending.pending_until,pair.id LIMIT $2 FOR UPDATE OF pair SKIP LOCKED`, now, limit)
	if err != nil {
		return 0, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return 0, err
	}
	q := controlstatedb.New(tx)
	for _, id := range ids {
		pair, err := q.LockConnectorPeerPairForLegClaim(ctx, id)
		if err != nil {
			return 0, err
		}
		if _, err = expireConnectorPeerPending(ctx, tx, pair, now); err != nil {
			return 0, err
		}
	}
	count, err = q.CleanupExpiredConnectorPeerPairs(ctx, controlstatedb.CleanupExpiredConnectorPeerPairsParams{Now: timestamptz(now), BatchSize: int32(limit)})
	if err != nil {
		return 0, err
	}
	return count, tx.Commit(ctx)
}
