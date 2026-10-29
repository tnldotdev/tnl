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

const maxNativePeerPairOwners = 64

// NativePeerPairRequest is an authority request, not a visitor stream opening.
// source must be a current device control session or workload credential. the
// signature proves possession of that source's enrolled native key.
type NativePeerPairRequest struct {
	ServiceID, ServiceRunID, PublisherIdentityID, IdempotencyKey string
	RunNumber                                                    int64
	Subject                                                      VisitorSubject
	Source                                                       VisitorTokenSource
	Signature                                                    []byte
	Action                                                       string
	RequestedAt                                                  time.Time
	PreviousPairID                                               string
	PreviousGeneration                                           int64
	ExpectedRelays                                               [2]NativePeerPairRelay
}

type NativePeerPairRelay struct {
	PublisherConnectionID string             `json:"publisher_connection_id"`
	AssignmentRevision    int64              `json:"assignment_revision"`
	RelayLease            RelayLeaseIdentity `json:"relay_lease"`
	RelayAddress          string             `json:"relay_address"`
	TLSServerName         string             `json:"tls_server_name"`
}

type NativePeerPair struct {
	ID, ServiceID, ServiceRunID, PublisherIdentityID string
	Subject                                          VisitorSubject
	RunNumber, DeliveryGeneration                    int64
	Key                                              string
	DeliveryID                                       [16]byte
	Relays                                           [2]NativePeerPairRelay
	ExpiresAt                                        time.Time
	ObservedAt, PublisherPreparedUntil               time.Time
}

func (NativePeerPair) String() string   { return "native peer pair" }
func (NativePeerPair) GoString() string { return "native peer pair" }

// proof adapts durable state fields to the handwritten signing value. state
// does not define its own proof format or serialize the signature input.
func (r NativePeerPairRequest) proof() tunnelv1.NativePeerPairProof {
	p := tunnelv1.NativePeerPairProof{ServiceID: r.ServiceID, ServiceRunID: r.ServiceRunID, RunNumber: r.RunNumber,
		PublisherIdentityID: r.PublisherIdentityID, Subject: r.Subject, Action: r.Action, IdempotencyKey: r.IdempotencyKey,
		RequestedAt: r.RequestedAt, PreviousPairID: r.PreviousPairID, PreviousGeneration: r.PreviousGeneration}
	for i, relay := range r.ExpectedRelays {
		p.ExpectedRelays[i] = tunnelv1.NativePeerPairRelay{PublisherConnectionID: relay.PublisherConnectionID,
			AssignmentRevision: relay.AssignmentRevision, RelayAddress: relay.RelayAddress, TLSServerName: relay.TLSServerName,
			RelayLease: tunnelv1.NativePeerRelayLease{RelayServiceID: relay.RelayLease.RelayServiceID, RelayID: relay.RelayLease.RelayID,
				RelayRunID: relay.RelayLease.RelayRunID, RelayLeaseRevision: relay.RelayLease.RelayLeaseRevision}}
	}
	return p
}

func nativePairSubjectID(s VisitorSubject) string {
	if s.Kind == tunnelv1.VisitorHumanDevice {
		return s.DeviceID
	}
	return s.WorkloadSessionID
}

func nativePeerPairKeyContext(id string) string { return "native-peer-pair/" + id }

// PrepareNativePeerPair creates or retrieves one connector owner's delivery.
// its initial signed create key identifies the owner, independently of the
// enrolled subject. a signed replacement retains that owner's replay fence.
func (d *Database) PrepareNativePeerPair(ctx context.Context, r NativePeerPairRequest, now time.Time) (result NativePeerPair, retErr error) {
	if r.Action != "create" && r.Action != "replace" {
		return result, ErrServiceAccess
	}
	return d.authorizeNativePeerPair(ctx, r, now)
}

// RenewNativePeerPair rechecks current authority for an unexpired pair before
// extending its serving deadline. it never changes the delivery generation.
func (d *Database) RenewNativePeerPair(ctx context.Context, r NativePeerPairRequest, now time.Time) (NativePeerPair, error) {
	if r.Action != "renew" {
		return NativePeerPair{}, ErrServiceAccess
	}
	return d.authorizeNativePeerPair(ctx, r, now)
}

func (d *Database) authorizeNativePeerPair(ctx context.Context, r NativePeerPairRequest, now time.Time) (result NativePeerPair, retErr error) {
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
	defer rollback(ctx, tx, "prepare native peer pair", &retErr)()
	// the source reader owns current service visitor permission, including the
	// session/credential deadline. it takes the team/service admission locks.
	permission, err := d.visitorPermissionForSource(ctx, tx, scope, r.Source, now)
	if err != nil {
		return result, err
	}
	subject, err := visitortoken.NativeSubject(permission.Subject)
	if err != nil || subject != r.Subject {
		return result, ErrServiceAccess
	}
	key, until, err := AuthenticateVisitorSubjectKey(ctx, tx, subject, r.ServiceID, now)
	if err != nil {
		return result, err
	}
	keyDigest, err := visitortoken.KeyDigest(key)
	if err != nil || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, message, r.Signature) {
		return result, ErrServiceAccess
	}
	switch signed := permission.Subject.(type) {
	case visitortoken.Device:
		if signed.KeySHA256 != keyDigest {
			return result, ErrServiceAccess
		}
	case visitortoken.Workload:
		if signed.KeySHA256 != keyDigest {
			return result, ErrServiceAccess
		}
	default:
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
	if run.RunNumber != r.RunNumber || run.PublisherIdentityID != r.PublisherIdentityID || run.State != "ready" || !run.Healthy ||
		run.ClosedAt.Valid || !run.PublisherExpiresAt.Time.After(now) || !run.CertificateExpiresAt.Valid || !run.CertificateExpiresAt.Time.After(now) {
		return result, ErrServiceAccess
	}
	publisherUntil, err := nativePeerPublisherAuthority(ctx, tx, run, now)
	if err != nil {
		return result, err
	}
	deadline := minTime(publisherUntil, minTime(now.Add(5*time.Minute), minTime(permission.ExpiresAt, until)))
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
		err = tx.QueryRow(ctx, `SELECT lease.relay_service_id,lease.relay_id,lease.relay_run_id,lease.relay_lease_revision,service.relay_address,service.tls_server_name
		    FROM control.relay_leases lease JOIN control.relay_services service ON service.relay_service_id=lease.relay_service_id
		    WHERE lease.relay_id=$1 AND lease.relay_run_id=$2 AND lease.relay_lease_revision=$3 AND lease.relay_service_id=$4
		    AND lease.lease_expires_at>$5 AND NOT lease.draining AND service.enabled FOR SHARE OF lease,service`, slot.RelayID.String, slot.RelayRunID.String, slot.RelayLeaseRevision.Int64, slot.RelayServiceID, now).
			Scan(&lease.RelayServiceID, &lease.RelayID, &lease.RelayRunID, &leaseRevision, &address, &serverName)
		if err != nil {
			return result, publisherLookupError(err, ErrServiceAccess)
		}
		if slot.RelayAddress != address || slot.TlsServerName != serverName {
			return NativePeerPair{}, ErrServiceAccess
		}
		lease.RelayLeaseRevision = uint64(leaseRevision)
		// a lease is required now and again at relay claim, but its short
		// renewal interval is not the pair's serving authority deadline.
		result.Relays[i] = NativePeerPairRelay{PublisherConnectionID: slot.PublisherConnectionID, AssignmentRevision: slot.ConnectionAssignmentRevision,
			RelayLease: lease, RelayAddress: address, TLSServerName: serverName}
	}
	if !deadline.After(now) || r.ExpectedRelays != result.Relays {
		return NativePeerPair{}, ErrServiceAccess
	}
	requestDigest := sha256.Sum256(message)
	ownerKey := r.IdempotencyKey
	needsOwnerSlot := true
	var row controlstatedb.ControlNativePeerPair
	// the signed key names the owner for every action. pair IDs never select one.
	row, err = q.GetNativePeerPairForOwner(ctx, controlstatedb.GetNativePeerPairForOwnerParams{
		SubjectKind: string(subject.Kind), SubjectID: nativePairSubjectID(subject), ServiceRunID: run.ID, OwnerKey: ownerKey})
	if r.Action == "replace" && errors.Is(err, pgx.ErrNoRows) {
		return NativePeerPair{}, ErrServiceConflict
	}
	if err == nil {
		var previous [2]NativePeerPairRelay
		if row.ServiceID != r.ServiceID || row.ServiceRunID != r.ServiceRunID || row.RunNumber != r.RunNumber || row.PublisherIdentityID != r.PublisherIdentityID ||
			json.Unmarshal(row.Slots, &previous) != nil || row.SubjectKind != subject.Kind || row.SubjectID != nativePairSubjectID(subject) {
			return NativePeerPair{}, ErrServiceConflict
		}
		if now.Before(row.LastAuthorizedAt.Time) {
			return NativePeerPair{}, ErrServiceConflict
		}
		switch r.Action {
		case "create":
			if row.ParentControlSessionID != parentSession || !row.ExpiresAt.Time.After(now) || previous != result.Relays || !requestAt.Equal(row.LastRequestAt.Time) || !bytes.Equal(row.RequestDigest, requestDigest[:]) {
				return NativePeerPair{}, ErrServiceConflict
			}
			row, err = q.LimitNativePeerPair(ctx, controlstatedb.LimitNativePeerPairParams{ID: row.ID, Now: timestamptz(now), AuthorityExpiresAt: timestamptz(deadline)})
		case "renew":
			if row.ParentControlSessionID != parentSession || !row.ExpiresAt.Time.After(now) || previous != result.Relays || row.ID != r.PreviousPairID ||
				row.DeliveryGeneration != r.PreviousGeneration || row.IdempotencyKey != r.IdempotencyKey {
				return NativePeerPair{}, ErrServiceAccess
			}
			if requestAt.After(row.LastRequestAt.Time) && requestAt.After(row.LastAuthorizedAt.Time) && now.After(row.LastAuthorizedAt.Time) {
				row, err = q.RenewNativePeerPair(ctx, controlstatedb.RenewNativePeerPairParams{ID: row.ID, Now: timestamptz(now), RequestAt: timestamptz(requestAt), RenewalDigest: requestDigest[:], AuthorityExpiresAt: timestamptz(deadline)})
			} else if requestAt.Equal(row.LastRequestAt.Time) && bytes.Equal(row.LastRenewalDigest, requestDigest[:]) {
				row, err = q.LimitNativePeerPair(ctx, controlstatedb.LimitNativePeerPairParams{ID: row.ID, Now: timestamptz(now), AuthorityExpiresAt: timestamptz(deadline)})
			} else {
				return NativePeerPair{}, ErrServiceConflict
			}
		case "replace":
			// a later renewal supersedes this reply proof; it cannot lend its bound.
			if row.ParentControlSessionID == parentSession && row.ExpiresAt.Time.After(now) && previous == result.Relays && row.IdempotencyKey == r.IdempotencyKey && requestAt.Equal(row.LastRequestAt.Time) && bytes.Equal(row.RequestDigest, requestDigest[:]) {
				row, err = q.LimitNativePeerPair(ctx, controlstatedb.LimitNativePeerPairParams{ID: row.ID, Now: timestamptz(now), AuthorityExpiresAt: timestamptz(deadline)})
				break
			}
			if row.ParentControlSessionID != parentSession || row.ID != r.PreviousPairID || row.DeliveryGeneration != r.PreviousGeneration ||
				r.IdempotencyKey != row.IdempotencyKey || requestAt.Before(row.LastRequestAt.Time) {
				return NativePeerPair{}, ErrServiceConflict
			}
			needsOwnerSlot = !row.ExpiresAt.Time.After(now) && !row.ReplayFenceUntil.Time.After(now)
			if count, deleteErr := q.ReplaceNativePeerPair(ctx, row.ID); deleteErr != nil || count != 1 {
				return NativePeerPair{}, errors.Join(ErrServiceConflict, deleteErr)
			}
			err = pgx.ErrNoRows
		}
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return NativePeerPair{}, publisherLookupError(err, ErrServiceAccess)
		}
	}
	if err == nil {
		secret, _, err := d.storageKey.Open(row.StorageKeyID, nativePeerPairKeyContext(row.ID), row.KeyCiphertext)
		if err != nil {
			return NativePeerPair{}, err
		}
		defer clear(secret)
		digest := sha256.Sum256(secret)
		if !bytes.Equal(digest[:], row.KeyDigest) {
			return NativePeerPair{}, ErrServiceAccess
		}
		result.Key = base64.RawURLEncoding.EncodeToString(secret)
	} else if errors.Is(err, pgx.ErrNoRows) {
		if r.Action == "renew" || r.Action == "replace" && row.ID == "" || r.Action == "create" && r.PreviousPairID != "" {
			return NativePeerPair{}, ErrServiceAccess
		}
		if needsOwnerSlot {
			// the run lock serializes fresh owners with replacement and renewal.
			// retained replay fences consume the same bounded owner budget.
			count, err := q.CountNativePeerPairOwners(ctx, controlstatedb.CountNativePeerPairOwnersParams{
				ServiceRunID: run.ID, Now: timestamptz(now), OwnerLimit: maxNativePeerPairOwners})
			if err != nil {
				return NativePeerPair{}, err
			}
			if count >= maxNativePeerPairOwners {
				return NativePeerPair{}, ErrServiceConflict
			}
		}
		id, err := opaqueid.New("npp_")
		if err != nil {
			return NativePeerPair{}, err
		}
		secret := make([]byte, 32)
		if _, err = rand.Read(secret); err != nil {
			return NativePeerPair{}, err
		}
		defer clear(secret)
		digest := sha256.Sum256(secret)
		sealed, err := d.storageKey.Seal(nativePeerPairKeyContext(id), secret)
		if err != nil {
			return NativePeerPair{}, err
		}
		encoded, err := json.Marshal(result.Relays)
		if err != nil {
			return NativePeerPair{}, err
		}
		// a delivery identifier collision must never reuse another pair's
		// header. retry only that named constraint; other conflicts are errors.
		err = pgx.ErrNoRows
		for attempt := 0; attempt < 5; attempt++ {
			var deliveryID [16]byte
			if _, err = rand.Read(deliveryID[:]); err != nil {
				return NativePeerPair{}, err
			}
			if deliveryID == [16]byte{} {
				continue
			}
			row, err = q.InsertNativePeerPair(ctx, controlstatedb.InsertNativePeerPairParams{
				ID: id, ServiceID: r.ServiceID, ServiceRunID: run.ID, RunNumber: run.RunNumber, PublisherIdentityID: run.PublisherIdentityID,
				SubjectKind: string(subject.Kind), SubjectID: nativePairSubjectID(subject), IdempotencyKey: r.IdempotencyKey,
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
				return NativePeerPair{}, ErrServiceConflict
			}
			var conflict *pgconn.PgError
			if errors.As(err, &conflict) && conflict != nil && conflict.Code == "23505" &&
				(conflict.ConstraintName == "native_peer_pairs_owner_key" || conflict.ConstraintName == "native_peer_pairs_request_key") {
				return NativePeerPair{}, errors.Join(ErrServiceConflict, err)
			}
			return NativePeerPair{}, err
		}
		result.Key = base64.RawURLEncoding.EncodeToString(secret)
	} else {
		return NativePeerPair{}, err
	}
	result.ID, result.ServiceID, result.ServiceRunID, result.PublisherIdentityID = row.ID, r.ServiceID, run.ID, run.PublisherIdentityID
	result.Subject, result.RunNumber, result.DeliveryGeneration = subject, run.RunNumber, row.DeliveryGeneration
	if len(row.DeliveryID) != len(result.DeliveryID) {
		return NativePeerPair{}, ErrServiceAccess
	}
	copy(result.DeliveryID[:], row.DeliveryID)
	if result.DeliveryID == [16]byte{} {
		return NativePeerPair{}, ErrServiceAccess
	}
	result.ExpiresAt = row.ExpiresAt.Time
	result.ObservedAt = now
	if row.PublisherPreparedUntil.Valid && row.PublisherPreparedUntil.Time.After(now) {
		result.PublisherPreparedUntil = minTime(row.PublisherPreparedUntil.Time, result.ExpiresAt)
	}
	if err = tx.Commit(ctx); err != nil {
		return NativePeerPair{}, err
	}
	return result, nil
}

// CleanupExpiredNativePeerPairs removes expired delivery material after its
// signed request can no longer be replayed. callers may repeat bounded batches.
func (d *Database) CleanupExpiredNativePeerPairs(ctx context.Context, now time.Time, limit int) (int64, error) {
	if now.IsZero() || limit < 1 || limit > 10000 {
		return 0, ErrServiceAccess
	}
	return controlstatedb.New(d.pool).CleanupExpiredNativePeerPairs(ctx, controlstatedb.CleanupExpiredNativePeerPairsParams{Now: timestamptz(now), BatchSize: int32(limit)})
}
