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
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

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
	Relays                                           [2]NativePeerPairRelay
	ExpiresAt                                        time.Time
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

// PrepareNativePeerPair creates or retrieves an exact delivery. only a signed
// replacement of the current pair changes its key and delivery generation.
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
	run, err := q.LockServiceRun(ctx, controlstatedb.LockServiceRunParams{ID: r.ServiceRunID, ServiceID: r.ServiceID})
	if err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	if run.RunNumber != r.RunNumber || run.PublisherIdentityID != r.PublisherIdentityID || run.State != "ready" || !run.Healthy ||
		run.ClosedAt.Valid || !run.PublisherExpiresAt.Time.After(now) || !run.CertificateExpiresAt.Valid || !run.CertificateExpiresAt.Time.After(now) {
		return result, ErrServiceAccess
	}
	if _, err = q.GetServiceRunPublisherIdentity(ctx, controlstatedb.GetServiceRunPublisherIdentityParams{
		ID: run.ID, ServiceID: run.ServiceID, RunNumber: run.RunNumber, PublisherIdentityID: run.PublisherIdentityID,
		PublisherGrantID: run.PublisherGrantID, PublisherKeyID: run.PublisherKeyID, Now: timestamptz(now),
	}); err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	deadline := minTime(now.Add(5*time.Minute), minTime(permission.ExpiresAt, until))
	deadline = minTime(deadline, minTime(run.PublisherExpiresAt.Time, run.CertificateExpiresAt.Time))
	var grantExpiry pgtype.Timestamptz
	if err = tx.QueryRow(ctx, `SELECT expires_at FROM control.publisher_grants WHERE id=$1 AND publisher_identity_id=$2 AND kind='service' AND service_id=$3 AND revoked_at IS NULL`, run.PublisherGrantID, run.PublisherIdentityID, r.ServiceID).Scan(&grantExpiry); err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	if grantExpiry.Valid {
		deadline = minTime(deadline, grantExpiry.Time)
	}
	// a member-owned publisher can lose company eligibility before the run,
	// grant, or relay leases expire. cap the pair at that confirmed deadline.
	var publisherEligibility pgtype.Timestamptz
	if err = tx.QueryRow(ctx, `SELECT CASE WHEN publisher.ownership='member' AND NOT member.personal_account_exception
	    AND (team.company_sign_in_required OR member.identity_connection_id IS NOT NULL) THEN
	    (SELECT eligibility.valid_until FROM control.identity_connections connection
	        JOIN control.company_eligibility eligibility ON eligibility.identity_connection_id=connection.id
	        AND eligibility.team_id=connection.team_id AND eligibility.identity_id=member.identity_id
	        WHERE connection.team_id=team.id AND connection.state='active' AND eligibility.connection_revision=connection.revision
	        AND eligibility.eligible AND (member.identity_connection_id IS NULL OR member.identity_connection_id=connection.id)
	        ORDER BY eligibility.valid_until LIMIT 1) END
	    FROM control.publisher_identities publisher JOIN control.teams team ON team.id=publisher.team_id
	    LEFT JOIN control.team_memberships member ON member.id=publisher.owner_membership_id
	    WHERE publisher.id=$1`, run.PublisherIdentityID).Scan(&publisherEligibility); err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	if publisherEligibility.Valid {
		deadline = minTime(deadline, publisherEligibility.Time)
	}
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
	row, err := q.GetNativePeerPair(ctx, controlstatedb.GetNativePeerPairParams{SubjectKind: string(subject.Kind), SubjectID: nativePairSubjectID(subject), ServiceRunID: run.ID})
	if err == nil {
		var previous [2]NativePeerPairRelay
		if row.ServiceID != r.ServiceID || row.RunNumber != r.RunNumber || row.PublisherIdentityID != r.PublisherIdentityID ||
			json.Unmarshal(row.Slots, &previous) != nil || row.SubjectKind != subject.Kind || row.SubjectID != nativePairSubjectID(subject) {
			return NativePeerPair{}, ErrServiceConflict
		}
		if now.Before(row.LastAuthorizedAt.Time) {
			return NativePeerPair{}, ErrServiceConflict
		}
		switch r.Action {
		case "create":
			if !row.ExpiresAt.Time.After(now) || previous != result.Relays || !bytes.Equal(row.RequestDigest, requestDigest[:]) {
				return NativePeerPair{}, ErrServiceConflict
			}
			row, err = q.LimitNativePeerPair(ctx, controlstatedb.LimitNativePeerPairParams{ID: row.ID, Now: timestamptz(now), AuthorityExpiresAt: timestamptz(deadline)})
		case "renew":
			if !row.ExpiresAt.Time.After(now) || previous != result.Relays || row.ID != r.PreviousPairID ||
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
			if row.ExpiresAt.Time.After(now) && previous == result.Relays && row.IdempotencyKey == r.IdempotencyKey && bytes.Equal(row.RequestDigest, requestDigest[:]) {
				row, err = q.LimitNativePeerPair(ctx, controlstatedb.LimitNativePeerPairParams{ID: row.ID, Now: timestamptz(now), AuthorityExpiresAt: timestamptz(deadline)})
				break
			}
			if row.ID != r.PreviousPairID || row.DeliveryGeneration != r.PreviousGeneration ||
				r.IdempotencyKey == row.IdempotencyKey || requestAt.Before(row.LastRequestAt.Time) {
				return NativePeerPair{}, ErrServiceConflict
			}
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
		row, err = q.InsertNativePeerPair(ctx, controlstatedb.InsertNativePeerPairParams{
			ID: id, ServiceID: r.ServiceID, ServiceRunID: run.ID, RunNumber: run.RunNumber, PublisherIdentityID: run.PublisherIdentityID,
			SubjectKind: string(subject.Kind), SubjectID: nativePairSubjectID(subject), IdempotencyKey: r.IdempotencyKey,
			RequestDigest: requestDigest[:], KeyDigest: digest[:], KeyCiphertext: sealed, StorageKeyID: d.storageKey.CurrentID(),
			Slots: encoded, Now: timestamptz(now), RequestAt: timestamptz(requestAt), ExpiresAt: timestamptz(deadline),
		})
		if err != nil {
			return NativePeerPair{}, err
		}
		result.Key = base64.RawURLEncoding.EncodeToString(secret)
	} else {
		return NativePeerPair{}, err
	}
	result.ID, result.ServiceID, result.ServiceRunID, result.PublisherIdentityID = row.ID, r.ServiceID, run.ID, run.PublisherIdentityID
	result.Subject, result.RunNumber, result.DeliveryGeneration = subject, run.RunNumber, row.DeliveryGeneration
	result.ExpiresAt = row.ExpiresAt.Time
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
