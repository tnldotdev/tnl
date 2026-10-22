package controlstate

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

type PrivateServiceInvitation struct {
	ID, PrivateServiceID, Email, Secret string
	ExpiresAt                           time.Time
	AcceptedAt, RevokedAt               *time.Time
}

func privateInvitationRecord(row controlstatedb.ControlPrivateServiceInvitation) PrivateServiceInvitation {
	return PrivateServiceInvitation{ID: row.ID, PrivateServiceID: row.PrivateServiceID,
		Email: row.NormalizedEmail, ExpiresAt: row.ExpiresAt.Time,
		AcceptedAt: optionalTime(row.AcceptedAt), RevokedAt: optionalTime(row.RevokedAt)}
}

func (d *Database) InvitePrivateServiceVisitor(ctx context.Context, serviceID, actorID, key, email string, expires, now time.Time) (result PrivateServiceInvitation, retErr error) {
	email, err := normalizeEmailRestriction(email)
	if err != nil || email == "" || !opaqueid.Valid(serviceID, opaqueid.PrivateServicePrefix) || len(key) < 1 || len(key) > 128 {
		return result, ErrPrivateServiceAccess
	}
	requestDigest := sha256.Sum256([]byte(serviceID + "\x00" + email + "\x00" + expires.UTC().Format(time.RFC3339Nano)))
	tx, err := d.beginServiceAccess(ctx, pgx.TxOptions{})
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "invite private service visitor", &retErr)()
	service, err := lockManagedPrivateService(ctx, tx, serviceID, actorID)
	if err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	existing, err := q.FindPrivateServiceInvitationRequest(ctx, controlstatedb.FindPrivateServiceInvitationRequestParams{CreatedByIdentityID: actorID, IdempotencyKey: key})
	if err == nil {
		if existing.PrivateServiceID != serviceID || !bytes.Equal(existing.RequestDigest, requestDigest[:]) {
			return result, ErrPrivateServiceConflict
		}
		// only the digest is stored. an exact retry recovers the owned ID and
		// current state so the manager can explicitly revoke and reissue.
		return privateInvitationRecord(existing), tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return result, err
	}
	if !expires.After(now) || expires.After(now.Add(maximumShareLifetime)) {
		return result, ErrPrivateServiceAccess
	}
	id, err := opaqueid.New(opaqueid.PrivateServiceInvitationPrefix)
	if err != nil {
		return result, err
	}
	var secretBytes [32]byte
	if _, err = rand.Read(secretBytes[:]); err != nil {
		return result, err
	}
	secret := id + "." + base64.RawURLEncoding.EncodeToString(secretBytes[:])
	digest := sha256.Sum256(secretBytes[:])
	row, err := q.InsertPrivateServiceInvitation(ctx, controlstatedb.InsertPrivateServiceInvitationParams{
		ID: id, PrivateServiceID: serviceID, TeamID: service.TeamID, NormalizedEmail: email,
		TokenDigest: digest[:], CreatedByIdentityID: actorID, IdempotencyKey: key,
		RequestDigest: requestDigest[:], Now: timestamptz(now), ExpiresAt: timestamptz(expires),
	})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return result, ErrPrivateServiceConflict
	}
	if err != nil {
		return result, err
	}
	if err = auditPrivateMutation(ctx, tx, serviceID, actorID, "invitation.create", row.ID, now); err != nil {
		return result, err
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	result = privateInvitationRecord(row)
	result.Secret = secret
	return result, nil
}

func (d *Database) ListPrivateServiceInvitations(ctx context.Context, serviceID, actorID, after string) (result []PrivateServiceInvitation, next string, retErr error) {
	if !opaqueid.Valid(serviceID, opaqueid.PrivateServicePrefix) || after != "" && !opaqueid.Valid(after, opaqueid.PrivateServiceInvitationPrefix) {
		return nil, "", ErrPrivateServiceAccess
	}
	tx, err := d.beginServiceAccess(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, "", err
	}
	defer rollback(ctx, tx, "list private service invitations", &retErr)()
	if _, err = lockManagedPrivateService(ctx, tx, serviceID, actorID); err != nil {
		return nil, "", err
	}
	rows, err := controlstatedb.New(tx).ListPrivateServiceInvitations(ctx, controlstatedb.ListPrivateServiceInvitationsParams{PrivateServiceID: serviceID, AfterID: after})
	if err != nil {
		return nil, "", err
	}
	if len(rows) > 100 {
		next, rows = rows[99].ID, rows[:100]
	}
	result = make([]PrivateServiceInvitation, 0, len(rows))
	for _, row := range rows {
		result = append(result, privateInvitationRecord(row))
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, "", err
	}
	return result, next, nil
}

func (d *Database) AcceptPrivateServiceInvitation(ctx context.Context, identityID, secret string, now time.Time) (result PrivateServiceGrant, retErr error) {
	tx, err := d.beginServiceAccess(ctx, pgx.TxOptions{})
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "accept private service invitation", &retErr)()
	invitation, err := pendingPrivateInvitation(ctx, tx, identityID, secret, now)
	if err != nil {
		return result, err
	}
	serviceID, id, digest := invitation.PrivateServiceID, invitation.ID, invitation.TokenDigest
	q := controlstatedb.New(tx)
	verifiedEmail := ""
	if proof, signed := serviceActor(ctx); signed && proof.identity.EmailVerified {
		verifiedEmail = proof.identity.NormalizedEmail
	}
	invitation, err = q.AcceptPrivateServiceInvitation(ctx, controlstatedb.AcceptPrivateServiceInvitationParams{ID: id, PrivateServiceID: serviceID, IdentityID: text(identityID), TokenDigest: digest, VerifiedActorEmail: nullableText(verifiedEmail), Now: timestamptz(now)})
	if errors.Is(err, pgx.ErrNoRows) {
		return result, ErrPrivateServiceAccess
	}
	if err != nil {
		return result, err
	}
	grantID, err := opaqueid.New(opaqueid.PrivateServiceGrantPrefix)
	if err != nil {
		return result, err
	}
	grant, err := q.InsertPrivateServiceGrant(ctx, controlstatedb.InsertPrivateServiceGrantParams{
		ID: grantID, PrivateServiceID: serviceID, TeamID: invitation.TeamID, Kind: "identity",
		IdentityID: text(identityID), InvitationID: text(id), CreatedByIdentityID: invitation.CreatedByIdentityID,
		IdempotencyKey: "invitation/" + id, RequestDigest: invitation.RequestDigest,
		Now: timestamptz(now), ExpiresAt: invitation.ExpiresAt,
	})
	if err != nil {
		return result, err
	}
	if err = auditPrivateMutation(ctx, tx, serviceID, identityID, "invitation.accept", id, now); err != nil {
		return result, err
	}
	if err = auditPrivateMutation(ctx, tx, serviceID, identityID, "grant.create", grant.ID, now); err != nil {
		return result, err
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	return privateGrantRecord(grant), nil
}

// pendingPrivateInvitation is shared by preview and acceptance. every rejected
// secret or recipient gets the same denial, without a service projection.
func pendingPrivateInvitation(ctx context.Context, tx pgx.Tx, identityID, secret string, now time.Time) (result controlstatedb.ControlPrivateServiceInvitation, retErr error) {
	id, encoded, found := strings.Cut(secret, ".")
	if !found || !opaqueid.Valid(id, opaqueid.PrivateServiceInvitationPrefix) || len(encoded) != 43 {
		return result, ErrPrivateServiceAccess
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) != 32 {
		return result, ErrPrivateServiceAccess
	}
	digest := sha256.Sum256(raw)
	var serviceID string
	if err = tx.QueryRow(ctx, `SELECT private_service_id FROM control.private_service_invitations WHERE id=$1`, id).Scan(&serviceID); errors.Is(err, pgx.ErrNoRows) {
		return result, ErrPrivateServiceAccess
	} else if err != nil {
		return result, err
	}
	if err = lockPrivateAdmission(ctx, tx, serviceID); err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	result, err = q.LockPendingPrivateServiceInvitation(ctx, controlstatedb.LockPendingPrivateServiceInvitationParams{ID: id, PrivateServiceID: serviceID, Now: timestamptz(now)})
	if err != nil {
		return result, publisherLookupError(err, ErrPrivateServiceAccess)
	}
	if subtle.ConstantTimeCompare(result.TokenDigest, digest[:]) != 1 {
		return result, ErrPrivateServiceAccess
	}
	if _, signed := serviceActor(ctx); signed {
		i, err := consumeServiceActor(ctx, q, identityID, now)
		if err != nil {
			return result, err
		}
		if !i.EmailVerified || i.NormalizedEmail == "" {
			return result, ErrServiceVerifiedEmailRequired
		}
		if i.NormalizedEmail != result.NormalizedEmail {
			return result, ErrPrivateServiceAccess
		}
		if err = serviceActorRecipientSource(ctx, q, result.TeamID, identityID, i, now); err != nil {
			return result, err
		}
		return result, nil
	}
	identity, err := q.LockVisitorIdentity(ctx, identityID)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, ErrPrivateServiceAccess
	}
	if err != nil {
		return result, err
	}
	if !identity.EmailVerified || identity.NormalizedEmail.String != result.NormalizedEmail {
		return result, ErrPrivateServiceAccess
	}
	return result, nil
}

func (d *Database) PreviewPrivateServiceInvitation(ctx context.Context, actor, secret string, now time.Time) (result PrivateServiceInvitationPreview, retErr error) {
	tx, err := d.beginServiceAccess(ctx, pgx.TxOptions{})
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "preview private service invitation", &retErr)()
	invitation, err := pendingPrivateInvitation(ctx, tx, actor, secret, now)
	if err != nil {
		return result, err
	}
	service, err := controlstatedb.New(tx).GetPrivateService(ctx, invitation.PrivateServiceID)
	if err != nil {
		return result, publisherLookupError(err, ErrPrivateServiceAccess)
	}
	result = PrivateServiceInvitationPreview{PrivateServiceID: service.ID, TeamID: service.TeamID, Name: service.Name, Protocol: service.Protocol, ExpiresAt: invitation.ExpiresAt.Time}
	return result, tx.Commit(ctx)
}

type PrivateServiceInvitationPreview struct {
	PrivateServiceID string    `json:"private_service_id"`
	TeamID           string    `json:"team_id"`
	Name             string    `json:"name"`
	Protocol         string    `json:"protocol"`
	ExpiresAt        time.Time `json:"expires_at"`
}

func (d *Database) RevokePrivateServiceInvitation(ctx context.Context, serviceID, actorID, invitationID string, now time.Time) (retErr error) {
	if !opaqueid.Valid(invitationID, opaqueid.PrivateServiceInvitationPrefix) {
		return ErrPrivateServiceAccess
	}
	tx, err := d.beginServiceAccess(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "revoke private service invitation", &retErr)()
	if _, err = lockManagedPrivateService(ctx, tx, serviceID, actorID); err != nil {
		return err
	}
	q := controlstatedb.New(tx)
	count, err := q.RevokePrivateServiceInvitation(ctx, controlstatedb.RevokePrivateServiceInvitationParams{
		ID: invitationID, PrivateServiceID: serviceID, Now: timestamptz(now),
	})
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrPrivateServiceAccess
	}
	revoked, err := q.RevokePrivateServiceInvitationGrant(ctx, controlstatedb.RevokePrivateServiceInvitationGrantParams{
		InvitationID: text(invitationID), PrivateServiceID: serviceID, Now: timestamptz(now),
	})
	if err != nil {
		return err
	}
	if revoked > 0 {
		if err = auditPrivateMutation(ctx, tx, serviceID, actorID, "grant.revoke", "invitation/"+invitationID, now); err != nil {
			return err
		}
	}
	if err = auditPrivateMutation(ctx, tx, serviceID, actorID, "invitation.revoke", invitationID, now); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
