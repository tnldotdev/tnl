package controlstate

import (
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
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/opaqueid"
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
	if err != nil || email == "" || !opaqueid.Valid(serviceID, opaqueid.PrivateServicePrefix) || len(key) < 1 || len(key) > 128 ||
		!expires.After(now) || expires.After(now.Add(maximumShareLifetime)) {
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
	requestDigest := sha256.Sum256([]byte(serviceID + "\x00" + email + "\x00" + expires.UTC().Format(time.RFC3339Nano)))
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "invite private service visitor", &retErr)()
	service, err := lockManagedPrivateService(ctx, tx, serviceID, actorID)
	if err != nil {
		return result, err
	}
	row, err := controlstatedb.New(tx).InsertPrivateServiceInvitation(ctx, controlstatedb.InsertPrivateServiceInvitationParams{
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
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	result = privateInvitationRecord(row)
	result.Secret = secret
	return result, nil
}

func (d *Database) ListPrivateServiceInvitations(ctx context.Context, serviceID, actorID string) (result []PrivateServiceInvitation, retErr error) {
	if !opaqueid.Valid(serviceID, opaqueid.PrivateServicePrefix) {
		return nil, ErrPrivateServiceAccess
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(ctx, tx, "list private service invitations", &retErr)()
	if _, err = lockManagedPrivateService(ctx, tx, serviceID, actorID); err != nil {
		return nil, err
	}
	rows, err := controlstatedb.New(tx).ListPrivateServiceInvitations(ctx, serviceID)
	if err != nil {
		return nil, err
	}
	result = make([]PrivateServiceInvitation, 0, len(rows))
	for _, row := range rows {
		result = append(result, privateInvitationRecord(row))
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return result, nil
}

func (d *Database) AcceptPrivateServiceInvitation(ctx context.Context, identityID, secret string, now time.Time) (result PrivateServiceGrant, retErr error) {
	id, encoded, found := strings.Cut(secret, ".")
	if !found || !opaqueid.Valid(id, opaqueid.PrivateServiceInvitationPrefix) || len(encoded) != 43 {
		return result, ErrPrivateServiceAccess
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) != 32 {
		return result, ErrPrivateServiceAccess
	}
	digest := sha256.Sum256(raw)
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "accept private service invitation", &retErr)()
	var serviceID string
	if err = tx.QueryRow(ctx, `SELECT private_service_id FROM control.private_service_invitations WHERE id=$1`, id).Scan(&serviceID); errors.Is(err, pgx.ErrNoRows) {
		return result, ErrPrivateServiceAccess
	} else if err != nil {
		return result, err
	}
	if err = lockPrivateAdmission(ctx, tx, serviceID); err != nil {
		return result, err
	}
	var stored []byte
	var email string
	if err = tx.QueryRow(ctx, `SELECT token_digest, normalized_email FROM control.private_service_invitations
		WHERE id=$1 AND private_service_id=$2 AND revoked_at IS NULL AND accepted_at IS NULL AND expires_at > $3 FOR UPDATE`, id, serviceID, now).Scan(&stored, &email); errors.Is(err, pgx.ErrNoRows) {
		return result, ErrPrivateServiceAccess
	} else if err != nil {
		return result, err
	}
	if subtle.ConstantTimeCompare(stored, digest[:]) != 1 {
		return result, ErrPrivateServiceAccess
	}
	identity, err := controlstatedb.New(tx).LockVisitorIdentity(ctx, identityID)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, ErrPrivateServiceAccess
	}
	if err != nil {
		return result, err
	}
	if !identity.EmailVerified || identity.NormalizedEmail.String != email {
		return result, ErrPrivateServiceAccess
	}
	q := controlstatedb.New(tx)
	invitation, err := q.AcceptPrivateServiceInvitation(ctx, controlstatedb.AcceptPrivateServiceInvitationParams{IdentityID: text(identityID), TokenDigest: digest[:], Now: timestamptz(now)})
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
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	return privateGrantRecord(grant), nil
}

func (d *Database) RevokePrivateServiceInvitation(ctx context.Context, serviceID, actorID, invitationID string, now time.Time) (retErr error) {
	if !opaqueid.Valid(invitationID, opaqueid.PrivateServiceInvitationPrefix) {
		return ErrPrivateServiceAccess
	}
	tx, err := d.pool.Begin(ctx)
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
	if _, err = q.RevokePrivateServiceInvitationGrant(ctx, controlstatedb.RevokePrivateServiceInvitationGrantParams{
		InvitationID: text(invitationID), PrivateServiceID: serviceID, Now: timestamptz(now),
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
