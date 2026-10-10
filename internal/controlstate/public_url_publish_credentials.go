package controlstate

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/certificateidentity"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

const maximumPublishCredentialLifetime = 90 * 24 * time.Hour

type PublishCredentialKind string

const (
	PublishCredentialSavedURL  PublishCredentialKind = "saved_url"
	PublishCredentialEphemeral PublishCredentialKind = "ephemeral"
)

type PublicURLPublishCredential struct {
	ID, PublicURLID, MembershipID, IdentityID, Target string
	Kind                                              PublishCredentialKind
	TeamID, DomainID, Namespace, IssuedRole           string
	PolicyRevision                                    uint64
	CertificatePlan                                   authorization.CertificatePlan
	CreatedAt, ExpiresAt                              time.Time
	RevokedAt                                         *time.Time
}

type CreatePublicURLPublishCredentialRequest struct {
	PublicURLID, TeamID, MembershipID, IdentityID, Target string
	PolicyRevision                                        uint64
	CertificatePlan                                       authorization.CertificatePlan
	Now, ExpiresAt                                        time.Time
}

type PublicURLPublishCredentialSummary struct {
	ID, PublicURLID, PublicURL, TeamID, DomainID, Namespace string
	Kind                                                    PublishCredentialKind
	CreatedAt, ExpiresAt                                    time.Time
	RevokedAt                                               *time.Time
}

type PublicURLPublishCredentialPage struct {
	Credentials []PublicURLPublishCredentialSummary
	NextCursor  string
}

var ErrPublicURLPublishCredential = errors.New("controlstate: public URL publish credential is invalid or expired")

// CreatePublicURLPublishCredential issues a secret only for an enabled, authorized saved URL.
func (d *Database) CreatePublicURLPublishCredential(ctx context.Context, request CreatePublicURLPublishCredentialRequest) (result PublicURLPublishCredential, secret credentials.PublicURLPublishCredential, retErr error) {
	if request.PublicURLID == "" || request.IdentityID == "" || request.MembershipID == "" || request.PolicyRevision == 0 ||
		!request.ExpiresAt.After(request.Now) || request.ExpiresAt.After(request.Now.Add(maximumPublishCredentialLifetime)) {
		return result, "", ErrPublicURLPublishCredential
	}
	plan := request.CertificatePlan
	if plan.CacheKey == "" || plan.Scope == "" || len(plan.Identifiers) == 0 || !plan.ChallengeMethod.Valid() {
		return result, "", ErrPublicURLPublishCredential
	}
	if err := d.requireOpen(); err != nil {
		return result, "", err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return result, "", fmt.Errorf("controlstate: create publish credential: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "create publish credential", &retErr)()
	queries := controlstatedb.New(tx)
	url, err := queries.LockPublicURLForRun(ctx, request.PublicURLID)
	if errors.Is(err, pgx.ErrNoRows) {
		return result, "", ErrPublicURLNotFound
	}
	if err != nil {
		return result, "", err
	}
	if url.LifecycleState != string(PublicURLLifecycleEnabled) || url.Ephemeral ||
		url.TeamID != request.TeamID || url.Target != request.Target || url.Purpose != string(PublicURLPurposeApp) ||
		!certificateidentity.Covers(plan.Identifiers, url.CanonicalHostname) {
		return result, "", ErrPublicURLPublishCredential
	}
	membership, err := queries.GetActivePublishRunMembership(ctx, controlstatedb.GetActivePublishRunMembershipParams{
		TeamID: request.TeamID, IdentityID: request.IdentityID,
	})
	if err != nil || membership.ID != request.MembershipID || membership.PolicyRevision != int64(request.PolicyRevision) ||
		url.PublicURLScope == "member" && (!url.MembershipID.Valid || url.MembershipID.String != membership.ID) ||
		url.PublicURLScope == "shared" && membership.Role != "admin" && membership.Role != "owner" {
		return result, "", ErrPublicURLPublishCredential
	}
	secret, tokenID, digest, err := credentials.NewPublicURLPublishCredential()
	if err != nil {
		return result, "", err
	}
	id, err := opaqueid.New(opaqueid.PublicURLPublishCredentialPrefix)
	if err != nil {
		return result, "", err
	}
	row, err := queries.InsertPublicURLPublishCredential(ctx, controlstatedb.InsertPublicURLPublishCredentialParams{
		ID: id, PublicURLID: nullableText(request.PublicURLID), TokenID: tokenID.String(), TokenDigest: digest[:],
		IssuedByIdentityID: request.IdentityID, MembershipID: request.MembershipID,
		PolicyRevision: int64(request.PolicyRevision), Target: request.Target,
		CertificateCacheKey: plan.CacheKey, CertificateScope: plan.Scope,
		CertificateIdentifiers: plan.Identifiers, CertificateChallengeMethod: string(plan.ChallengeMethod),
		CreatedAt: timestamptz(request.Now), ExpiresAt: timestamptz(request.ExpiresAt),
	})
	if err != nil {
		return result, "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return result, "", err
	}
	return publicURLPublishCredentialFromRow(row), secret, nil
}

// AuthenticatePublicURLPublishCredential accepts only a valid scoped credential.
func (d *Database) AuthenticatePublicURLPublishCredential(ctx context.Context, token credentials.PublicURLPublishCredential, now time.Time) (PublicURLPublishCredential, []byte, error) {
	id, hash, retrySecret, err := credentials.ParsePublicURLPublishCredential(token)
	if err != nil {
		return PublicURLPublishCredential{}, nil, ErrPublicURLPublishCredential
	}
	if err := d.requireOpen(); err != nil {
		return PublicURLPublishCredential{}, nil, err
	}
	row, err := controlstatedb.New(d.pool).GetPublicURLPublishCredentialByTokenID(ctx, id.String())
	if errors.Is(err, pgx.ErrNoRows) {
		return PublicURLPublishCredential{}, nil, ErrPublicURLPublishCredential
	}
	if err != nil {
		return PublicURLPublishCredential{}, nil, err
	}
	if row.Kind != string(PublishCredentialSavedURL) || subtle.ConstantTimeCompare(row.TokenDigest, hash[:]) != 1 || row.RevokedAt.Valid || !row.ExpiresAt.Time.After(now) {
		return PublicURLPublishCredential{}, nil, ErrPublicURLPublishCredential
	}
	return publicURLPublishCredentialFromRow(row), retrySecret, nil
}

// ValidatePublicURLPublishCredential rechecks current URL and team membership state.
func (d *Database) ValidatePublicURLPublishCredential(ctx context.Context, credential PublicURLPublishCredential, route PublicURL) error {
	if credential.Kind != PublishCredentialSavedURL || credential.PublicURLID != route.ID || credential.Target != route.Target || route.LifecycleState != PublicURLLifecycleEnabled ||
		route.Ephemeral || route.Purpose != PublicURLPurposeApp {
		return ErrPublicURLPublishCredential
	}
	membership, err := controlstatedb.New(d.pool).GetActivePublishRunMembership(ctx, controlstatedb.GetActivePublishRunMembershipParams{
		TeamID: route.TeamID, IdentityID: credential.IdentityID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrPublicURLPublishCredential
	}
	if err != nil {
		return err
	}
	if membership.ID != credential.MembershipID || membership.PolicyRevision != int64(credential.PolicyRevision) ||
		route.PublicURLScope == PublicURLScopeMember && route.MembershipID != membership.ID ||
		route.PublicURLScope == PublicURLScopeShared && membership.Role != "admin" && membership.Role != "owner" {
		return ErrPublicURLPublishCredential
	}
	return nil
}

func (d *Database) ListPublicURLPublishCredentials(ctx context.Context, publicURLID string) ([]PublicURLPublishCredential, error) {
	rows, err := controlstatedb.New(d.pool).ListPublicURLPublishCredentials(ctx, nullableText(publicURLID))
	if err != nil {
		return nil, err
	}
	result := make([]PublicURLPublishCredential, len(rows))
	for index, row := range rows {
		result[index] = publicURLPublishCredentialFromRow(row)
	}
	return result, nil
}

func (d *Database) ListTeamPublicURLPublishCredentials(ctx context.Context, teamID, cursor string) (PublicURLPublishCredentialPage, error) {
	if !validStateText(teamID) || cursor != "" && !opaqueid.Valid(cursor, opaqueid.PublicURLPublishCredentialPrefix) {
		return PublicURLPublishCredentialPage{}, ErrPublicURLInvalid
	}
	if err := d.requireOpen(); err != nil {
		return PublicURLPublishCredentialPage{}, err
	}
	rows, err := controlstatedb.New(d.pool).ListTeamPublicURLPublishCredentials(ctx, controlstatedb.ListTeamPublicURLPublishCredentialsParams{
		TeamID: teamID, Cursor: nullableText(cursor),
	})
	if err != nil {
		return PublicURLPublishCredentialPage{}, err
	}
	page := PublicURLPublishCredentialPage{Credentials: make([]PublicURLPublishCredentialSummary, 0, min(len(rows), 100))}
	for _, row := range rows[:min(len(rows), 100)] {
		entry := PublicURLPublishCredentialSummary{
			ID: row.ID, PublicURLID: row.PublicURLID, Kind: PublishCredentialKind(row.Kind),
			TeamID: row.TeamID, DomainID: row.DomainID, Namespace: row.Namespace,
			CreatedAt: row.CreatedAt.Time, ExpiresAt: row.ExpiresAt.Time,
		}
		if row.CanonicalHostname != "" {
			entry.PublicURL = "https://" + row.CanonicalHostname
		}
		if row.RevokedAt.Valid {
			entry.RevokedAt = &row.RevokedAt.Time
		}
		page.Credentials = append(page.Credentials, entry)
	}
	if len(rows) > 100 {
		page.NextCursor = page.Credentials[len(page.Credentials)-1].ID
	}
	return page, nil
}

func (d *Database) PublicURLPublishCredentialByID(ctx context.Context, id string) (PublicURLPublishCredential, error) {
	if !opaqueid.Valid(id, opaqueid.PublicURLPublishCredentialPrefix) {
		return PublicURLPublishCredential{}, ErrPublicURLNotFound
	}
	if err := d.requireOpen(); err != nil {
		return PublicURLPublishCredential{}, err
	}
	row, err := controlstatedb.New(d.pool).GetPublicURLPublishCredentialByID(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return PublicURLPublishCredential{}, ErrPublicURLNotFound
	}
	if err != nil {
		return PublicURLPublishCredential{}, err
	}
	return publicURLPublishCredentialFromRow(row), nil
}

func (d *Database) RevokePublicURLPublishCredential(ctx context.Context, publicURLID, credentialID string, now time.Time) (PublicURLPublishCredential, error) {
	row, err := controlstatedb.New(d.pool).RevokePublicURLPublishCredential(ctx, controlstatedb.RevokePublicURLPublishCredentialParams{
		PublicURLID: nullableText(publicURLID), ID: credentialID, RevokedAt: timestamptz(now),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return PublicURLPublishCredential{}, ErrPublicURLNotFound
	}
	if err != nil {
		return PublicURLPublishCredential{}, err
	}
	return publicURLPublishCredentialFromRow(row), nil
}

func publicURLPublishCredentialFromRow(row controlstatedb.ControlPublicUrlPublishCredential) PublicURLPublishCredential {
	result := PublicURLPublishCredential{
		ID: row.ID, PublicURLID: row.PublicURLID.String, MembershipID: row.MembershipID, Kind: PublishCredentialKind(row.Kind),
		TeamID: row.TeamID.String, DomainID: row.DomainID.String, Namespace: row.Namespace.String, IssuedRole: row.IssuedRole.String,
		IdentityID: row.IssuedByIdentityID, Target: row.Target, PolicyRevision: uint64(row.PolicyRevision),
		CertificatePlan: authorization.CertificatePlan{
			CacheKey: row.CertificateCacheKey, Scope: row.CertificateScope,
			Identifiers: row.CertificateIdentifiers, ChallengeMethod: certificateidentity.ChallengeMethod(row.CertificateChallengeMethod),
		}, CreatedAt: row.CreatedAt.Time, ExpiresAt: row.ExpiresAt.Time,
	}
	if row.RevokedAt.Valid {
		result.RevokedAt = &row.RevokedAt.Time
	}
	return result
}
