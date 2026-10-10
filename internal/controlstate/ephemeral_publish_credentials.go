package controlstate

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/certificateidentity"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

type CreateEphemeralCredentialRequest struct {
	TeamID, DomainID, Namespace, MembershipID, IdentityID, Role string
	PolicyRevision                                              uint64
	CertificatePlan                                             authorization.CertificatePlan
	Now, ExpiresAt                                              time.Time
}

var ErrEphemeralCredential = errors.New("controlstate: ad-hoc public URL credential is invalid or expired")

func (d *Database) CreateEphemeralCredential(ctx context.Context, request CreateEphemeralCredentialRequest) (result PublicURLPublishCredential, secret credentials.EphemeralCredential, retErr error) {
	plan := request.CertificatePlan
	canonical, err := naming.CanonicalizeHostname(request.Namespace)
	if request.TeamID == "" || request.DomainID == "" || request.IdentityID == "" || request.MembershipID == "" ||
		request.PolicyRevision == 0 || canonical != request.Namespace || err != nil ||
		!request.ExpiresAt.After(request.Now) || request.ExpiresAt.After(request.Now.Add(maximumPublishCredentialLifetime)) ||
		plan.CacheKey != request.Namespace || plan.Scope != request.Namespace || plan.ChallengeMethod != certificateidentity.ChallengeDNS01 ||
		!slices.Contains(plan.Identifiers, "*."+request.Namespace) {
		return result, "", ErrEphemeralCredential
	}
	for _, identifier := range plan.Identifiers {
		if identifier != "*."+request.Namespace && identifier != request.Namespace {
			return result, "", ErrEphemeralCredential
		}
	}
	if err := d.requireOpen(); err != nil {
		return result, "", err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return result, "", fmt.Errorf("controlstate: create ad-hoc credential: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "create ad-hoc credential", &retErr)()
	queries := controlstatedb.New(tx)
	membership, err := queries.GetActivePublishRunMembership(ctx, controlstatedb.GetActivePublishRunMembershipParams{
		TeamID: request.TeamID, IdentityID: request.IdentityID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return result, "", ErrEphemeralCredential
	}
	if err != nil {
		return result, "", err
	}
	if membership.ID != request.MembershipID || membership.PolicyRevision != int64(request.PolicyRevision) || membership.Role != request.Role {
		return result, "", ErrEphemeralCredential
	}
	domain, err := queries.GetReadyEphemeralCredentialDomain(ctx, controlstatedb.GetReadyEphemeralCredentialDomainParams{
		DomainID: request.DomainID, TeamID: nullableText(request.TeamID),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return result, "", ErrEphemeralCredential
	}
	if err != nil {
		return result, "", err
	}
	if request.Namespace != domain.CanonicalDomain && !strings.HasSuffix(request.Namespace, "."+domain.CanonicalDomain) ||
		request.Namespace == domain.CanonicalDomain && request.Role != "admin" && request.Role != "owner" {
		return result, "", ErrEphemeralCredential
	}
	secret, tokenID, digest, err := credentials.NewEphemeralCredential()
	if err != nil {
		return result, "", err
	}
	id, err := opaqueid.New(opaqueid.PublicURLPublishCredentialPrefix)
	if err != nil {
		return result, "", err
	}
	row, err := queries.InsertEphemeralPublishCredential(ctx, controlstatedb.InsertEphemeralPublishCredentialParams{
		ID: id, TokenID: tokenID.String(), TokenDigest: digest[:], IssuedByIdentityID: request.IdentityID,
		MembershipID: request.MembershipID, PolicyRevision: int64(request.PolicyRevision),
		TeamID: nullableText(request.TeamID), DomainID: nullableText(request.DomainID), Namespace: nullableText(request.Namespace),
		IssuedRole: nullableText(request.Role), CertificateCacheKey: plan.CacheKey, CertificateScope: plan.Scope,
		CertificateIdentifiers: plan.Identifiers, CreatedAt: timestamptz(request.Now), ExpiresAt: timestamptz(request.ExpiresAt),
	})
	if err != nil {
		return result, "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return result, "", err
	}
	return publicURLPublishCredentialFromRow(row), secret, nil
}

func (d *Database) AuthenticateEphemeralCredential(ctx context.Context, token credentials.EphemeralCredential, now time.Time) (PublicURLPublishCredential, error) {
	id, hash, _, err := credentials.ParseEphemeralCredential(token)
	if err != nil {
		return PublicURLPublishCredential{}, ErrEphemeralCredential
	}
	if err := d.requireOpen(); err != nil {
		return PublicURLPublishCredential{}, err
	}
	row, err := controlstatedb.New(d.pool).GetPublicURLPublishCredentialByTokenID(ctx, id.String())
	if errors.Is(err, pgx.ErrNoRows) {
		return PublicURLPublishCredential{}, ErrEphemeralCredential
	}
	if err != nil {
		return PublicURLPublishCredential{}, err
	}
	if row.Kind != string(PublishCredentialEphemeral) || subtle.ConstantTimeCompare(row.TokenDigest, hash[:]) != 1 ||
		row.RevokedAt.Valid || !row.ExpiresAt.Time.After(now) {
		return PublicURLPublishCredential{}, ErrEphemeralCredential
	}
	return publicURLPublishCredentialFromRow(row), nil
}

func (d *Database) RevokeEphemeralCredential(ctx context.Context, teamID, credentialID string, now time.Time) (PublicURLPublishCredential, error) {
	row, err := controlstatedb.New(d.pool).RevokeEphemeralPublishCredential(ctx, controlstatedb.RevokeEphemeralPublishCredentialParams{
		ID: credentialID, TeamID: nullableText(teamID), RevokedAt: timestamptz(now),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return PublicURLPublishCredential{}, ErrPublicURLNotFound
	}
	if err != nil {
		return PublicURLPublishCredential{}, err
	}
	return publicURLPublishCredentialFromRow(row), nil
}
