package controlstate

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
)

func validateEphemeralAllocation(ctx context.Context, queries *controlstatedb.Queries, request CreatePublicURLRequest, now time.Time) (
	controlstatedb.ControlPublicUrlPublishCredential, controlstatedb.GetReadyEphemeralCredentialDomainRow, error,
) {
	credential, err := queries.GetPublicURLPublishCredentialByID(ctx, request.EphemeralCredentialID)
	if errors.Is(err, pgx.ErrNoRows) {
		return credential, controlstatedb.GetReadyEphemeralCredentialDomainRow{}, ErrPublicURLAccess
	}
	if err != nil {
		return credential, controlstatedb.GetReadyEphemeralCredentialDomainRow{}, err
	}
	if credential.Kind != string(PublishCredentialEphemeral) || credential.RevokedAt.Valid || !credential.ExpiresAt.Time.After(now) ||
		credential.TeamID.String != request.TeamID || credential.DomainID.String != request.DomainID ||
		credential.IssuedByIdentityID != request.ActingIdentityID || credential.Namespace.String != request.EphemeralNamespace ||
		credential.CertificateChallengeMethod != "dns-01" ||
		subtle.ConstantTimeCompare(credential.TokenDigest, request.EphemeralTokenDigest[:]) != 1 ||
		request.DNSState != PublicURLDNSPending || request.Purpose != PublicURLPurposeApp {
		return credential, controlstatedb.GetReadyEphemeralCredentialDomainRow{}, ErrPublicURLAccess
	}
	membership, err := queries.GetActivePublishRunMembership(ctx, controlstatedb.GetActivePublishRunMembershipParams{
		TeamID: request.TeamID, IdentityID: credential.IssuedByIdentityID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return credential, controlstatedb.GetReadyEphemeralCredentialDomainRow{}, ErrPublicURLAccess
	}
	if err != nil {
		return credential, controlstatedb.GetReadyEphemeralCredentialDomainRow{}, err
	}
	if membership.ID != credential.MembershipID || membership.PolicyRevision != credential.PolicyRevision ||
		membership.Role != credential.IssuedRole.String {
		return credential, controlstatedb.GetReadyEphemeralCredentialDomainRow{}, ErrPublicURLAccess
	}
	domain, err := queries.GetReadyEphemeralCredentialDomain(ctx, controlstatedb.GetReadyEphemeralCredentialDomainParams{
		DomainID: request.DomainID, TeamID: nullableText(request.TeamID),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return credential, domain, ErrPublicURLAccess
	}
	if err != nil {
		return credential, domain, err
	}
	shared := request.EphemeralNamespace == domain.CanonicalDomain
	if shared && membership.Role != "admin" && membership.Role != "owner" ||
		!shared && !strings.HasSuffix(request.EphemeralNamespace, "."+domain.CanonicalDomain) {
		return credential, domain, ErrPublicURLAccess
	}
	return credential, domain, nil
}

func newEphemeralHostname(namespace string) (string, error) {
	canonical, err := naming.CanonicalizeHostname(namespace)
	if err != nil || canonical != namespace {
		return "", ErrPublicURLInvalid
	}
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return "", err
	}
	label := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(entropy[:]))
	hostname := "eph-" + label + "." + namespace
	if len(hostname) > naming.MaxHostnameBytes {
		return "", ErrPublicURLInvalid
	}
	return hostname, nil
}
