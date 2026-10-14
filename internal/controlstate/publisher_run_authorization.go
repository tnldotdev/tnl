package controlstate

import (
	"context"
	"crypto/ed25519"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/certificateidentity"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
)

// PublisherKeyForAccess returns the registered signing key for an active token.
func (d *Database) PublisherKeyForAccess(ctx context.Context, identity PublisherIdentity) (ed25519.PublicKey, error) {
	key, err := controlstatedb.New(d.pool).GetPublisherIdentityKey(ctx, controlstatedb.GetPublisherIdentityKeyParams{
		KeyID: identity.KeyID, PublisherIdentityID: identity.ID,
	})
	if errors.Is(err, pgx.ErrNoRows) || err == nil && (key.IdentityRevokedAt.Valid || key.RetiredAt.Valid) {
		return nil, ErrPublisherIdentity
	}
	if err != nil {
		return nil, err
	}
	return key.PublicKey, nil
}

// PublisherRunPlan derives the certificate boundary without depending on the
// enrolling person's current membership.
func (d *Database) PublisherRunPlan(ctx context.Context, publisher PublisherIdentity, route PublicURL, dnsAutomation bool) (authorization.CertificatePlan, error) {
	if route.TeamID != publisher.Scope.TeamID || route.LifecycleState != PublicURLLifecycleEnabled ||
		publisher.GuestID != "" && (route.Purpose != PublicURLPurposeDemo || !route.Ephemeral || route.MembershipID == "") ||
		publisher.Scope.Kind == "saved_url" && (route.ID != publisher.Scope.PublicURLID || route.Ephemeral) ||
		publisher.Scope.Kind == "namespace" && (!route.Ephemeral || route.DomainID != publisher.Scope.DomainID) ||
		publisher.Scope.Kind != "saved_url" && publisher.Scope.Kind != "namespace" {
		return authorization.CertificatePlan{}, ErrPublisherIdentity
	}
	domain, err := controlstatedb.New(d.pool).GetReadyPublisherDomain(ctx, controlstatedb.GetReadyPublisherDomainParams{
		DomainID: route.DomainID, TeamID: text(route.TeamID),
	})
	if err != nil || domain.ID != route.DomainID {
		return authorization.CertificatePlan{}, ErrPublisherIdentity
	}
	namespace, err := controlstatedb.New(d.pool).GetPublisherRunNamespace(ctx, controlstatedb.GetPublisherRunNamespaceParams{
		PublicURLID: route.ID, TeamID: route.TeamID,
	})
	if err != nil || publisher.Scope.Kind == "namespace" && namespace != publisher.Scope.Namespace {
		return authorization.CertificatePlan{}, ErrPublisherIdentity
	}
	plan := authorization.PublicURLCertificatePlan(route.CanonicalHostname, namespace,
		domain.Kind == "custom" && route.PublicURLScope == PublicURLScopeShared, dnsAutomation)
	if plan == nil || !certificateidentity.Covers(plan.Identifiers, route.CanonicalHostname) ||
		publisher.Scope.Kind == "namespace" && publisher.GuestID == "" && plan.ChallengeMethod != certificateidentity.ChallengeDNS01 {
		return authorization.CertificatePlan{}, ErrPublisherIdentity
	}
	return *plan, nil
}

// PublisherMayStartRun checks ownership before reading a URL across teams.
func (d *Database) PublisherMayStartRun(ctx context.Context, identity PublisherIdentity, publicURLID string) (bool, error) {
	if identity.Scope.Kind == "saved_url" {
		return identity.Scope.PublicURLID == publicURLID, nil
	}
	if identity.GuestID != "" {
		return d.GuestOwnsPublicURL(ctx, identity.GuestID, publicURLID)
	}
	if identity.Scope.Kind != "namespace" {
		return false, nil
	}
	allocation, err := controlstatedb.New(d.pool).GetPublisherNamespaceAllocation(ctx, publicURLID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return allocation.PublisherIdentityID == identity.ID && allocation.PublisherGrantID == identity.GrantID, nil
}
