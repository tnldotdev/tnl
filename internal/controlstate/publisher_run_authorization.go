package controlstate

import (
	"context"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/certificateidentity"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
)

// PublisherRunPlan derives the same certificate boundary for an enrolled
// publisher without relying on the enrolling person's current membership.
func (d *Database) PublisherRunPlan(ctx context.Context, publisher PublisherIdentity, route PublicURL, dnsAutomation bool) (authorization.CertificatePlan, error) {
	if err := ctx.Err(); err != nil {
		return authorization.CertificatePlan{}, err
	}
	if route.TeamID != publisher.Scope.TeamID || route.LifecycleState != PublicURLLifecycleEnabled ||
		publisher.Scope.Kind == "saved_url" && (route.ID != publisher.Scope.PublicURLID || route.Ephemeral) ||
		publisher.Scope.Kind == "namespace" && (!route.Ephemeral || route.DomainID != publisher.Scope.DomainID || route.Namespace != publisher.Scope.Namespace) {
		return authorization.CertificatePlan{}, ErrPublisherIdentity
	}
	if publisher.Scope.Kind != "saved_url" && publisher.Scope.Kind != "namespace" {
		return authorization.CertificatePlan{}, ErrPublisherIdentity
	}
	domain, err := controlstatedb.New(d.pool).GetReadyPublisherDomain(ctx, controlstatedb.GetReadyPublisherDomainParams{
		DomainID: route.DomainID, TeamID: text(route.TeamID),
	})
	if err != nil || domain.ID != route.DomainID {
		return authorization.CertificatePlan{}, ErrPublisherIdentity
	}
	namespace := route.Namespace
	if publisher.Scope.Kind == "namespace" {
		namespace = publisher.Scope.Namespace
	}
	plan := authorization.PublicURLCertificatePlan(route.CanonicalHostname, namespace,
		domain.Kind == "custom" && route.PublicURLScope == PublicURLScopeShared, dnsAutomation)
	if !certificateidentity.Covers(plan.Identifiers, route.CanonicalHostname) ||
		publisher.Scope.Kind == "namespace" && publisher.GuestID == "" && plan.ChallengeMethod != certificateidentity.ChallengeDNS01 {
		return authorization.CertificatePlan{}, ErrPublisherIdentity
	}
	if plan.CacheKey == "" || plan.Scope == "" {
		return authorization.CertificatePlan{}, ErrPublisherIdentity
	}
	return *plan, nil
}
