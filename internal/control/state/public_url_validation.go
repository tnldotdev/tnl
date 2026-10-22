package state

import (
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/authorization"
)

func validateCreatePublicURLRequest(request CreatePublicURLRequest) ([]netip.Prefix, error) {
	for _, value := range []string{
		request.TeamID, request.DomainID, request.ActingIdentityID, request.IdempotencyKey,
		string(request.PublicURLScope), string(request.DNSState),
	} {
		if !validStateText(value) {
			return nil, ErrPublicURLInvalid
		}
	}
	if len(request.IdempotencyKey) > 128 || request.MembershipID != "" && !validStateText(request.MembershipID) ||
		request.PublisherIdentityID == "" && !validStateText(request.CanonicalHostname) ||
		request.PublisherIdentityID != "" && (request.CanonicalHostname != "" || !request.Ephemeral ||
			!opaqueid.Valid(request.PublisherIdentityID, opaqueid.PublisherIdentityPrefix) || !opaqueid.Valid(request.PublisherGrantID, opaqueid.PublisherGrantPrefix) ||
			!opaqueid.Valid(request.PublisherInvocationID, opaqueid.InvocationPrefix)) ||
		!request.Purpose.ValidForCreation() || request.GuestID != "" && request.Purpose != PublicURLPurposeDemo ||
		request.DNSAuthorityReference != "" && !validStateText(request.DNSAuthorityReference) ||
		request.DNSState == PublicURLDNSUnmanaged && request.DNSAuthorityReference != "" ||
		request.PublicURLScope != PublicURLScopeMember && request.PublicURLScope != PublicURLScopeShared ||
		request.DNSState != PublicURLDNSUnmanaged && request.DNSState != PublicURLDNSPending {
		return nil, ErrPublicURLInvalid
	}
	if request.GuestID != "" && (!validStateText(request.GuestID) || request.ActingIdentityID != request.GuestID || request.PolicyRevision == 0) {
		return nil, ErrPublicURLInvalid
	}
	if request.PublisherIdentityID == "" {
		canonical, err := naming.CanonicalizeHostname(request.CanonicalHostname)
		if err != nil || canonical != request.CanonicalHostname {
			return nil, ErrPublicURLInvalid
		}
	}
	if !request.ServiceProtocol.ValidCreateTarget(request.Purpose, request.Target, request.Ephemeral) ||
		request.ServiceProtocol != PublicURLServiceHTTP {
		return nil, ErrPublicURLInvalid
	}
	canonicalPrefixes, err := authorization.CanonicalizeIPPrefixes(request.AllowedIPPrefixes)
	if err != nil || !slices.Equal(canonicalPrefixes, request.AllowedIPPrefixes) {
		return nil, ErrPublicURLInvalid
	}
	prefixes := make([]netip.Prefix, len(canonicalPrefixes))
	for index, value := range canonicalPrefixes {
		prefixes[index], _ = netip.ParsePrefix(value)
	}
	return prefixes, nil
}

func validateAuthorizedPublicURLUpdateRequest(request AuthorizedPublicURLUpdateRequest) ([]netip.Prefix, error) {
	for _, value := range []string{request.PublicURLID, request.TeamID, request.ActingIdentityID} {
		if !validStateText(value) {
			return nil, ErrPublicURLInvalid
		}
	}
	if request.PolicyRevision == 0 || request.ExpectedMutationRevision == 0 ||
		request.Target != "" && authorization.ValidateTarget(request.Target) != nil {
		return nil, ErrPublicURLInvalid
	}
	canonicalPrefixes, err := authorization.CanonicalizeIPPrefixes(request.AllowedIPPrefixes)
	if err != nil || request.AllowedIPPrefixes == nil || !slices.Equal(canonicalPrefixes, request.AllowedIPPrefixes) {
		return nil, ErrPublicURLInvalid
	}
	return prefixValues(canonicalPrefixes), nil
}

func ephemeralRouteExpiry(ephemeral bool, now time.Time) pgtype.Timestamptz {
	if !ephemeral {
		return pgtype.Timestamptz{}
	}
	return timestamptz(now.Add(ephemeralPublicURLGracePeriod))
}

func authorizeRouteCreation(
	request CreatePublicURLRequest,
	context controlstatedb.GetPublicURLCreationContextRow,
	labels []controlstatedb.ListTeamNamespaceLabelsRow,
) error {
	if context.DomainState != "ready" || context.DomainKind == "custom" && context.DomainTeamID.String != request.TeamID ||
		context.DomainKind == "managed" && context.DomainTeamID.Valid || !hostnameWithin(request.CanonicalHostname, context.CanonicalDomain) {
		return ErrPublicURLAccess
	}
	if request.DNSState == PublicURLDNSPending && request.DNSAuthorityReference != context.DnsAuthorityReference.String {
		return ErrPublicURLAccess
	}
	actorNamespace, direct := naming.PublicURLNamespace(naming.NamespaceFacts{
		Domain: context.CanonicalDomain, Managed: context.DomainKind == "managed",
		Mode: request.ManagedURLMode, Personal: context.TeamKind == "personal",
		TeamName: context.TeamDisplayName, MemberSlug: context.ActorMemberSlug, ManagedLabel: context.ActorManagedLabel,
	})
	if request.PublicURLScope == "member" {
		if direct || request.MembershipID != context.ActorMembershipID ||
			request.CanonicalHostname == actorNamespace || !hostnameWithin(request.CanonicalHostname, actorNamespace) {
			return ErrPublicURLAccess
		}
		return nil
	}
	if request.MembershipID != "" || context.ActorRole != "admin" && context.ActorRole != "owner" {
		return ErrPublicURLAccess
	}
	if context.DomainKind == "managed" {
		namespace := naming.SharedPublicURLNamespace(context.CanonicalDomain, true, request.ManagedURLMode, context.TeamDisplayName, context.TeamManagedLabel)
		if depth, within := naming.ChildDepth(request.CanonicalHostname, namespace); !within || depth < 1 {
			return ErrPublicURLAccess
		}
		if context.TeamKind == "organization" && request.ManagedURLMode == naming.ManagedURLModeSimple {
			for _, label := range labels {
				memberNamespace := label.MemberSlug + "." + namespace
				if hostnameWithin(request.CanonicalHostname, memberNamespace) {
					return ErrPublicURLAccess
				}
			}
		}
		return nil
	}
	for _, label := range labels {
		namespace := label.MemberSlug + "." + context.CanonicalDomain
		if request.CanonicalHostname == namespace || strings.HasSuffix(request.CanonicalHostname, "."+namespace) {
			return ErrPublicURLAccess
		}
	}
	return nil
}

func hostnameWithin(hostname, domain string) bool {
	return hostname == domain || strings.HasSuffix(hostname, "."+domain)
}

func routeIPPolicy(prefixes []netip.Prefix) IPPolicy {
	if len(prefixes) == 0 {
		return IPPolicyAllowAll
	}
	return IPPolicyAllowlist
}

func nullableText(value string) pgtype.Text {
	if value == "" {
		return pgtype.Text{}
	}
	return text(value)
}
