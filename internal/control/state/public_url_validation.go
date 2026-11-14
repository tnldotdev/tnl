package state

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
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
		!validStateText(request.CanonicalHostname) ||
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
	canonical, err := naming.CanonicalizeHostname(request.CanonicalHostname)
	if err != nil || canonical != request.CanonicalHostname {
		return nil, ErrPublicURLInvalid
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

// ordinary and deployment-owned exact URLs share all membership and reserved
// namespace checks. callers hold the team guard through insertion.
func authorizePublicURLCreation(ctx context.Context, queries *controlstatedb.Queries, request CreatePublicURLRequest) (controlstatedb.GetPublicURLCreationContextRow, error) {
	creation, err := queries.GetPublicURLCreationContext(ctx, controlstatedb.GetPublicURLCreationContextParams{
		IdentityID: request.ActingIdentityID, DomainID: request.DomainID, TeamID: request.TeamID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return creation, ErrPublicURLAccess
	}
	if err != nil {
		return creation, fmt.Errorf("controlstate: create public_url: read authority context: %w", err)
	}
	labels, err := queries.ListTeamNamespaceLabels(ctx, request.TeamID)
	if err != nil {
		return creation, fmt.Errorf("controlstate: create public_url: read namespaces: %w", err)
	}
	if request.DNSState == PublicURLDNSPending && request.DNSAuthorityReference != creation.DnsAuthorityReference.String {
		return creation, ErrPublicURLAccess
	}
	if err := authorizeServiceHostname(creation, labels, request.TeamID, request.MembershipID, request.CanonicalHostname, string(request.PublicURLScope), request.ManagedURLMode); err != nil {
		return creation, errors.Join(ErrPublicURLAccess, err)
	}
	return creation, nil
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
