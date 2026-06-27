package controlapi

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"

	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func controlSessionResponse(session controlstate.ControlSession) authorityv1.ControlSessionResponse {
	return authorityv1.ControlSessionResponse{
		SessionId: session.SessionID, AccessToken: session.AccessToken.String(),
		AccessExpiresAt: session.AccessExpiresAt, RefreshToken: session.RefreshToken.String(),
		RefreshExpiresAt: session.RefreshExpiresAt, Identity: identityContextResponse(session.Identity),
	}
}

func identityContextResponse(context controlstate.IdentityContext) authorityv1.IdentityContext {
	identity := authorityv1.Identity{
		Id: context.Identity.ID, DisplayName: context.Identity.DisplayName,
		Administrator: context.Identity.Administrator, CreatedAt: context.Identity.CreatedAt,
	}
	if context.Identity.NormalizedEmail != "" {
		email := openapi_types.Email(context.Identity.NormalizedEmail)
		verified := context.Identity.EmailVerified
		identity.NormalizedEmail, identity.EmailVerified = &email, &verified
	}
	memberships := make([]authorityv1.Membership, len(context.Memberships))
	for index, membership := range context.Memberships {
		memberships[index] = authorityv1.Membership{
			Id: membership.ID, TeamId: membership.TeamID, IdentityId: membership.IdentityID,
			TeamDisplayName: membership.TeamDisplayName, TeamKind: authorityv1.TeamKind(membership.TeamKind),
			Role: authorityv1.TeamRole(membership.Role), MemberSlug: membership.MemberSlug,
			ManagedLabel: membership.ManagedLabel, PolicyRevision: membership.PolicyRevision,
			CreatedAt: membership.CreatedAt, UpdatedAt: membership.UpdatedAt,
		}
	}
	return authorityv1.IdentityContext{
		Identity: identity, PersonalTeamId: context.PersonalTeamID, Memberships: memberships,
	}
}

func teamResponse(team controlstate.Team) authorityv1.Team {
	return authorityv1.Team{
		Id: team.ID, Kind: authorityv1.TeamKind(team.Kind), DisplayName: team.DisplayName,
		ManagedLabel: team.ManagedLabel, DefaultDomainId: team.DefaultDomainID,
		PolicyRevision: team.PolicyRevision, CreatedAt: team.CreatedAt, UpdatedAt: team.UpdatedAt,
	}
}

func domainResponse(domain controlstate.Domain) authorityv1.Domain {
	result := authorityv1.Domain{
		Id: domain.ID, Kind: authorityv1.DomainKind(domain.Kind), CanonicalDomain: domain.CanonicalDomain,
		State: authorityv1.DomainState(domain.State), AuthorityRevision: domain.AuthorityRevision,
		RequiredRecords: []authorityv1.DNSRecord{}, CreatedAt: domain.CreatedAt, UpdatedAt: domain.UpdatedAt,
	}
	if domain.TeamID != "" {
		result.TeamId = &domain.TeamID
	}
	if !domain.VerifiedAt.IsZero() {
		result.VerifiedAt = &domain.VerifiedAt
	}
	return result
}

func routeResponse(route controlstate.Route) controlv1.Route {
	result := controlv1.Route{
		Id: route.ID, TeamId: route.TeamID, DomainId: route.DomainID,
		CanonicalHostname: route.CanonicalHostname, Target: route.Target,
		RouteScope: controlv1.RouteScope(route.RouteScope), PolicyRevision: route.PolicyRevision,
		LifecycleState: controlv1.RouteLifecycleState(route.LifecycleState), NextRouteVersion: route.NextRouteVersion,
		CreatedAt: route.CreatedAt, UpdatedAt: route.UpdatedAt,
	}
	if route.MembershipID != "" {
		result.MembershipId = &route.MembershipID
	}
	if len(route.AllowedIPPrefixes) != 0 {
		prefixes := make([]string, len(route.AllowedIPPrefixes))
		for index, prefix := range route.AllowedIPPrefixes {
			prefixes[index] = prefix.String()
		}
		result.AllowedIpPrefixes = &prefixes
	}
	if route.AttachedSessionID != "" {
		result.AttachedSessionId = &route.AttachedSessionID
	}
	return result
}

func routeSessionSetupResponse(
	route controlstate.Route,
	setup controlstate.RouteSessionSetup,
	certificatePlan controlv1.CertificatePlan,
	relayTransportTrustBundle string,
) controlv1.RouteSessionSetup {
	return controlv1.RouteSessionSetup{
		Route: routeResponse(route), RouteSession: routeSessionResponse(setup),
		RouteSessionToken: setup.SessionToken.String(), CertificatePlan: certificatePlan,
		PublisherConnections:      publisherConnectionResponses(setup.PublisherConnections),
		RelayTransportTrustBundle: relayTransportTrustBundle,
	}
}

func serviceEnrollmentTokenResponse(token controlstate.ServiceEnrollmentToken) controlv1.ServiceEnrollmentToken {
	result := controlv1.ServiceEnrollmentToken{
		Id: token.ID, Role: controlv1.ServiceEnrollmentRole(token.Role), CreatedAt: token.CreatedAt,
		LastUsedAt: token.LastUsedAt, RevokedAt: token.RevokedAt,
	}
	if token.RelayServiceID != "" {
		result.RelayServiceId = &token.RelayServiceID
	}
	return result
}

func serviceEnrollmentResponse(
	cfg Config,
	enrollment controlstate.ServiceEnrollment,
) controlv1.ServiceEnrollmentResponse {
	response := controlv1.ServiceEnrollmentResponse{
		Role: controlv1.ServiceEnrollmentRole(enrollment.Role), ServiceCertificate: enrollment.ServiceCertificatePEM,
		TrustBundle: enrollment.TrustBundlePEM, CertificateExpiresAt: enrollment.CertificateExpiresAt,
	}
	if enrollment.Role == controlstate.ServiceEnrollmentRoleIngress {
		response.InternalControlEndpoint = cfg.IngressControlEndpoint
		return response
	}
	response.InternalControlEndpoint = cfg.RelayControlEndpoint
	response.RelayServiceId = &enrollment.RelayServiceID
	response.RelayAddress = &enrollment.RelayAddress
	response.TlsServerName = &enrollment.TLSServerName
	response.RelayTransportCertificate = &enrollment.RelayTransportMaterial.CertificatePEM
	response.RelayTransportPrivateKey = &enrollment.RelayTransportMaterial.PrivateKeyPEM
	return response
}

func routeSessionResponse(setup controlstate.RouteSessionSetup) controlv1.RouteSession {
	readyPublisherConnections := 0
	for _, connection := range setup.PublisherConnections {
		if connection.State == "ready" {
			readyPublisherConnections++
		}
	}
	result := controlv1.RouteSession{
		Id: setup.RouteSessionID, RouteId: setup.RouteID, TeamId: setup.TeamID,
		RouteVersion: int64(setup.RouteVersion), PolicyRevision: int64(setup.PolicyRevision),
		State: controlv1.RouteSessionState(setup.State), CreatedAt: setup.CreatedAt, ExpiresAt: setup.ExpiresAt,
		ReadyPublisherConnections: &readyPublisherConnections, ReadyAt: setup.ReadyAt, ClosedAt: setup.ClosedAt,
	}
	if setup.MembershipID != "" {
		result.MembershipId = &setup.MembershipID
	}
	return result
}

func routeSessionLifecycleResponse(lifecycle controlstate.RouteSessionLifecycle) controlv1.RouteSession {
	readyPublisherConnections := lifecycle.ReadyPublisherConnectionCount
	result := controlv1.RouteSession{
		Id: lifecycle.RouteSessionID, RouteId: lifecycle.RouteID, TeamId: lifecycle.TeamID,
		RouteVersion: int64(lifecycle.RouteVersion), PolicyRevision: int64(lifecycle.PolicyRevision),
		State: controlv1.RouteSessionState(lifecycle.State), CreatedAt: lifecycle.CreatedAt, ExpiresAt: lifecycle.ExpiresAt,
		ReadyPublisherConnections: &readyPublisherConnections, ReadyAt: lifecycle.ReadyAt, ClosedAt: lifecycle.ClosedAt,
	}
	if lifecycle.MembershipID != "" {
		result.MembershipId = &lifecycle.MembershipID
	}
	return result
}

func publisherConnectionResponses(connections [2]controlstate.PublisherConnectionPlan) []controlv1.PublisherConnectionPlan {
	result := make([]controlv1.PublisherConnectionPlan, len(connections))
	for index, connection := range connections {
		state := controlv1.PublisherConnectionState(connection.State)
		if connection.State == "closed" || connection.State == "expired" {
			state = controlv1.PublisherConnectionStateReplacing
		}
		result[index] = controlv1.PublisherConnectionPlan{
			ConnectionSlot: connection.ConnectionSlot, PublisherConnectionId: connection.PublisherConnectionID,
			ConnectionAssignmentRevision: int64(connection.ConnectionAssignmentRevision),
			RelayServiceId:               connection.RelayServiceID, RelayAddress: connection.RelayAddress,
			TlsServerName:                          connection.TLSServerName,
			PublisherConnectionCredential:          connection.PublisherConnectionCredential.String(),
			PublisherConnectionCredentialExpiresAt: connection.PublisherConnectionCredentialExpiresAt, State: state,
		}
	}
	return result
}

func certificateIssuanceRequestDigest(routeVersion uint64, csrDER []byte) [32]byte {
	hash := sha256.New()
	var encodedVersion [8]byte
	binary.BigEndian.PutUint64(encodedVersion[:], routeVersion)
	_, _ = hash.Write(encodedVersion[:])
	_, _ = hash.Write(csrDER)
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func certificateIssuanceResponse(issuance controlstate.CertificateIssuance) controlv1.CertificateIssuance {
	identifiers := make([]controlv1.CanonicalHostname, len(issuance.CertificatePlan.Identifiers))
	copy(identifiers, issuance.CertificatePlan.Identifiers)
	result := controlv1.CertificateIssuance{
		Id: issuance.ID, RouteSessionId: issuance.RouteSessionID, RouteId: issuance.RouteID,
		RouteVersion: int64(issuance.RouteVersion), State: controlv1.CertificateIssuanceState(issuance.State),
		CertificatePlan: controlv1.CertificatePlan{
			CacheKey: issuance.CertificatePlan.CacheKey, Scope: issuance.CertificatePlan.Scope,
			Identifiers: identifiers, ChallengeMethod: controlv1.CertificateChallengeMethod(issuance.CertificatePlan.ChallengeMethod),
		},
		RetryAt: issuance.RetryAt, NotBefore: issuance.NotBefore, NotAfter: issuance.NotAfter,
		CreatedAt: issuance.CreatedAt, UpdatedAt: issuance.UpdatedAt,
	}
	if issuance.CertificatePEM != "" {
		result.CertificatePem = &issuance.CertificatePEM
	}
	if len(issuance.Challenges) > 0 {
		challenges := make([]controlv1.CertificateChallenge, len(issuance.Challenges))
		for index, challenge := range issuance.Challenges {
			challenges[index] = controlv1.CertificateChallenge{
				Identifier: challenge.Identifier, Method: controlv1.CertificateChallengeMethod(challenge.Method),
				Token: challenge.Token, Digest: base64.RawURLEncoding.EncodeToString(challenge.Digest[:]),
				ExpiresAt: challenge.ExpiresAt,
			}
		}
		result.Challenges = &challenges
	}
	return result
}

func validLocalCertificatePlan(plan controlv1.CertificatePlan, hostname string) bool {
	return plan.CacheKey == hostname && plan.Scope == hostname && plan.ChallengeMethod == controlv1.TlsAlpn01 &&
		len(plan.Identifiers) == 1 && plan.Identifiers[0] == hostname
}
