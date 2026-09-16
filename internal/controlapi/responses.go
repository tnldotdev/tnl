package controlapi

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func routeResponse(route controlstate.Route) controlv1.Route {
	result := controlv1.Route{
		Id: route.ID, TeamId: route.TeamID, DomainId: route.DomainID,
		CanonicalHostname: route.CanonicalHostname, Target: route.Target,
		RouteScope: controlv1.RouteScope(route.RouteScope), PolicyRevision: route.PolicyRevision,
		LifecycleState: controlv1.RouteLifecycleState(route.LifecycleState), NextRouteVersion: route.NextRouteVersion,
		Ephemeral: route.Ephemeral, ExpiresAt: route.ExpiresAt, CreatedAt: route.CreatedAt, UpdatedAt: route.UpdatedAt,
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
) controlv1.RouteSessionSetup {
	return controlv1.RouteSessionSetup{
		Route: routeResponse(route), RouteSession: routeSessionResponse(setup),
		RouteSessionToken: setup.RouteSessionToken.String(), CertificatePlan: certificatePlan,
		PublisherConnections: connectionAssignmentResponses(setup.PublisherConnections),
	}
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

func connectionAssignmentResponses(assignments [2]controlstate.ConnectionAssignment) []controlv1.ConnectionAssignment {
	result := make([]controlv1.ConnectionAssignment, len(assignments))
	for index, connection := range assignments {
		state := controlv1.PublisherConnectionState(connection.State)
		if connection.State == "closed" || connection.State == "expired" {
			state = controlv1.PublisherConnectionStateReplacing
		}
		result[index] = controlv1.ConnectionAssignment{
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
		RetryAt: issuance.RetryAt, CreatedAt: issuance.CreatedAt, UpdatedAt: issuance.UpdatedAt,
	}
	if result.State == controlv1.CertificateIssuanceStateWaitingForInstall || result.State == controlv1.CertificateIssuanceStateInstalled {
		if issuance.CertificatePEM != "" {
			result.CertificatePem = &issuance.CertificatePEM
		}
		result.NotBefore, result.NotAfter = issuance.NotBefore, issuance.NotAfter
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
