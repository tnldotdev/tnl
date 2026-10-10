package controlapi

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func publicURLResponse(route controlstate.PublicURL) controlv1.PublicURL {
	protocol := controlv1.PublicURLServiceProtocol(route.ServiceProtocol)
	if protocol == "" {
		protocol = "http"
	}
	result := controlv1.PublicURL{
		Id: route.ID, TeamId: route.TeamID, DomainId: route.DomainID,
		CanonicalHostname: route.CanonicalHostname, Target: route.Target,
		ServiceProtocol: protocol,
		PublicUrlScope:  controlv1.PublicURLScope(route.PublicURLScope), Purpose: controlv1.PublicURLPurpose(route.Purpose), PolicyRevision: route.PolicyRevision,
		LifecycleState: controlv1.PublicURLLifecycleState(route.LifecycleState), NextPublishRunNumber: route.NextPublishRunNumber,
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
	if route.OpenPublishRunID != "" {
		result.OpenPublishRunId = &route.OpenPublishRunID
	}
	if route.PublicPort != nil {
		port := int(*route.PublicPort)
		result.PublicPort = &port
	}
	return result
}

func publishRunSetupResponse(
	route controlstate.PublicURL,
	setup controlstate.PublishRunSetup,
	certificatePlan controlv1.CertificatePlan,
) controlv1.PublishRunSetup {
	return controlv1.PublishRunSetup{
		PublicUrl: publicURLResponse(route), PublishRun: publishRunResponse(setup),
		PublishRunToken: setup.PublishRunToken.String(), CertificatePlan: certificatePlan,
		PublisherConnections: connectionAssignmentResponses(setup.PublisherConnections),
	}
}

func publishRunResponse(setup controlstate.PublishRunSetup) controlv1.PublishRun {
	readyPublisherConnections := 0
	for _, connection := range setup.PublisherConnections {
		if connection.State == "ready" {
			readyPublisherConnections++
		}
	}
	result := controlv1.PublishRun{
		Id: setup.PublishRunID, PublicUrlId: setup.PublicURLID, TeamId: setup.TeamID,
		PublishRunNumber: int64(setup.PublishRunNumber), PolicyRevision: int64(setup.PolicyRevision),
		State: controlv1.PublishRunState(setup.State), CreatedAt: setup.CreatedAt, ExpiresAt: setup.ExpiresAt,
		ReadyPublisherConnections: &readyPublisherConnections, ReadyAt: setup.ReadyAt, ClosedAt: setup.ClosedAt,
	}
	if setup.MembershipID != "" {
		result.MembershipId = &setup.MembershipID
	}
	return result
}

func publishRunLifecycleResponse(lifecycle controlstate.PublishRunLifecycle) controlv1.PublishRun {
	readyPublisherConnections := lifecycle.ReadyPublisherConnectionCount
	result := controlv1.PublishRun{
		Id: lifecycle.PublishRunID, PublicUrlId: lifecycle.PublicURLID, TeamId: lifecycle.TeamID,
		PublishRunNumber: int64(lifecycle.PublishRunNumber), PolicyRevision: int64(lifecycle.PolicyRevision),
		State: controlv1.PublishRunState(lifecycle.State), CreatedAt: lifecycle.CreatedAt, ExpiresAt: lifecycle.ExpiresAt,
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

func certificateIssuanceRequestDigest(publishRunNumber uint64, csrDER []byte) [32]byte {
	hash := sha256.New()
	var encodedVersion [8]byte
	binary.BigEndian.PutUint64(encodedVersion[:], publishRunNumber)
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
		Id: issuance.ID, PublishRunId: issuance.PublishRunID, PublicUrlId: issuance.PublicURLID,
		PublishRunNumber: int64(issuance.PublishRunNumber), State: controlv1.CertificateIssuanceState(issuance.State),
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
