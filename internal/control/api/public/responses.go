package public

import (
	"crypto/sha256"
	"encoding/binary"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func publicURLResponse(publicURL controlstate.PublicURL) controlv1.PublicURL {
	protocol := controlv1.PublicURLServiceProtocol(publicURL.ServiceProtocol)
	if protocol == "" {
		protocol = controlv1.Http
	}
	result := controlv1.PublicURL{
		PublisherPool: &publicURL.PublisherPool,
		Id:            publicURL.ID, TeamId: publicURL.TeamID, DomainId: publicURL.DomainID,
		CanonicalHostname: publicURL.CanonicalHostname, Target: publicURL.Target,
		ServiceProtocol:  protocol,
		AccessMode:       controlv1.VisitorAccessMode(publicURL.AccessMode),
		MutationRevision: int64(publicURL.MutationRevision),
		PublicUrlScope:   controlv1.PublicURLScope(publicURL.PublicURLScope), Purpose: controlv1.PublicURLPurpose(publicURL.Purpose), PolicyRevision: publicURL.PolicyRevision,
		LifecycleState: controlv1.PublicURLLifecycleState(publicURL.LifecycleState), NextPublishRunNumber: publicURL.NextPublishRunNumber,
		Ephemeral: publicURL.Ephemeral, ExpiresAt: publicURL.ExpiresAt, CreatedAt: publicURL.CreatedAt, UpdatedAt: publicURL.UpdatedAt,
	}
	if publicURL.MembershipID != "" {
		result.MembershipId = &publicURL.MembershipID
	}
	if len(publicURL.AllowedIPPrefixes) != 0 {
		prefixes := make([]string, len(publicURL.AllowedIPPrefixes))
		for index, prefix := range publicURL.AllowedIPPrefixes {
			prefixes[index] = prefix.String()
		}
		result.AllowedIpPrefixes = &prefixes
	}
	if publicURL.OpenPublishRunID != "" {
		result.OpenPublishRunId = &publicURL.OpenPublishRunID
	}
	return result
}

func publishRunSetupResponse(
	publicURL controlstate.PublicURL,
	setup controlstate.PublishRunSetup,
	certificatePlan controlv1.CertificatePlan,
) controlv1.PublishRunSetup {
	return controlv1.PublishRunSetup{
		PublicUrl: publicURLResponse(publicURL), PublishRun: publishRunResponse(setup),
		PublishRunToken: setup.PublishRunToken.String(), CertificatePlan: certificatePlan,
		PublisherConnections: connectionAssignmentResponses(setup.PublisherConnections),
		Traffic:              trafficLimitsResponse(setup.Traffic),
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
	return result
}
