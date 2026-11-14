package controlv1

import "github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"

// PublicURLConnectorPeerPairProof adapts HTTP fields to the canonical tunnel
// proof. source credentials and HTTP JSON are not signing inputs.
func PublicURLConnectorPeerPairProof(publicURLID string, body PublicURLConnectorPeerPairRequest) (tunnelv1.ConnectorPeerPairProof, error) {
	subject, valid := publicURLConnectorSubject(body.Subject)
	if !valid || len(body.ExpectedRelays) != 2 {
		return tunnelv1.ConnectorPeerPairProof{}, tunnelv1.ErrConnectorPeerPairProof
	}
	proof := tunnelv1.ConnectorPeerPairProof{PublicURLID: publicURLID, PublishRunID: body.PublishRunId, PublishRunNumber: body.PublishRunNumber,
		PublisherIdentityID: body.PublisherIdentityId, Subject: subject, Action: string(body.Action),
		IdempotencyKey: body.IdempotencyKey, RequestedAt: body.RequestedAt}
	if body.PreviousPairId != nil {
		proof.PreviousPairID = *body.PreviousPairId
	}
	if body.PreviousGeneration != nil {
		proof.PreviousGeneration = *body.PreviousGeneration
	}
	for slot, relay := range body.ExpectedRelays {
		converted, valid := connectorProofRelay(relay)
		if !valid {
			return tunnelv1.ConnectorPeerPairProof{}, tunnelv1.ErrConnectorPeerPairProof
		}
		proof.ExpectedRelays[slot] = converted
	}
	if _, err := proof.Message(); err != nil {
		return tunnelv1.ConnectorPeerPairProof{}, err
	}
	return proof, nil
}

func PublicURLConnectorPeerPairProofMessage(publicURLID string, body PublicURLConnectorPeerPairRequest) ([]byte, error) {
	proof, err := PublicURLConnectorPeerPairProof(publicURLID, body)
	if err != nil {
		return nil, err
	}
	return proof.Message()
}

func PublicURLConnectorPeerPairRebindProof(publicURLID, pairID string, body PublicURLConnectorPeerPairRebindRequest) (tunnelv1.ConnectorPeerPairRebindProof, error) {
	subject, valid := publicURLConnectorSubject(body.Subject)
	if !valid || len(body.ExpectedRelays) > 2 || len(body.PathProofs) > 2 {
		return tunnelv1.ConnectorPeerPairRebindProof{}, tunnelv1.ErrConnectorPeerPairRebindProof
	}
	proof := tunnelv1.ConnectorPeerPairRebindProof{PublicURLID: publicURLID, PublishRunID: body.PublishRunId, PublishRunNumber: body.PublishRunNumber,
		PairID: pairID, Phase: string(body.Phase), IdempotencyKey: body.IdempotencyKey, OperationID: body.OperationId,
		ExpectedGeneration: body.ExpectedGeneration, RequestedAt: body.RequestedAt, PublisherIdentityID: body.PublisherIdentityId,
		TrustRevision: body.TrustRevision, Subject: subject, BindingChallenge: body.BindingChallenge}
	for _, relay := range body.ExpectedRelays {
		converted, valid := connectorProofRelay(relay)
		if !valid {
			return tunnelv1.ConnectorPeerPairRebindProof{}, tunnelv1.ErrConnectorPeerPairRebindProof
		}
		proof.ExpectedRelays = append(proof.ExpectedRelays, converted)
	}
	for _, path := range body.PathProofs {
		proof.PathProofs = append(proof.PathProofs, tunnelv1.ConnectorPeerPairPathProof{
			ConnectionSlot: path.ConnectionSlot, ProbeNonce: path.ProbeNonce, ReplyFrame: path.ReplyFrame})
	}
	if _, err := proof.Message(); err != nil {
		return tunnelv1.ConnectorPeerPairRebindProof{}, err
	}
	return proof, nil
}

func PublicURLConnectorPeerPairRebindProofMessage(publicURLID, pairID string, body PublicURLConnectorPeerPairRebindRequest) ([]byte, error) {
	proof, err := PublicURLConnectorPeerPairRebindProof(publicURLID, pairID, body)
	if err != nil {
		return nil, err
	}
	return proof.Message()
}

func publicURLConnectorSubject(subject VisitorSubject) (tunnelv1.VisitorSubject, bool) {
	if subject.Kind != VisitorSubjectKind(tunnelv1.VisitorHumanDevice) || subject.IdentityId == nil || subject.DeviceId == nil ||
		subject.WorkloadSessionId != nil || subject.GrantId != nil || subject.KeyId != nil {
		return tunnelv1.VisitorSubject{}, false
	}
	return tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, IdentityID: *subject.IdentityId, DeviceID: *subject.DeviceId}, true
}

func connectorProofRelay(relay ConnectorPeerPairRelay) (tunnelv1.ConnectorPeerPairRelay, bool) {
	if relay.RelayLease.RelayLeaseRevision < 1 {
		return tunnelv1.ConnectorPeerPairRelay{}, false
	}
	return tunnelv1.ConnectorPeerPairRelay{PublisherConnectionID: relay.PublisherConnectionId,
		AssignmentRevision: relay.AssignmentRevision, RelayAddress: relay.RelayAddress, TLSServerName: relay.TlsServerName,
		RelayLease: tunnelv1.ConnectorPeerRelayLease{RelayServiceID: relay.RelayLease.RelayServiceId, RelayID: relay.RelayLease.RelayId,
			RelayRunID: relay.RelayLease.RelayRunId, RelayLeaseRevision: uint64(relay.RelayLease.RelayLeaseRevision)}}, true
}
