package controlv1

import "github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"

// ConnectorPeerPairRebindProof adapts generated fields to the handwritten proof.
// it verifies phase-specific shape, not source authentication or current authority.
func ConnectorPeerPairRebindProof(serviceID, pairID string, body ConnectorPeerPairRebindRequest) (tunnelv1.ConnectorPeerPairRebindProof, error) {
	subject, valid := connectorProofSubject(body.Subject)
	if len(body.ExpectedRelays) > 2 || len(body.PathProofs) > 2 || !valid {
		return tunnelv1.ConnectorPeerPairRebindProof{}, tunnelv1.ErrConnectorPeerPairRebindProof
	}
	proof := tunnelv1.ConnectorPeerPairRebindProof{Phase: string(body.Phase), ServiceID: serviceID, PairID: pairID,
		IdempotencyKey: body.IdempotencyKey, OperationID: body.OperationId, ExpectedGeneration: body.ExpectedGeneration,
		RequestedAt: body.RequestedAt, ServiceRunID: body.ServiceRunId, RunNumber: body.RunNumber,
		PublisherIdentityID: body.PublisherIdentityId, TrustRevision: body.TrustRevision, Subject: subject,
		BindingChallenge: body.BindingChallenge}
	for _, relay := range body.ExpectedRelays {
		if relay.RelayLease.RelayLeaseRevision < 1 {
			return tunnelv1.ConnectorPeerPairRebindProof{}, tunnelv1.ErrConnectorPeerPairRebindProof
		}
		proof.ExpectedRelays = append(proof.ExpectedRelays, tunnelv1.ConnectorPeerPairRelay{PublisherConnectionID: relay.PublisherConnectionId,
			AssignmentRevision: relay.AssignmentRevision, RelayAddress: relay.RelayAddress, TLSServerName: relay.TlsServerName,
			RelayLease: tunnelv1.ConnectorPeerRelayLease{RelayServiceID: relay.RelayLease.RelayServiceId, RelayID: relay.RelayLease.RelayId,
				RelayRunID: relay.RelayLease.RelayRunId, RelayLeaseRevision: uint64(relay.RelayLease.RelayLeaseRevision)}})
	}
	for _, path := range body.PathProofs {
		proof.PathProofs = append(proof.PathProofs, tunnelv1.ConnectorPeerPairPathProof{ConnectionSlot: path.ConnectionSlot,
			ProbeNonce: path.ProbeNonce, ReplyFrame: path.ReplyFrame})
	}
	if _, err := proof.Message(); err != nil {
		return tunnelv1.ConnectorPeerPairRebindProof{}, err
	}
	return proof, nil
}

// ConnectorPeerPairRebindProofMessage returns signing bytes before a caller sets
// Signature. neither source credentials nor signature bytes enter this message.
func ConnectorPeerPairRebindProofMessage(serviceID, pairID string, body ConnectorPeerPairRebindRequest) ([]byte, error) {
	proof, err := ConnectorPeerPairRebindProof(serviceID, pairID, body)
	if err != nil {
		return nil, err
	}
	return proof.Message()
}
