package state

import (
	"bytes"
	"strings"
	"testing"
	"time"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestConnectorPeerPairProofStateAndHTTPBytesMatch(t *testing.T) {
	at := time.Date(2026, 1, 2, 3, 4, 5, 123456789, time.UTC)
	stateRequest := ConnectorPeerPairRequest{ServiceID: "svc_1234567890123456789012", ServiceRunID: "srun_1234567890123456789012",
		RunNumber: 2, PublisherIdentityID: "pub_1234567890123456789012", IdempotencyKey: "pair-one", Action: "create", RequestedAt: at,
		Subject: VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, IdentityID: "ident_1234567890123456789012", DeviceID: "vdev_1234567890123456789012"},
		ExpectedRelays: [2]ConnectorPeerPairRelay{
			{PublisherConnectionID: "pc_1234567890123456789012", AssignmentRevision: 5, RelayAddress: "a.example.test:443", TLSServerName: "a.example.test",
				RelayLease: RelayLeaseIdentity{RelayServiceID: "relay-a", RelayID: "node-a", RelayRunID: "process-a", RelayLeaseRevision: 3}},
			{PublisherConnectionID: "pc_abcdefghijklmnopqrstuv", AssignmentRevision: 6, RelayAddress: "b.example.test:443", TLSServerName: "b.example.test",
				RelayLease: RelayLeaseIdentity{RelayServiceID: "relay-b", RelayID: "node-b", RelayRunID: "process-b", RelayLeaseRevision: 4}},
		}}
	wireRequest := controlv1.ConnectorPeerPairRequest{ServiceRunId: stateRequest.ServiceRunID, RunNumber: stateRequest.RunNumber,
		PublisherIdentityId: stateRequest.PublisherIdentityID, IdempotencyKey: stateRequest.IdempotencyKey, Action: "create", RequestedAt: at,
		Subject: controlv1.VisitorSubject{Kind: "human_device", IdentityId: &stateRequest.Subject.IdentityID, DeviceId: &stateRequest.Subject.DeviceID},
		ExpectedRelays: []controlv1.ConnectorPeerPairRelay{
			{PublisherConnectionId: stateRequest.ExpectedRelays[0].PublisherConnectionID, AssignmentRevision: 5, RelayAddress: "a.example.test:443", TlsServerName: "a.example.test",
				RelayLease: controlv1.ConnectorPeerRelayLease{RelayServiceId: "relay-a", RelayId: "node-a", RelayRunId: "process-a", RelayLeaseRevision: 3}},
			{PublisherConnectionId: stateRequest.ExpectedRelays[1].PublisherConnectionID, AssignmentRevision: 6, RelayAddress: "b.example.test:443", TlsServerName: "b.example.test",
				RelayLease: controlv1.ConnectorPeerRelayLease{RelayServiceId: "relay-b", RelayId: "node-b", RelayRunId: "process-b", RelayLeaseRevision: 4}},
		}}
	fromState, err := stateRequest.proof().Message()
	if err != nil {
		t.Fatal(err)
	}
	fromClient, err := controlv1.ConnectorPeerPairProofMessage(stateRequest.ServiceID, wireRequest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fromState, fromClient) || !strings.Contains(string(fromClient), `"RelayLeaseRevision":3`) || strings.Contains(string(fromClient), `"relay_lease_revision"`) {
		t.Fatal("state and generated public wire did not agree on the signed v1 bytes")
	}
}
