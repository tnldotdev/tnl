package controlv1

import (
	"bytes"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestConnectorProofAdaptersPreserveEveryVisitorSubject(t *testing.T) {
	for _, subject := range []tunnelv1.VisitorSubject{
		{Kind: tunnelv1.VisitorHumanDevice, IdentityID: "ident_1234567890123456789012", DeviceID: "vdev_1234567890123456789012"},
		{Kind: tunnelv1.VisitorWorkloadSession, WorkloadSessionID: "wls_1234567890123456789012"},
		{Kind: tunnelv1.VisitorRegisteredKey, GrantID: "pgrant_1234567890123456789012", KeyID: "pkey_1234567890123456789012"},
	} {
		t.Run(subject.Kind, func(t *testing.T) {
			wire := VisitorSubject{Kind: VisitorSubjectKind(subject.Kind)}
			if subject.IdentityID != "" {
				wire.IdentityId, wire.DeviceId = &subject.IdentityID, &subject.DeviceID
			}
			if subject.WorkloadSessionID != "" {
				wire.WorkloadSessionId = &subject.WorkloadSessionID
			}
			if subject.GrantID != "" {
				wire.GrantId, wire.KeyId = &subject.GrantID, &subject.KeyID
			}
			const service = "svc_1234567890123456789012"
			request := ConnectorPeerPairRequest{Action: "create", ServiceRunId: "srun_1234567890123456789012", RunNumber: 2, PublisherIdentityId: "pub_1234567890123456789012", Subject: wire, IdempotencyKey: "pair-one", RequestedAt: time.Date(2026, 1, 2, 3, 4, 5, 123456000, time.UTC)}
			for _, name := range []string{"a", "b"} {
				request.ExpectedRelays = append(request.ExpectedRelays, ConnectorPeerPairRelay{
					PublisherConnectionId: "pc_1234567890123456789012", AssignmentRevision: 1, RelayAddress: name + ".example.test:443", TlsServerName: name + ".example.test",
					RelayLease: ConnectorPeerRelayLease{RelayServiceId: "relay-" + name, RelayId: "node-" + name, RelayRunId: "process-" + name, RelayLeaseRevision: 1},
				})
			}
			proof, err := ConnectorPeerPairProof(service, request)
			if err != nil || proof.Subject != subject {
				t.Fatal("pair adapter lost its exact visitor subject", proof.Subject, err)
			}
			proof.Subject = subject
			want, err := proof.Message()
			if err != nil {
				t.Fatal(err)
			}
			got, err := ConnectorPeerPairProofMessage(service, request)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatal("pair adapter changed protocol signing bytes", err)
			}
			rebind := rebindRequestFixture()
			rebind.Subject = wire
			rebindProof, err := ConnectorPeerPairRebindProof(service, "cpp_1234567890123456789012", rebind)
			if err != nil || rebindProof.Subject != subject {
				t.Fatal("rebind adapter lost its exact visitor subject", rebindProof.Subject, err)
			}
			empty := ""
			if subject.Kind == tunnelv1.VisitorHumanDevice {
				request.Subject.GrantId = &empty
				rebind.Subject.GrantId = &empty
			} else {
				request.Subject.IdentityId = &empty
				rebind.Subject.IdentityId = &empty
			}
			if _, err := ConnectorPeerPairProofMessage(service, request); err == nil {
				t.Fatal("pair adapter signed an extra subject variant field")
			}
			if _, err := ConnectorPeerPairRebindProofMessage(service, "cpp_1234567890123456789012", rebind); err == nil {
				t.Fatal("rebind adapter signed an extra subject variant field")
			}
		})
	}
}
