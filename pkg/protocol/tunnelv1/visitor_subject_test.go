package tunnelv1

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func TestVisitorSubjectVariants(t *testing.T) {
	human := VisitorSubject{Kind: VisitorHumanDevice, IdentityID: opaqueid.IdentityPrefix + strings.Repeat("A", 22), DeviceID: opaqueid.VisitorDevicePrefix + strings.Repeat("B", 22)}
	workload := VisitorSubject{Kind: VisitorWorkloadSession, WorkloadSessionID: "wls_" + strings.Repeat("C", 22)}
	for _, s := range []VisitorSubject{human, workload} {
		if err := s.Validate(); err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		var decoded VisitorSubject
		if err = json.Unmarshal(data, &decoded); err != nil || decoded != s {
			t.Fatal("subject did not round trip", err)
		}
	}
	for _, bad := range []VisitorSubject{{}, {Kind: VisitorHumanDevice, IdentityID: human.IdentityID}, {Kind: VisitorHumanDevice, IdentityID: human.IdentityID, DeviceID: human.DeviceID, WorkloadSessionID: workload.WorkloadSessionID}, {Kind: VisitorWorkloadSession, WorkloadSessionID: workload.WorkloadSessionID, IdentityID: human.IdentityID}, {Kind: "publisher", WorkloadSessionID: workload.WorkloadSessionID}, {Kind: VisitorWorkloadSession, WorkloadSessionID: strings.Repeat("C", 256)}} {
		if bad.Validate() == nil {
			t.Fatal("accepted mixed or invalid visitor subject")
		}
	}
}

func TestVisitorSubjectRejectsMixedWireVariants(t *testing.T) {
	for _, raw := range []string{
		`{"kind":"workload_session","workload_session_id":"wls_aaaaaaaaaaaaaaaaaaaaaa","identity_id":""}`,
		`{"kind":"workload_session","workload_session_id":"wls_aaaaaaaaaaaaaaaaaaaaaa","device_id":null}`,
		`{"kind":"human_device","identity_id":"ident_aaaaaaaaaaaaaaaaaaaaaa","device_id":"vdev_aaaaaaaaaaaaaaaaaaaaaa","workload_session_id":""}`,
		`{"kind":"workload_session","workload_session_id":"wls_aaaaaaaaaaaaaaaaaaaaaa","publisher_identity_id":"pub_aaaaaaaaaaaaaaaaaaaaaa"}`,
		`{"kind":"workload_session","workload_session_id":"wls_` + strings.Repeat("a", 10000) + `"}`,
	} {
		var subject VisitorSubject
		if json.Unmarshal([]byte(raw), &subject) == nil {
			t.Fatal("mixed or unbounded wire subject accepted")
		}
	}
}

func TestVisitorSubjectPrivateFrameProofsAndBounds(t *testing.T) {
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		subject VisitorSubject
		golden  string
	}{
		{VisitorSubject{Kind: VisitorHumanDevice, IdentityID: testOpaqueID(opaqueid.IdentityPrefix), DeviceID: testOpaqueID(opaqueid.VisitorDevicePrefix)}, `{"session_id":"cns_aaaaaaaaaaaaaaaaaaaaaa","subject":{"kind":"human_device","identity_id":"ident_aaaaaaaaaaaaaaaaaaaaaa","device_id":"vdev_aaaaaaaaaaaaaaaaaaaaaa"},"grant_revision":7}`},
		{VisitorSubject{Kind: VisitorWorkloadSession, WorkloadSessionID: testOpaqueID("wls_")}, `{"session_id":"cns_aaaaaaaaaaaaaaaaaaaaaa","subject":{"kind":"workload_session","workload_session_id":"wls_aaaaaaaaaaaaaaaaaaaaaa"},"grant_revision":7}`},
	} {
		t.Run(test.subject.Kind, func(t *testing.T) {
			hello := ConnectorSessionHello{ProtocolVersion: 1, Kind: "connector_session", ServiceID: testOpaqueID(opaqueid.ServicePrefix), SessionID: testOpaqueID(opaqueid.ConnectorSessionPrefix), Credential: strings.Repeat("a", 43), Subject: test.subject, Nonce: bytes.Repeat([]byte{1}, 32)}
			digest, err := hello.Claim().Digest()
			if err != nil {
				t.Fatal(err)
			}
			hello.Signature = ed25519.Sign(key, digest)
			var frame bytes.Buffer
			if err = WriteConnectorSessionHello(&frame, hello); err != nil {
				t.Fatal(err)
			}
			wire := bytes.Clone(frame.Bytes())
			if len(wire)-4 > MaxServiceHeaderBytes || int(binary.BigEndian.Uint32(wire[:4])) != len(wire)-4 {
				t.Fatal("hello framing bound")
			}
			decoded, err := ReadConnectorSessionHello(&frame)
			if err != nil {
				t.Fatal(err)
			}
			proof, err := decoded.Claim().Digest()
			if err != nil || decoded.Subject != test.subject || !ed25519.Verify(public, proof, decoded.Signature) {
				t.Fatal("subject proof lost across frame", err)
			}
			for _, mutate := range []func(*VisitorConnectorClaim){func(c *VisitorConnectorClaim) {
				c.Subject = VisitorSubject{Kind: VisitorWorkloadSession, WorkloadSessionID: "wls_bbbbbbbbbbbbbbbbbbbbbb"}
			}, func(c *VisitorConnectorClaim) { c.Credential = strings.Repeat("b", 43) }, func(c *VisitorConnectorClaim) { c.SessionID = "cns_bbbbbbbbbbbbbbbbbbbbbb" }, func(c *VisitorConnectorClaim) { c.Nonce = bytes.Repeat([]byte{2}, 32) }} {
				claim := decoded.Claim()
				mutate(&claim)
				changed, err := claim.Digest()
				if err != nil || ed25519.Verify(public, changed, decoded.Signature) {
					t.Fatal("proof did not bind exact claim")
				}
			}
			admission := ConnectorAdmission{SessionID: hello.SessionID, Subject: test.subject, GrantRevision: 7}
			data, err := json.Marshal(admission)
			if err != nil || string(data) != test.golden {
				t.Fatalf("admission golden: %s %v", data, err)
			}
			accepted := ConnectorSessionAccepted{ProtocolVersion: 1, Kind: "connector_session_accepted", ServiceID: hello.ServiceID, SessionID: hello.SessionID, Subject: test.subject, SourceIP: "192.0.2.1", ExpiresAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}
			if err := WriteConnectorSessionAccepted(&frame, accepted); err != nil {
				t.Fatal(err)
			}
			if got, err := ReadConnectorSessionAccepted(&frame); err != nil || got != accepted {
				t.Fatal("accepted subject", err)
			}
			// removed human fields are never an alternative to the tagged subject.
			for _, field := range []string{"identity_id", "device_id", "workload_session_id"} {
				body := append(bytes.Clone(wire[4:len(wire)-1]), []byte(`,"`+field+`":"legacy"}`)...)
				frame.Reset()
				_ = binary.Write(&frame, binary.BigEndian, uint32(len(body)))
				frame.Write(body)
				if _, err := ReadConnectorSessionHello(&frame); err == nil {
					t.Fatal("legacy field accepted")
				}
			}
			hello.Subject.WorkloadSessionID = strings.Repeat("a", MaxServiceHeaderBytes)
			frame.Reset()
			if err := WriteConnectorSessionHello(&frame, hello); err == nil || frame.Len() != 0 {
				t.Fatal("unbounded subject wrote bytes")
			}
			frame.Reset()
			_ = binary.Write(&frame, binary.BigEndian, uint32(MaxServiceHeaderBytes+1))
			if _, err := ReadConnectorSessionHello(&frame); err == nil {
				t.Fatal("unbounded frame accepted")
			}
		})
	}
}
