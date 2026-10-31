package tunnelv1

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"

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

func TestVisitorSubjectNativeFrameProofsAndBounds(t *testing.T) {
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, subject := range []VisitorSubject{
		{Kind: VisitorHumanDevice, IdentityID: testOpaqueID(opaqueid.IdentityPrefix), DeviceID: testOpaqueID(opaqueid.VisitorDevicePrefix)},
		{Kind: VisitorWorkloadSession, WorkloadSessionID: testOpaqueID("wls_")},
	} {
		t.Run(subject.Kind, func(t *testing.T) {
			entry := peerOpeningFixture()
			entry.Subject = subject
			entry.Permission.PublicKey = base64.RawURLEncoding.EncodeToString(public)
			proof, err := NativePeerProofMessage(entry, nil)
			if err != nil {
				t.Fatal(err)
			}
			entry.Permission.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, proof))
			var wire bytes.Buffer
			if err := WriteNativePeerVisitorEntry(&wire, entry); err != nil {
				t.Fatal(err)
			}
			original := bytes.Clone(wire.Bytes())
			if wire.Len()-4 > MaxHeaderBytes || int(binary.BigEndian.Uint32(original[:4])) != wire.Len()-4 {
				t.Fatal("native frame bound")
			}
			decoded, err := ReadNativePeerVisitorEntry(&wire)
			if err != nil || decoded.Subject != subject {
				t.Fatal("subject lost across frame", err)
			}
			message, err := NativePeerProofMessage(decoded, nil)
			signature, _ := base64.RawURLEncoding.DecodeString(decoded.Permission.Signature)
			if err != nil || !ed25519.Verify(public, message, signature) {
				t.Fatal("subject signature lost across frame", err)
			}
			for _, mutate := range []func(*NativePeerVisitorEntry){
				func(e *NativePeerVisitorEntry) {
					e.Subject = VisitorSubject{Kind: VisitorWorkloadSession, WorkloadSessionID: "wls_bbbbbbbbbbbbbbbbbbbbbb"}
				},
				func(e *NativePeerVisitorEntry) { e.Permission.Token = "different-token" },
				func(e *NativePeerVisitorEntry) { e.PairID = "npp_bbbbbbbbbbbbbbbbbbbbbb" },
				func(e *NativePeerVisitorEntry) { e.VisitorConnectionID = "vc_bbbbbbbbbbbbbbbbbbbbbb" },
			} {
				changed := decoded
				mutate(&changed)
				message, err := NativePeerProofMessage(changed, nil)
				if err != nil || ed25519.Verify(public, message, signature) {
					t.Fatal("signature did not bind exact native opening", err)
				}
			}
			for _, field := range []string{"identity_id", "device_id", "workload_session_id", "connector_session_id", "session_credential"} {
				body := string(original[4:len(original)-1]) + `,"` + field + `":"legacy"}`
				if _, err := ReadNativePeerVisitorEntry(frame(body)); err == nil {
					t.Fatal("legacy field accepted")
				}
			}
			entry.Subject.WorkloadSessionID = strings.Repeat("a", MaxHeaderBytes)
			wire.Reset()
			if err := WriteNativePeerVisitorEntry(&wire, entry); err == nil || wire.Len() != 0 {
				t.Fatal("unbounded subject wrote bytes")
			}
			if _, err := ReadNativePeerVisitorEntry(bytes.NewReader(binary.BigEndian.AppendUint32(nil, MaxHeaderBytes+1))); err == nil {
				t.Fatal("unbounded frame accepted")
			}
		})
	}
}
