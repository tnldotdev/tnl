package targettrust

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"testing"
)

func TestDeclarationPreservesBothDigestFormats(t *testing.T) {
	declaration := Declaration{Hostname: "db.example", Digest: "da1ddea34ff954d059450909910705d099d9ec15f9a0317816a77336817fe0c3"}
	snapshot, err := declaration.Snapshot()
	if err != nil || !snapshot.System || snapshot.Digest != "ccd0b1cc832fd1a6c408f0dd878d591657eb816c12a4cd92e9fc05d634a281ca" {
		t.Fatalf("saved-service snapshot = %+v, %v", snapshot, err)
	}
	roundtrip, err := snapshot.Declaration()
	if err != nil || roundtrip.Hostname != declaration.Hostname || roundtrip.Digest != declaration.Digest || len(roundtrip.CAPEM) != 0 {
		t.Fatalf("project declaration = %+v, %v", roundtrip, err)
	}
	ca, _ := testCA(t)
	snapshotValue, err := CapturePEM("db.example", ca)
	if err != nil {
		t.Fatal(err)
	}
	declared, err := snapshotValue.Declaration()
	if err != nil {
		t.Fatal(err)
	}
	expected := sha256.Sum256(append([]byte("tnl-target-tls/v1\x00db.example\x00"), snapshotValue.PEM...))
	if declared.Digest != hex.EncodeToString(expected[:]) {
		t.Fatal("project declaration digest changed")
	}
	restored, err := declared.Snapshot()
	if err != nil || restored.Digest != snapshotValue.Digest || !bytes.Equal(restored.PEM, snapshotValue.PEM) || restored.System {
		t.Fatalf("CA snapshot roundtrip = %+v, %v", restored, err)
	}
}

func TestPortableTrustValidationRejectsContradictions(t *testing.T) {
	ca, leaf := testCA(t)
	for _, tc := range []struct {
		name, hostname string
		pem            []byte
		system         bool
	}{
		{"noncanonical hostname", "DB.Example", nil, true},
		{"invalid hostname", "db/path", nil, true},
		{"zoned IP", "fe80::1%lo0", nil, true},
		{"system with CA", "db.example", ca, true},
		{"empty CA", "db.example", nil, false},
		{"leaf certificate", "db.example", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Certificate[0]}), false},
		{"trailing data", "db.example", append(bytes.Clone(ca), []byte("private data")...), false},
		{"too many CAs", "db.example", bytes.Repeat(ca, 33), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := Snapshot{Hostname: tc.hostname, PEM: tc.pem, System: tc.system}
			s.Digest = s.digest()
			if s.Validate() == nil {
				t.Fatal("invalid saved-service trust accepted")
			}
			if tc.system == (len(tc.pem) == 0) {
				d := Declaration{Hostname: tc.hostname, CAPEM: tc.pem, Digest: declarationDigest(tc.hostname, tc.pem)}
				if d.Validate() == nil {
					t.Fatal("invalid project trust accepted")
				}
			}
		})
	}
	s := Snapshot{Hostname: "db.example", System: true, Digest: "wrong"}
	if s.Validate() == nil {
		t.Fatal("changed snapshot digest accepted")
	}
	if (Declaration{Hostname: "db.example", Digest: "wrong"}).Validate() == nil {
		t.Fatal("changed declaration digest accepted")
	}
}
