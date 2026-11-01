package visitortoken

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestConnectorPeerPermissionBindsCanonicalOwnerAndOpening(t *testing.T) {
	key, permission, view, now := tokenFixture(t)
	native := ed25519.NewKeyFromSeed([]byte(strings.Repeat("v", 32)))
	digest, _ := KeyDigest(native.Public())
	permission.Scope = visitorscope.Scope{Kind: visitorscope.Service, ID: "svc_" + strings.Repeat("A", 22)}
	permission.Port = 15432
	permission.Subject = Device{IdentityID: "ident_" + strings.Repeat("B", 22), SessionID: "cs_" + strings.Repeat("C", 22), DeviceID: "vdev_" + strings.Repeat("D", 22), KeySHA256: digest}
	view.Scope, view.Port, view.MetadataRevision = permission.Scope, permission.Port, 5
	token := issueToken(t, key, permission, view, now)
	subject, _ := ConnectorSubject(permission.Subject)
	entry := tunnelv1.ConnectorPeerVisitorEntry{ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.ConnectorPeerVisitorStream, PairID: "cpp_" + strings.Repeat("E", 22), DeliveryID: base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("f", 16))), DeliveryGeneration: 1, ServiceID: permission.Scope.ID, ServiceRunID: "srun_" + strings.Repeat("G", 22), RunNumber: 1, Subject: subject, SourceIP: "192.0.2.1", VisitorConnectionID: "vc_" + strings.Repeat("H", 22), MetadataRevision: 5, Permission: tunnelv1.ConnectorVisitorPermission{Token: token.Reveal(), PublicKey: base64.RawURLEncoding.EncodeToString(native.Public().(ed25519.PublicKey)), Signature: base64.RawURLEncoding.EncodeToString(make([]byte, 64))}}
	initial := []byte("exact initial TLS bytes")
	message, err := tunnelv1.ConnectorPeerProofMessage(entry, initial)
	if err != nil {
		t.Fatal(err)
	}
	entry.Permission.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(native, message))
	expected := entry.Session()
	expected.ExpiresAt = now.Add(time.Minute)
	if _, err := VerifyConnectorPeerSession(entry, initial, expected, view, now); err != nil {
		t.Fatal("valid connector permission rejected", err)
	}
	for name, change := range map[string]func(*tunnelv1.ConnectorPeerVisitorEntry){
		"source":     func(e *tunnelv1.ConnectorPeerVisitorEntry) { e.SourceIP = "198.51.100.1" },
		"pair":       func(e *tunnelv1.ConnectorPeerVisitorEntry) { e.PairID = "cpp_" + strings.Repeat("Z", 22) },
		"generation": func(e *tunnelv1.ConnectorPeerVisitorEntry) { e.DeliveryGeneration++ },
		"run":        func(e *tunnelv1.ConnectorPeerVisitorEntry) { e.RunNumber++ },
		"visitor":    func(e *tunnelv1.ConnectorPeerVisitorEntry) { e.VisitorConnectionID = "vc_" + strings.Repeat("Z", 22) },
		"metadata":   func(e *tunnelv1.ConnectorPeerVisitorEntry) { e.MetadataRevision++ },
		"subject":    func(e *tunnelv1.ConnectorPeerVisitorEntry) { e.Subject.DeviceID = "vdev_" + strings.Repeat("Z", 22) },
		"key": func(e *tunnelv1.ConnectorPeerVisitorEntry) {
			e.Permission.PublicKey = base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := entry
			change(&changed)
			if _, err := VerifyConnectorPeerSession(changed, initial, expected, view, now); err == nil {
				t.Fatal("changed native binding accepted")
			}
		})
	}
	if _, err := VerifyConnectorPeerSession(entry, []byte("changed"), expected, view, now); err == nil {
		t.Fatal("initial bytes were not possession-bound")
	}
	expected.ExpiresAt = now
	if _, err := VerifyConnectorPeerSession(entry, initial, expected, view, now); err == nil {
		t.Fatal("expired exact owner admitted a stream")
	}
}
