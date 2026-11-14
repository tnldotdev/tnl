package visitortoken

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestConnectorPeerPermissionBindsCanonicalOwnerAndOpening(t *testing.T) {
	testConnectorPeerPermissionBindsCanonicalOwnerAndOpening(t, visitorscope.Service)
}

func TestPublicURLConnectorPeerPermissionBindsCanonicalOwnerAndOpening(t *testing.T) {
	testConnectorPeerPermissionBindsCanonicalOwnerAndOpening(t, visitorscope.PublicURL)
}

func testConnectorPeerPermissionBindsCanonicalOwnerAndOpening(t *testing.T, kind visitorscope.Kind) {
	t.Helper()
	key, permission, view, now := tokenFixture(t)
	native := ed25519.NewKeyFromSeed([]byte(strings.Repeat("v", 32)))
	digest, _ := KeyDigest(native.Public())
	permission.Scope = visitorscope.Scope{Kind: visitorscope.Service, ID: "svc_" + strings.Repeat("A", 22)}
	permission.Port = 15432
	if kind == visitorscope.PublicURL {
		permission.Scope = visitorscope.Scope{Kind: kind, ID: "url_" + strings.Repeat("A", 22)}
		permission.Port = 20007
	}
	permission.Subject = Device{IdentityID: "ident_" + strings.Repeat("B", 22), SessionID: "cs_" + strings.Repeat("C", 22), DeviceID: "vdev_" + strings.Repeat("D", 22), KeySHA256: digest}
	view.Scope, view.Port, view.MetadataRevision = permission.Scope, permission.Port, 5
	token := issueToken(t, key, permission, view, now)
	subject, _ := ConnectorSubject(permission.Subject)
	entry := tunnelv1.ConnectorPeerVisitorEntry{ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.ConnectorPeerVisitorStream, PairID: "cpp_" + strings.Repeat("E", 22), DeliveryID: base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("f", 16))), DeliveryGeneration: 1, ServiceID: permission.Scope.ID, ServiceRunID: "srun_" + strings.Repeat("G", 22), RunNumber: 1, Subject: subject, SourceIP: "192.0.2.1", VisitorConnectionID: "vc_" + strings.Repeat("H", 22), MetadataRevision: 5, Permission: tunnelv1.ConnectorVisitorPermission{Token: token.Reveal(), PublicKey: base64.RawURLEncoding.EncodeToString(native.Public().(ed25519.PublicKey)), Signature: base64.RawURLEncoding.EncodeToString(make([]byte, 64))}}
	if kind == visitorscope.PublicURL {
		entry.ServiceID, entry.ServiceRunID, entry.RunNumber = "", "", 0
		entry.PublicURLID, entry.PublishRunID, entry.PublishRunNumber = permission.Scope.ID, "pr_"+strings.Repeat("G", 22), 1
	}
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
		"run": func(e *tunnelv1.ConnectorPeerVisitorEntry) {
			if e.PublicURLID != "" {
				e.PublishRunNumber++
			} else {
				e.RunNumber++
			}
		},
		"visitor":  func(e *tunnelv1.ConnectorPeerVisitorEntry) { e.VisitorConnectionID = "vc_" + strings.Repeat("Z", 22) },
		"metadata": func(e *tunnelv1.ConnectorPeerVisitorEntry) { e.MetadataRevision++ },
		"subject":  func(e *tunnelv1.ConnectorPeerVisitorEntry) { e.Subject.DeviceID = "vdev_" + strings.Repeat("Z", 22) },
		"key": func(e *tunnelv1.ConnectorPeerVisitorEntry) {
			e.Permission.PublicKey = base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := entry
			change(&changed)
			if got, err := VerifyConnectorPeerSession(changed, initial, expected, view, now); !errors.Is(err, ErrBinding) || got.Valid() {
				t.Fatal("changed native binding did not fail closed with ErrBinding", err)
			}
		})
	}
	if got, err := VerifyConnectorPeerSession(entry, []byte("changed"), expected, view, now); !errors.Is(err, ErrBinding) || got.Valid() {
		t.Fatal("initial bytes were not possession-bound", err)
	}
	zeroPortError := ErrToken
	if kind == visitorscope.PublicURL {
		zeroPortError = ErrPolicy
	}
	for _, test := range []struct {
		name   string
		change func(*View)
		want   error
	}{
		{"resource kind", func(v *View) {
			if v.Scope.Kind == visitorscope.Service {
				v.Scope.Kind = visitorscope.PublicURL
			} else {
				v.Scope.Kind = visitorscope.Service
			}
		}, ErrBinding},
		{"resource id", func(v *View) { v.Scope.ID += "Z" }, ErrBinding},
		{"port", func(v *View) { v.Port++ }, ErrToken},
		{"zero port", func(v *View) { v.Port = 0 }, zeroPortError},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := view
			test.change(&changed)
			if got, err := VerifyConnectorPeerSession(entry, initial, expected, changed, now); !errors.Is(err, test.want) || got.Valid() {
				t.Fatal("signed permission crossed its exact resource or endpoint", err)
			}
		})
	}
	// even another current checked owner cannot reuse the original opening's
	// possession proof. matching expected state must not bypass the signature.
	changed := entry
	changed.SourceIP = "198.51.100.1"
	moved := changed.Session()
	moved.ExpiresAt = expected.ExpiresAt
	if got, err := VerifyConnectorPeerSession(changed, initial, moved, view, now); !errors.Is(err, ErrBinding) || got.Valid() {
		t.Fatal("new checked source reused the old opening signature", err)
	}
	expected.ExpiresAt = now
	if got, err := VerifyConnectorPeerSession(entry, initial, expected, view, now); !errors.Is(err, ErrBinding) || got.Valid() {
		t.Fatal("expired exact owner admitted a stream", err)
	}
}
