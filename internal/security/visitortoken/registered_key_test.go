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

func TestRegisteredKeyConnectorCurrentAuthority(t *testing.T) {
	key, permission, view, now := tokenFixture(t)
	native := ed25519.NewKeyFromSeed([]byte(strings.Repeat("r", 32)))
	digest, _ := KeyDigest(native.Public())
	registered := RegisteredKey{GrantID: "pgrant_" + strings.Repeat("A", 22), KeyID: "pkey_" + strings.Repeat("B", 22), KeySHA256: digest}
	permission.Scope = visitorscope.Scope{Kind: visitorscope.Service, ID: "svc_" + strings.Repeat("C", 22)}
	permission.Subject, permission.Port = registered, 15432
	view.Scope, view.Port, view.MetadataRevision = permission.Scope, permission.Port, 3
	parent := RegisteredKeyLease{KeySHA256: digest, ExpiresAt: now.Add(time.Minute)}
	view = view.WithRegisteredKeyLeases(map[string]RegisteredKeyLease{registered.AuthorityID(): parent})
	token := issueToken(t, key, permission, view, now)
	subject, err := ConnectorSubject(registered)
	if err != nil || subject.Validate() != nil {
		t.Fatal(err)
	}
	entry := tunnelv1.ConnectorPeerVisitorEntry{ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.ConnectorPeerVisitorStream,
		PairID: "cpp_" + strings.Repeat("D", 22), DeliveryID: base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("e", 16))), DeliveryGeneration: 1,
		ServiceID: permission.Scope.ID, ServiceRunID: "srun_" + strings.Repeat("F", 22), RunNumber: 1, Subject: subject, SourceIP: "192.0.2.1",
		VisitorConnectionID: "vc_" + strings.Repeat("G", 22), MetadataRevision: 3,
		Permission: tunnelv1.ConnectorVisitorPermission{Token: token.Reveal(), PublicKey: base64.RawURLEncoding.EncodeToString(native.Public().(ed25519.PublicKey)), Signature: base64.RawURLEncoding.EncodeToString(make([]byte, 64))}}
	message, err := tunnelv1.ConnectorPeerProofMessage(entry, nil)
	if err != nil {
		t.Fatal(err)
	}
	entry.Permission.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(native, message))
	expected := entry.Session()
	expected.ExpiresAt = now.Add(time.Minute)
	verified, err := VerifyConnectorPeerSession(entry, nil, expected, view, now)
	if err != nil || verified.Facts().Subject != registered {
		t.Fatal("valid exact registered key rejected", err)
	}
	if _, err := VerifyBearer(token, view, now); err == nil {
		t.Fatal("registered signing permission became a bearer visitor credential")
	}
	for name, leases := range map[string]map[string]RegisteredKeyLease{
		"revoked":     nil,
		"expired":     {registered.AuthorityID(): {KeySHA256: digest, ExpiresAt: now}},
		"rotated":     {registered.AuthorityID(): {KeySHA256: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), ExpiresAt: parent.ExpiresAt}},
		"other grant": {"pgrant_" + strings.Repeat("Z", 22) + "." + registered.KeyID: parent},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyConnectorPeerSession(entry, nil, expected, view.WithRegisteredKeyLeases(leases), now); err == nil {
				t.Fatal("stale key authority admitted a stream")
			}
		})
	}
}
