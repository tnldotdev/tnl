package visitorlease

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"net/netip"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func connectorGuardFixture(t *testing.T) (*Lease, Update, visitortoken.VerifiedPermission) {
	t.Helper()
	id := func(prefix, letter string) string { return prefix + strings.Repeat(letter, 22) }
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: id("svc_", "A")}
	l, err := New(scope, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.Close)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	connectorKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))
	digest, _ := visitortoken.KeyDigest(connectorKey.Public())
	now := time.Now()
	u := Update{View: visitortoken.View{Issuer: "https://control.example.test", Scope: scope, Hostname: "service.example.test", Port: 15432, VisitorPolicyRevision: 1, MetadataRevision: 5, ObservedAt: now, ValidUntil: now.Add(10 * time.Second)}.WithVerificationKeys(map[string]ed25519.PublicKey{"first": key.Public().(ed25519.PublicKey)}), KeyRevision: 1, Enabled: true, Snapshot: true}
	if err := l.Apply(l.Begin(), u); err != nil {
		t.Fatal(err)
	}
	view, _, _ := l.Current()
	subject := visitortoken.Device{IdentityID: id("ident_", "D"), SessionID: id("cs_", "I"), DeviceID: id("vdev_", "E"), KeySHA256: digest}
	token, err := visitortoken.Sign(view.Issuer, "first", key, visitortoken.Permission{Scope: scope, Hostname: view.Hostname, Port: view.Port, VisitorPolicyRevision: 1, Subject: subject, ExpiresAt: now.Add(time.Minute)}, now)
	if err != nil {
		t.Fatal(err)
	}
	peer, _ := visitortoken.ConnectorSubject(subject)
	e := tunnelv1.ConnectorPeerVisitorEntry{ProtocolVersion: 1, Kind: tunnelv1.ConnectorPeerVisitorStream, PairID: id("cpp_", "F"), DeliveryID: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 16)), DeliveryGeneration: 1, ServiceID: scope.ID, ServiceRunID: id("srun_", "C"), RunNumber: 1, Subject: peer, SourceIP: "192.0.2.1", VisitorConnectionID: id("vc_", "G"), MetadataRevision: 5, Permission: tunnelv1.ConnectorVisitorPermission{Token: token.Reveal(), PublicKey: base64.RawURLEncoding.EncodeToString(connectorKey.Public().(ed25519.PublicKey)), Signature: base64.RawURLEncoding.EncodeToString(make([]byte, 64))}}
	message, err := tunnelv1.ConnectorPeerProofMessage(e, nil)
	if err != nil {
		t.Fatal(err)
	}
	e.Permission.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(connectorKey, message))
	expected := e.Session()
	expected.ExpiresAt = now.Add(time.Minute)
	permission, err := visitortoken.VerifyConnectorPeerSession(e, nil, expected, view, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return l, u, permission
}

func TestPolicyConnectorMetadataSurvivesDecode(t *testing.T) {
	for _, revision := range []int64{-1, 0, 7} {
		wire := controlv1.VisitorPolicyUpdate{Policy: controlv1.VisitorPolicySnapshot{Resource: controlv1.VisitorResourceScope{Kind: "service", Id: "svc_" + strings.Repeat("A", 22)}, Port: 15432, MetadataRevision: revision}}
		update, err := Decode(wire)
		if revision < 0 {
			if err == nil {
				t.Fatal("negative metadata revision accepted")
			}
		} else if err != nil || update.View.MetadataRevision != revision {
			t.Fatal("metadata revision lost", revision, err)
		}
	}
}

func TestPolicyConnectorRemovalFencesBeforeCallback(t *testing.T) {
	for _, mutation := range []string{"metadata", "key", "disabled", "revision"} {
		t.Run(mutation, func(t *testing.T) {
			l, u, permission := connectorGuardFixture(t)
			entered, release := make(chan struct{}), make(chan struct{})
			g, err := l.BindConnector(permission, netip.MustParseAddr("192.0.2.1"), 5, func() { close(entered); <-release })
			if err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "metadata":
				u.View.MetadataRevision++
			case "key":
				u.View = u.View.WithVerificationKeys(nil)
				u.KeyRevision++
			case "disabled":
				u.Enabled = false
			case "revision":
				u.View.VisitorPolicyRevision++
				u.Events = []int64{2}
			}
			finished := make(chan error, 1)
			go func() { finished <- l.Apply(l.Begin(), u) }()
			<-entered
			if _, err := g.Current(); err == nil {
				t.Error("removed guard usable while callback held")
			}
			close(release)
			if err := <-finished; err != nil {
				t.Fatal(err)
			}
			g.Close()
		})
	}
}

func TestPolicyConnectorCloseAndExpiryAreSynchronous(t *testing.T) {
	for _, closeGuard := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			l, _, permission := connectorGuardFixture(t)
			g, err := l.BindConnector(permission, netip.MustParseAddr("192.0.2.1"), 5, func() {})
			if err != nil {
				t.Fatal(err)
			}
			g.guard.timer.Stop()
			l.timer.Stop()
			if closeGuard {
				g.Close()
			} else {
				time.Sleep(11 * time.Second)
			}
			if _, err := g.Current(); err == nil {
				t.Fatal("connector use ignored membership or absolute expiry")
			}
			g.Close()
		})
	}
}

func TestPolicyConnectorCannotBorrowRequestGuard(t *testing.T) {
	l, _, _ := connectorGuardFixture(t)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	permission := admission(t, l, key, "first", time.Now().Add(time.Minute))
	request, err := l.Bind(permission, netip.MustParseAddr("192.0.2.1"), func() {})
	if err != nil {
		t.Fatal(err)
	}
	defer request.Close()
	if _, ok := any(request).(interface{ Current() (time.Time, error) }); ok {
		t.Fatal("request guard exposed connector stream use")
	}
	if g, err := l.BindConnector(permission, netip.MustParseAddr("192.0.2.1"), 5, func() {}); err == nil || g != nil {
		t.Fatal("HTTP bearer minted connector stream permission")
	}
}
