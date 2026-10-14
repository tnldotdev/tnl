package controlstate

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/publisheridentity"
)

func TestIntegrationGuestPublisherStaysInsideItsTrial(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "guest_publisher")
	guest, err := NewGuestTrialCredential(netip.MustParseAddr("192.0.2.7"))
	if err != nil {
		t.Fatal(err)
	}
	domainID, err := database.CreateGuestTrial(t.Context(), guest, "example.test", now)
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := database.RegisterGuestPublisherIdentity(t.Context(), guest.ID, public, now)
	if err != nil || identity.GuestID != guest.ID || identity.Scope.TeamID != guest.TeamID ||
		identity.Scope.DomainID != domainID || identity.Scope.Namespace != guest.NamespaceLabel+".example.test" {
		t.Fatalf("guest publisher identity = %+v, %v", identity, err)
	}
	for _, test := range []struct {
		ip      string
		allowed bool
	}{{"192.0.2.7", true}, {"192.0.2.8", false}} {
		matched, err := database.GuestPublisherSourceMatches(t.Context(), guest.ID, netip.MustParseAddr(test.ip))
		if err != nil || matched != test.allowed {
			t.Fatalf("source %s = %t, %v", test.ip, matched, err)
		}
	}
	const audience = "https://control.example/v1/publisher/token"
	assertion, err := publisheridentity.Sign(identity.ID, identity.KeyID, audience, private, now)
	if err != nil {
		t.Fatal(err)
	}
	access, err := database.ExchangePublisherAssertion(t.Context(), identity.ID, identity.GrantID, audience, assertion, now)
	if err != nil || access.GuestID != guest.ID || access.Scope != identity.Scope {
		t.Fatalf("guest access = %+v, %v", access, err)
	}
	authenticated, err := database.AuthenticatePublisherAccess(t.Context(), access.Token, now)
	if err != nil || authenticated.GuestID != guest.ID {
		t.Fatalf("guest token scope = %+v, %v", authenticated, err)
	}
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.guest_trials SET used_ready_ns = $2 WHERE id = $1`,
		guest.ID, int64(GuestReadyAllowance)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.AuthenticatePublisherAccess(t.Context(), access.Token, now.Add(time.Second)); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatalf("spent trial retained publisher access: %v", err)
	}
	other, err := publisheridentity.Sign(identity.ID, identity.KeyID, audience, private, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExchangePublisherAssertion(t.Context(), identity.ID, identity.GrantID, audience, other, now.Add(time.Second)); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatalf("spent trial exchanged a new token: %v", err)
	}
}
