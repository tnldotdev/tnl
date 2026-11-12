package tnl

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
	"github.com/tnldotdev/tnl/internal/security/machineproof"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

func registeredSDKChallenge() authorityv1.IdentitySourceChallenge {
	public := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32)).Public().(ed25519.PublicKey)
	c := authorityv1.IdentitySourceChallenge{Schema: 1, Id: strings.Repeat("a", 32), BindingDigest: strings.Repeat("b", 64), Server: "https://control.example", Source: authorityv1.IdentitySourceSelection{Kind: "registered_key", MachineId: "mci_0123456789ABCDEFGHIJKL", KeyId: "source-key"}, Operation: "publication_exchange", NativePublicKey: base64.RawURLEncoding.EncodeToString(public), Nonce: strings.Repeat("n", 32), ExpiresAt: time.Now().Add(10 * time.Second), Publication: &authorityv1.IdentitySourcePublicationSelection{Namespace: "apps.example"}, Audience: "https://control.example/v1/machine-publication-sessions/exchange"}
	c.Scope = machineproof.Publication("", "apps.example", "exchange", c.NativePublicKey, c.Nonce)
	return c
}

func TestRegisteredSourceSignsOnlyCanonicalPreparedChallengeAndPinsNativeTuple(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{21}, 32))
	options := Options{ServerURL: "https://control.example", RegisteredKeySource: &RegisteredKeySource{MachineID: "mci_0123456789ABCDEFGHIJKL", KeyID: "source-key", PrivateKey: private}}
	identity, err := PreparePublisherIdentity(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	public := append(ed25519.PublicKey(nil), private.Public().(ed25519.PublicKey)...)
	clear(private)
	c := registeredSDKChallenge()
	request := publisherprotocol.ApplicationPublication{Allocate: &struct {
		Namespace string `json:"namespace"`
	}{Namespace: "apps.example"}}
	tuple := &applicationNativeTuple{}
	if err := validateApplicationSourceChallenge(c, request, identity, tuple); err != nil {
		t.Fatal(err)
	}
	reply, _, err := signApplicationSourceChallenge(t.Context(), identity.registered, c)
	if err != nil {
		t.Fatal(err)
	}
	if reply.ChallengeId != c.Id || reply.Schema != 1 {
		t.Fatal("reply lost defining shared correlation")
	}
	if _, err := publisherproof.Verify(reply.Assertion, c.Source.MachineId, c.Source.KeyId, c.Scope, c.Audience, public, time.Now()); err != nil {
		t.Fatal("source did not use canonical publisherproof JWT", err)
	}
	for _, change := range []func(*authorityv1.IdentitySourceChallenge){
		func(c *authorityv1.IdentitySourceChallenge) { c.Source.KeyId = "rotated-key" },
		func(c *authorityv1.IdentitySourceChallenge) {
			p := *c.Publication
			p.Namespace = "other.example"
			c.Publication = &p
			c.Scope = machineproof.Publication("", p.Namespace, "exchange", c.NativePublicKey, c.Nonce)
		},
		func(c *authorityv1.IdentitySourceChallenge) {
			c.Nonce = strings.Repeat("z", 32)
			c.Scope = machineproof.Publication("", "apps.example", "exchange", c.NativePublicKey, c.Nonce)
		},
		func(c *authorityv1.IdentitySourceChallenge) {
			c.NativePublicKey = base64.RawURLEncoding.EncodeToString(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{10}, 32)).Public().(ed25519.PublicKey))
			c.Scope = machineproof.Publication("", "apps.example", "exchange", c.NativePublicKey, c.Nonce)
		},
	} {
		changed := c
		change(&changed)
		if validateApplicationSourceChallenge(changed, request, identity, tuple) == nil {
			t.Fatal("source signed changed selection or original native tuple")
		}
	}
}

func TestRegisteredSourceSigningKeepsFixedExpiryAndIndependentFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		challenge := registeredSDKChallenge()
		originalExpiry := challenge.ExpiresAt
		independent := errors.New("independent source signing failure")
		source := &registeredApplicationSource{selection: challenge.Source, sign: func(ctx context.Context, _ authorityv1.IdentitySourceChallenge) (string, time.Time, error) {
			deadline, ok := ctx.Deadline()
			if !ok || !deadline.Equal(originalExpiry) {
				t.Error("signing extended the fixed native challenge deadline")
			}
			<-ctx.Done()
			return "must-not-escape", time.Now().Add(time.Hour), errors.Join(ctx.Err(), independent)
		}}
		reply, _, err := signApplicationSourceChallenge(t.Context(), source, challenge)
		if reply.Assertion != "" || !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, independent) || challenge.ExpiresAt != originalExpiry {
			t.Fatal("late signing replaced expiry or hid its independent failure", err)
		}
	})
}
