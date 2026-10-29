package visitortoken

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
)

func FuzzVisitorTokenVerification(f *testing.F) {
	now := time.Unix(1_800_000_000, 0).UTC()
	private := ed25519.NewKeyFromSeed([]byte(strings.Repeat("k", 32)))
	permission := Permission{Scope: visitorscope.Scope{Kind: visitorscope.PublicURL, ID: "url_" + strings.Repeat("A", 22)}, Hostname: "preview.example.test", Port: 443, VisitorPolicyRevision: 1,
		Subject: Browser{IdentityID: "ident_" + strings.Repeat("A", 22), SessionID: "cs_" + strings.Repeat("B", 22)}, ExpiresAt: now.Add(time.Minute)}
	view := View{Issuer: "https://control.example.test", Scope: permission.Scope, Hostname: permission.Hostname, Port: permission.Port, VisitorPolicyRevision: 1,
		ObservedAt: now, ValidUntil: now.Add(PolicyLifetime)}.WithVerificationKeys(map[string]ed25519.PublicKey{"test-key": private.Public().(ed25519.PublicKey)})
	token, err := Sign(view.Issuer, "test-key", private, permission, now)
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range []string{"", token.Reveal(), strings.Repeat("A", 43), "e30.e30.e30", strings.Repeat("A", MaxTokenBytes+1)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		_, err := VerifyBearer(Token(raw), view, now)
		if len(raw) > MaxTokenBytes && !errors.Is(err, ErrToken) {
			t.Fatal("oversized credential escaped the token bound")
		}
	})
}
