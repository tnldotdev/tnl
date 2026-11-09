package visitorlease

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestDecodeServiceGrantVerifiersRejectsIncompleteOrCrossScopeAuthority(t *testing.T) {
	now := time.Now()
	id := "shg_" + strings.Repeat("A", 22)
	secret := bytes.Repeat([]byte{9}, 32)
	token, _ := visitortoken.GrantToken(id, secret)
	_, digest, _ := visitortoken.GrantTokenDigest(token)
	for _, fault := range []string{"valid", "short digest", "long digest", "zero digest", "duplicate", "ID", "kind", "expiry", "public URL", "overflow"} {
		t.Run(fault, func(t *testing.T) {
			body := controlv1.VisitorPolicyUpdate{Policy: controlv1.VisitorPolicySnapshot{Resource: controlv1.VisitorResourceScope{Kind: "service", Id: "svc_" + strings.Repeat("A", 22)}, Hostname: "service.example.test", Port: 25443, Issuer: "https://control.example.test", VisitorPolicyRevision: 1, ObservedAt: now, ValidUntil: now.Add(visitortoken.PolicyLifetime), GrantVerifiers: []controlv1.VisitorGrantVerifier{{GrantId: id, Kind: "token", SecretDigest: bytes.Clone(digest[:]), ExpiresAt: now.Add(7 * 24 * time.Hour)}}}}
			verifier := &body.Policy.GrantVerifiers[0]
			switch fault {
			case "short digest":
				verifier.SecretDigest = make([]byte, 31)
			case "long digest":
				verifier.SecretDigest = make([]byte, 33)
			case "zero digest":
				verifier.SecretDigest = make([]byte, 32)
			case "duplicate":
				body.Policy.GrantVerifiers = append(body.Policy.GrantVerifiers, *verifier)
			case "ID":
				verifier.GrantId = "invalid"
			case "kind":
				verifier.Kind = "unknown"
			case "expiry":
				verifier.ExpiresAt = time.Time{}
			case "public URL":
				body.Policy.Resource = controlv1.VisitorResourceScope{Kind: "public_url", Id: "url_" + strings.Repeat("A", 22)}
			case "overflow":
				body.Policy.GrantVerifiers = make([]controlv1.VisitorGrantVerifier, 257)
			}
			update, err := Decode(body)
			if fault != "valid" {
				if !errors.Is(err, ErrUpdate) {
					t.Fatal("invalid grant authority decoded", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			verifier.SecretDigest[0] ^= 1
			body.Policy.GrantVerifiers = nil
			if _, err := visitortoken.VerifyBearer(token, update.View, now); err != nil {
				t.Fatal("wire buffer mutated decoded snapshot", err)
			}
		})
	}
}
