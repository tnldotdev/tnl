package visitorlease

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestDecodeShareVerifiersRejectsIncompleteOrAmbiguousAuthority(t *testing.T) {
	now := time.Now()
	id := "shr_" + strings.Repeat("A", 22)
	secret := bytes.Repeat([]byte{9}, 32)
	digest := sha256.Sum256(secret)
	for _, fault := range []string{"valid", "short digest", "long digest", "zero digest", "duplicate", "ID", "expiry", "service", "overflow"} {
		t.Run(fault, func(t *testing.T) {
			body := controlv1.VisitorPolicyUpdate{Policy: controlv1.VisitorPolicySnapshot{Resource: controlv1.VisitorResourceScope{Kind: "public_url", Id: "url_" + strings.Repeat("A", 22)}, Hostname: "preview.example.test", Port: 443, Issuer: "https://control.example.test", VisitorPolicyRevision: 1, ObservedAt: now, ValidUntil: now.Add(visitortoken.PolicyLifetime), ShareVerifiers: []controlv1.VisitorShareVerifier{{ShareId: id, SecretDigest: bytes.Clone(digest[:]), ExpiresAt: now.Add(7 * 24 * time.Hour)}}}}
			verifier := &body.Policy.ShareVerifiers[0]
			switch fault {
			case "short digest":
				verifier.SecretDigest = make([]byte, 31)
			case "long digest":
				verifier.SecretDigest = make([]byte, 33)
			case "zero digest":
				verifier.SecretDigest = make([]byte, 32)
			case "duplicate":
				body.Policy.ShareVerifiers = append(body.Policy.ShareVerifiers, *verifier)
			case "ID":
				verifier.ShareId = "invalid"
			case "expiry":
				verifier.ExpiresAt = time.Time{}
			case "service":
				body.Policy.Resource = controlv1.VisitorResourceScope{Kind: "service", Id: "svc_" + strings.Repeat("A", 22)}
			case "overflow":
				body.Policy.ShareVerifiers = make([]controlv1.VisitorShareVerifier, 257)
			}
			update, err := Decode(body)
			if fault != "valid" {
				if !errors.Is(err, ErrUpdate) {
					t.Fatal("invalid share authority decoded", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			verifier.SecretDigest[0] ^= 1
			body.Policy.ShareVerifiers = nil
			token, _ := visitortoken.ShareToken(id, secret)
			if _, err := visitortoken.VerifyBearer(token, update.View, now); err != nil {
				t.Fatal("wire buffer mutated decoded snapshot", err)
			}
		})
	}
}
