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

func TestDecodeDurableVerifiersRejectsIncompleteAndCrossScopeAuthority(t *testing.T) {
	for _, kind := range []string{"share", "grant"} {
		for _, fault := range []string{"valid", "short digest", "long digest", "zero digest", "duplicate", "ID", "expiry", "scope", "overflow", "kind"} {
			t.Run(kind+"/"+fault, func(t *testing.T) {
				now := time.Now()
				secret := bytes.Repeat([]byte{9}, 32)
				id := "shr_" + strings.Repeat("A", 22)
				token, _ := visitortoken.ShareToken(id, secret)
				digest := sha256.Sum256(secret)
				resource := controlv1.VisitorResourceScope{Kind: "public_url", Id: "url_" + strings.Repeat("A", 22)}
				if kind == "grant" {
					id = "shg_" + strings.Repeat("A", 22)
					token, _ = visitortoken.GrantToken(id, secret)
					_, digest, _ = visitortoken.GrantTokenDigest(token)
					resource = controlv1.VisitorResourceScope{Kind: "service", Id: "svc_" + strings.Repeat("A", 22)}
				}
				wireDigest := bytes.Clone(digest[:])
				deadline := now.Add(7 * 24 * time.Hour)
				switch fault {
				case "short digest":
					wireDigest = make([]byte, 31)
				case "long digest":
					wireDigest = make([]byte, 33)
				case "zero digest":
					wireDigest = make([]byte, 32)
				case "ID":
					id = "invalid"
				case "expiry":
					deadline = time.Time{}
				case "scope":
					if kind == "share" {
						resource = controlv1.VisitorResourceScope{Kind: "service", Id: "svc_" + strings.Repeat("A", 22)}
					} else {
						resource = controlv1.VisitorResourceScope{Kind: "public_url", Id: "url_" + strings.Repeat("A", 22)}
					}
				}
				body := controlv1.VisitorPolicyUpdate{Policy: controlv1.VisitorPolicySnapshot{Resource: resource, Hostname: "preview.example.test", Port: 443, Issuer: "https://control.example.test", VisitorPolicyRevision: 1, ObservedAt: now, ValidUntil: now.Add(visitortoken.PolicyLifetime)}}
				count := 1
				if fault == "duplicate" {
					count = 2
				}
				if fault == "overflow" {
					count = 257
				}
				for range count {
					if kind == "share" {
						body.Policy.ShareVerifiers = append(body.Policy.ShareVerifiers, controlv1.VisitorShareVerifier{ShareId: id, SecretDigest: wireDigest, ExpiresAt: deadline})
					} else {
						grantKind := controlv1.VisitorGrantVerifierKind("token")
						if fault == "kind" {
							grantKind = "unknown"
						}
						body.Policy.GrantVerifiers = append(body.Policy.GrantVerifiers, controlv1.VisitorGrantVerifier{GrantId: id, Kind: grantKind, SecretDigest: wireDigest, ExpiresAt: deadline})
					}
				}
				update, err := Decode(body)
				if fault != "valid" && !(kind == "share" && fault == "kind") {
					if !errors.Is(err, ErrUpdate) {
						t.Fatal("invalid verifier decoded", err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				wireDigest[0] ^= 1
				if _, err := visitortoken.VerifyBearer(token, update.View, now); err != nil {
					t.Fatal("wire mutation changed installed snapshot", err)
				}
			})
		}
	}
}
