package visitortoken

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
)

func tokenFixture(t *testing.T) (ed25519.PrivateKey, Permission, View, time.Time) {
	t.Helper()
	now := time.Unix(1_800_000_000, 0).UTC()
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("k", ed25519.SeedSize)))
	permission := Permission{Scope: visitorscope.Scope{Kind: visitorscope.PublicURL, ID: "url_" + strings.Repeat("A", 22)}, Hostname: "preview.example.test", Port: 443,
		VisitorPolicyRevision: 7, Subject: Browser{IdentityID: "ident_" + strings.Repeat("A", 22), SessionID: "cs_" + strings.Repeat("B", 22)}, ExpiresAt: now.Add(RenewableLifetime)}
	view := View{Issuer: "https://control.example.test", Scope: permission.Scope, Hostname: permission.Hostname, Port: permission.Port,
		VisitorPolicyRevision: permission.VisitorPolicyRevision, ObservedAt: now, ValidUntil: now.Add(PolicyLifetime), Keys: map[string]ed25519.PublicKey{"key-one": key.Public().(ed25519.PublicKey)}}
	return key, permission, view, now
}

func issueToken(t *testing.T, key ed25519.PrivateKey, permission Permission, view View, now time.Time) Token {
	t.Helper()
	token, err := Sign(view.Issuer, "key-one", key, permission, now)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestVisitorTokensUseExactCurrentResourceAndServer(t *testing.T) {
	key, permission, view, now := tokenFixture(t)
	for _, kind := range []visitorscope.Kind{visitorscope.PublicURL, visitorscope.Service} {
		t.Run(string(kind), func(t *testing.T) {
			if kind == visitorscope.Service {
				permission.Scope, permission.Port = visitorscope.Scope{Kind: kind, ID: "svc_" + strings.Repeat("A", 22)}, 5432
				view.Scope, view.Port = permission.Scope, permission.Port
			}
			token := issueToken(t, key, permission, view, now)
			got, err := VerifyBearer(token, view, now.Add(time.Second))
			if err != nil || got.Scope != permission.Scope || got.Subject != permission.Subject || !got.ExpiresAt.Equal(permission.ExpiresAt) {
				t.Fatalf("permission mismatch: %+v, %v", got, err)
			}
			for name, change := range map[string]func(*View){
				"issuer":   func(v *View) { v.Issuer = "https://other.example.test" },
				"resource": func(v *View) { v.Scope.ID = strings.ReplaceAll(v.Scope.ID, "A", "B") },
				"hostname": func(v *View) { v.Hostname = "other.example.test" },
				"port": func(v *View) {
					if v.Port == 443 {
						v.Port = 8443
					} else {
						v.Port++
					}
				},
				"revision":       func(v *View) { v.VisitorPolicyRevision++ },
				"older-revision": func(v *View) { v.VisitorPolicyRevision-- },
				"kind": func(v *View) {
					if v.Scope.Kind == visitorscope.PublicURL {
						v.Scope = visitorscope.Scope{Kind: visitorscope.Service, ID: "svc_" + strings.Repeat("A", 22)}
					} else {
						v.Scope = visitorscope.Scope{Kind: visitorscope.PublicURL, ID: "url_" + strings.Repeat("A", 22)}
						v.Port = 443
					}
				},
				"missing-key": func(v *View) { v.Keys = nil },
				"wrong-key": func(v *View) {
					v.Keys = map[string]ed25519.PublicKey{"key-one": ed25519.NewKeyFromSeed([]byte(strings.Repeat("x", 32))).Public().(ed25519.PublicKey)}
				},
				"expired-policy":     func(v *View) { v.ValidUntil = now.Add(time.Second) },
				"oversized-lease":    func(v *View) { v.ValidUntil = now.Add(PolicyLifetime + time.Nanosecond) },
				"future-observation": func(v *View) { v.ObservedAt = now.Add(2 * time.Second) },
			} {
				t.Run(name, func(t *testing.T) {
					changed := view
					change(&changed)
					if _, err := VerifyBearer(token, changed, now.Add(time.Second)); err == nil {
						t.Fatal("accepted token at wrong trust boundary")
					}
				})
			}
		})
	}
}

func TestTokenExpiryIsIndependentOfPolicyFreshness(t *testing.T) {
	key, permission, view, now := tokenFixture(t)
	token := issueToken(t, key, permission, view, now)
	if _, err := VerifyBearer(token, view, now.Add(PolicyLifetime)); !errors.Is(err, ErrPolicy) {
		t.Fatal("token extended expired policy", err)
	}
	view.ObservedAt, view.ValidUntil = now.Add(time.Minute), now.Add(time.Minute+PolicyLifetime)
	if _, err := VerifyBearer(token, view, now.Add(time.Minute)); err != nil {
		t.Fatal("current policy required ten-second token renewal", err)
	}
	view.ObservedAt, view.ValidUntil = permission.ExpiresAt, permission.ExpiresAt.Add(PolicyLifetime)
	if _, err := VerifyBearer(token, view, permission.ExpiresAt); !errors.Is(err, ErrToken) {
		t.Fatal("expired token accepted under current policy", err)
	}
	if _, err := VerifyBearer(token, view, now.Add(-time.Second)); err == nil {
		t.Fatal("future token accepted")
	}
}

func TestTokenClaimsAreClosedBoundedAndNeverLegacyCredentials(t *testing.T) {
	key, permission, view, now := tokenFixture(t)
	token := issueToken(t, key, permission, view, now)
	parts := strings.Split(token.Reveal(), ".")
	signed, err := jose.ParseSigned(token.Reveal(), []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := signed.Verify(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	sign := func(payload []byte, tokenType string) Token {
		t.Helper()
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: key}, (&jose.SignerOptions{}).WithType(jose.ContentType(tokenType)).WithHeader("kid", "key-one"))
		if err != nil {
			t.Fatal(err)
		}
		signed, err := signer.Sign(payload)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := signed.CompactSerialize()
		if err != nil {
			t.Fatal(err)
		}
		return Token(raw)
	}
	for name, invalid := range map[string]Token{
		"opaque-cookie":   Token(strings.Repeat("A", 43)),
		"too-large":       Token(strings.Repeat("A", MaxTokenBytes+1)),
		"signature":       Token(parts[0] + "." + parts[1] + "." + strings.Repeat("A", 86)),
		"wrong-type":      sign(payload, "JWT"),
		"unknown-field":   sign(append([]byte(`{"extra":true,`), payload[1:]...), Type),
		"duplicate":       sign(append([]byte(`{"version":1,`), payload[1:]...), Type),
		"duplicate-scope": sign([]byte(strings.Replace(string(payload), `"kind":"public_url"`, `"kind":"public_url","kind":"public_url"`, 1)), Type),
		"unknown-variant": sign([]byte(strings.Replace(string(payload), `"kind":"browser"`, `"kind":"publisher"`, 1)), Type),
		"mixed-variant":   sign([]byte(strings.Replace(string(payload), `"identity_id":`, `"device_id":"vdev_`+strings.Repeat("A", 22)+`","identity_id":`, 1)), Type),
		"wrong-subject":   sign([]byte(strings.Replace(string(payload), `"ident_`+strings.Repeat("A", 22)+`"`, `"pub_`+strings.Repeat("A", 22)+`"`, 1)), Type),
		"trailing":        sign(append(payload, []byte(` {}`)...), Type),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyBearer(invalid, view, now); !errors.Is(err, ErrToken) {
				t.Fatal("invalid token did not fail closed", err)
			}
		})
	}
	if len(token.Reveal()) > MaxTokenBytes || strings.Contains(fmt.Sprintf("%v %#v", token, token), token.Reveal()) {
		t.Fatal("token exceeds bound or formatting exposes credentials")
	}
	var restored claims
	if json.Unmarshal(payload, &restored) != nil || restored.Expires-restored.Issued != int64(RenewableLifetime/time.Second) {
		t.Fatal("incorrect issued deadline")
	}
}

func TestNativeProofBindsKeySessionConnectionAndOpeningBytes(t *testing.T) {
	key, permission, view, now := tokenFixture(t)
	visitor := ed25519.NewKeyFromSeed([]byte(strings.Repeat("v", 32)))
	public := visitor.Public().(ed25519.PublicKey)
	digest, err := KeyDigest(public)
	if err != nil {
		t.Fatal(err)
	}
	permission.Scope, permission.Port = visitorscope.Scope{Kind: visitorscope.Service, ID: "svc_" + strings.Repeat("A", 22)}, 5432
	view.Scope, view.Port = permission.Scope, permission.Port
	session, connection := "cns_"+strings.Repeat("A", 22), "vc_"+strings.Repeat("B", 22)
	initial := []byte("original client hello")
	for name, subject := range map[string]Subject{
		"device":   Device{IdentityID: "ident_" + strings.Repeat("A", 22), SessionID: "cs_" + strings.Repeat("B", 22), DeviceID: "vdev_" + strings.Repeat("C", 22), KeySHA256: digest},
		"workload": Workload{SessionID: "wls_" + strings.Repeat("D", 22), KeySHA256: digest},
	} {
		t.Run(name, func(t *testing.T) {
			permission.Subject = subject
			token := issueToken(t, key, permission, view, now)
			message, err := NativeProofMessage(token, session, connection, initial)
			if err != nil {
				t.Fatal(err)
			}
			signature := ed25519.Sign(visitor, message)
			if _, err := VerifyNative(token, view, subject, session, connection, initial, public, signature, now); err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyBearer(token, view, now); !errors.Is(err, ErrBinding) {
				t.Fatal("native token became a bearer credential", err)
			}
			for _, wrong := range []struct {
				session, connection string
				initial             []byte
				public              ed25519.PublicKey
				signature           []byte
			}{
				{strings.ReplaceAll(session, "A", "Z"), connection, initial, public, signature},
				{session, strings.ReplaceAll(connection, "B", "Z"), initial, public, signature},
				{session, connection, []byte("changed hello"), public, signature},
				{session, connection, initial, key.Public().(ed25519.PublicKey), signature},
				{session, connection, initial, public, nil},
			} {
				if _, err := VerifyNative(token, view, subject, wrong.session, wrong.connection, wrong.initial, wrong.public, wrong.signature, now); !errors.Is(err, ErrBinding) {
					t.Fatal("wrong native binding accepted", err)
				}
			}
			if _, err := VerifyNative(token, view, Browser{IdentityID: "ident_" + strings.Repeat("A", 22), SessionID: "cs_" + strings.Repeat("B", 22)}, session, connection, initial, public, signature, now); !errors.Is(err, ErrBinding) {
				t.Fatal("native permission changed its authenticated session subject", err)
			}
		})
	}
}
