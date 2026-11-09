package visitortoken

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
)

func shareFixture(t *testing.T) (Token, View, time.Time, string, ShareVerifier) {
	t.Helper()
	_, _, view, now := tokenFixture(t)
	id := "shr_" + strings.Repeat("S", 22)
	secret := bytes.Repeat([]byte{7}, 32)
	token, err := ShareToken(id, secret)
	if err != nil {
		t.Fatal(err)
	}
	verifier := ShareVerifier{Digest: sha256.Sum256(secret), ExpiresAt: now.Add(7 * 24 * time.Hour)}
	return token, view.WithShareVerifiers(map[string]ShareVerifier{id: verifier}), now, id, verifier
}

func TestOpaqueShareTokenSurvivesSevenDaysOfCurrentPolicyWithoutExchange(t *testing.T) {
	token, view, now, id, verifier := shareFixture(t)
	permission, err := VerifyBearer(token, view, now)
	if err != nil || !permission.Valid() || permission.Facts().Subject != (Share{ShareID: id}) {
		t.Fatal("share verification failed", err)
	}
	for _, elapsed := range []time.Duration{time.Minute, 6 * time.Hour, 24 * time.Hour, 7*24*time.Hour - time.Second} {
		at := now.Add(elapsed)
		view.VisitorPolicyRevision++
		view.ObservedAt, view.ValidUntil = at, at.Add(PolicyLifetime)
		view = view.WithVerificationKeys(nil)
		if _, err := VerifyBearer(token, view, at); err != nil {
			t.Fatal("the exact share token required replacement", err)
		}
		if err := CheckCurrent(permission, view, at); err != nil {
			t.Fatal("unrelated revision or signing-key rotation revoked a live share", err)
		}
	}
	view.ObservedAt, view.ValidUntil = verifier.ExpiresAt, verifier.ExpiresAt.Add(PolicyLifetime)
	if _, err := VerifyBearer(token, view, verifier.ExpiresAt); !errors.Is(err, ErrToken) {
		t.Fatal("share outlived advertised expiry", err)
	}
}

func TestOpaqueShareRequiresCurrentExactAuthorityAndPossession(t *testing.T) {
	token, view, now, id, verifier := shareFixture(t)
	permission, err := VerifyBearer(token, view, now)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*View){
		"revoked": func(v *View) { *v = v.WithShareVerifiers(nil) },
		"replaced verifier": func(v *View) {
			other := verifier
			other.Digest[0] ^= 1
			*v = v.WithShareVerifiers(map[string]ShareVerifier{id: other})
		},
		"expired parent": func(v *View) {
			other := verifier
			other.ExpiresAt = now
			*v = v.WithShareVerifiers(map[string]ShareVerifier{id: other})
		},
		"resource": func(v *View) { v.Scope.ID = "url_" + strings.Repeat("B", 22); *v = v.WithShareVerifiers(nil) },
		"service": func(v *View) {
			v.Scope = visitorscope.Scope{Kind: visitorscope.Service, ID: "svc_" + strings.Repeat("A", 22)}
		},
	} {
		t.Run(name, func(t *testing.T) {
			other := view
			change(&other)
			if _, err := VerifyBearer(token, other, now); !errors.Is(err, ErrToken) {
				t.Fatal("share accepted without current authority", err)
			}
			if err := CheckCurrent(permission, other, now); !errors.Is(err, ErrToken) {
				t.Fatal("old evidence retained authority", err)
			}
		})
	}
	if _, err := VerifyBearer(token, view, view.ValidUntil); !errors.Is(err, ErrPolicy) {
		t.Fatal("policy outage retained admission", err)
	}
	if err := CheckCurrent(permission, view, view.ValidUntil); !errors.Is(err, ErrPolicy) {
		t.Fatal("policy outage retained active traffic", err)
	}
	wrong, _ := ShareToken(id, bytes.Repeat([]byte{8}, 32))
	if _, err := VerifyBearer(wrong, view, now); !errors.Is(err, ErrToken) {
		t.Fatal("wrong secret accepted", err)
	}
	short := verifier
	short.ExpiresAt = now.Add(time.Second)
	view = view.WithShareVerifiers(map[string]ShareVerifier{id: short})
	if !PermissionDeadline(permission, view).Equal(short.ExpiresAt) {
		t.Fatal("current parent deadline was ignored")
	}
}

func TestOpaqueShareSnapshotsDetachInputsAndTokensRedactFormatting(t *testing.T) {
	token, view, now, id, verifier := shareFixture(t)
	input := map[string]ShareVerifier{id: verifier}
	view = view.WithShareVerifiers(input)
	delete(input, id)
	if _, err := VerifyBearer(token, view, now); err != nil {
		t.Fatal("caller mutated installed authority", err)
	}
	for _, formatted := range []string{fmt.Sprint(token), fmt.Sprintf("%+v", token), fmt.Sprintf("%#v", token)} {
		if strings.Contains(formatted, token.Reveal()) || strings.Contains(formatted, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))) {
			t.Fatal("formatting disclosed bearer secret")
		}
	}
	for _, invalid := range []Token{"", Token("vsh1." + id + ".bad"), Token(token.Reveal() + "="), Token(token.Reveal() + ".extra"), Token("vsh1.invalid." + strings.Repeat("A", 43)), Token("vsh1." + id + "." + strings.Repeat("A", 42) + "B"), Token("vsh1." + strings.Repeat("A", MaxTokenBytes))} {
		if _, err := VerifyBearer(invalid, view, now); !errors.Is(err, ErrToken) {
			t.Fatal("malformed token accepted", err)
		}
	}
	if _, err := ShareToken("bad", make([]byte, 32)); !errors.Is(err, ErrToken) {
		t.Fatal("invalid ID encoded")
	}
	if _, err := ShareToken(id, make([]byte, 31)); !errors.Is(err, ErrToken) {
		t.Fatal("short secret encoded")
	}
}
