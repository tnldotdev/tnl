package visitortoken

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
)

func TestServiceGrantCredentialPreservesIdentityPurposeAndCanonicalEncoding(t *testing.T) {
	id := "shg_" + strings.Repeat("A", 22)
	token, err := GrantToken(id, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	actual, digest, err := GrantTokenDigest(token)
	if err != nil || actual != id || digest != sha256.Sum256([]byte("tnl service grant v1\x00"+token.Reveal())) {
		t.Fatal("service credential lost its identity or purpose", err)
	}
	for _, raw := range []string{"", strings.TrimPrefix(token.Reveal(), "vsg1."), token.Reveal() + "=", strings.Replace(token.Reveal(), "shg_", "url_", 1), token.Reveal()[:len(token)-1] + "B", token.Reveal() + ".extra", strings.Replace(token.Reveal(), "vsg1.", "vrf1.", 1)} {
		if _, _, err := GrantTokenDigest(Token(raw)); !errors.Is(err, ErrToken) {
			t.Fatal("noncanonical or retired credential accepted", err)
		}
	}
}

func TestServiceGrantBearerSurvivesCurrentPolicyRevisionsButNotLostAuthority(t *testing.T) {
	_, _, view, now := tokenFixture(t)
	view.Scope = visitorscope.Scope{Kind: visitorscope.Service, ID: "svc_" + strings.Repeat("A", 22)}
	view.Port = 25443
	id := "shg_" + strings.Repeat("G", 22)
	token, _ := GrantToken(id, bytes.Repeat([]byte{7}, 32))
	_, digest, _ := GrantTokenDigest(token)
	verifier := GrantVerifier{Kind: "token", Digest: digest, ExpiresAt: now.Add(7 * 24 * time.Hour)}
	input := map[string]GrantVerifier{id: verifier}
	view = view.WithGrantVerifiers(input)
	delete(input, id)
	permission, err := VerifyBearer(token, view, now)
	if err != nil || permission.Facts().Subject != (Grant{GrantID: id, Kind: "token"}) {
		t.Fatal("service bearer denied", err)
	}
	at := now.Add(6 * 24 * time.Hour)
	view.VisitorPolicyRevision++
	view.ObservedAt, view.ValidUntil = at, at.Add(PolicyLifetime)
	if _, err := VerifyBearer(token, view, at); err != nil {
		t.Fatal("saved service credential needed replacement", err)
	}
	if err := CheckCurrent(permission, view, at); err != nil {
		t.Fatal("unrelated policy revision canceled live service credential", err)
	}
	short := verifier
	short.ExpiresAt = at.Add(time.Second)
	view = view.WithGrantVerifiers(map[string]GrantVerifier{id: short})
	if !PermissionDeadline(permission, view).Equal(short.ExpiresAt) {
		t.Fatal("shortened current parent deadline ignored")
	}
	for _, replacement := range []map[string]GrantVerifier{nil, {id: {Kind: "share", Digest: digest, ExpiresAt: verifier.ExpiresAt}}, {id: {Kind: "token", Digest: sha256.Sum256([]byte("wrong")), ExpiresAt: verifier.ExpiresAt}}} {
		if err := CheckCurrent(permission, view.WithGrantVerifiers(replacement), at); !errors.Is(err, ErrToken) {
			t.Fatal("old evidence retained changed/revoked grant", err)
		}
	}
	if _, err := VerifyBearer(token, view, view.ValidUntil); !errors.Is(err, ErrPolicy) {
		t.Fatal("grant survived policy outage", err)
	}
	public := view
	public.Scope = visitorscope.Scope{Kind: visitorscope.PublicURL, ID: "url_" + strings.Repeat("A", 22)}
	public.Port = 443
	if _, err := VerifyBearer(token, public, at); !errors.Is(err, ErrToken) {
		t.Fatal("service grant became a public URL share", err)
	}
}
