package oidc

import (
	"errors"
	"testing"
	"time"
)

func TestVerifierCompanyContextRequiresSignedTypedClaims(t *testing.T) {
	p := newTestProvider(t, "/company")
	v, err := NewVerifier(VerifierConfig{Issuer: p.issuer, ClientID: "tnl-cli", HTTPClient: p.client})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	proof := TeamContext{TeamID: "team_company", IdentityConnectionID: "icn_company", ConnectionRevision: 3, SourceID: "source-company", Subject: "directory-subject", AuthenticatedAt: now.Unix()}
	sign := func(value any) string {
		return p.signer.Token(t, "key-1", map[string]any{"iss": p.issuer, "sub": "identity-subject", "aud": "tnl-cli", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "tnl_team_contexts": value})
	}
	identity, err := v.Verify(loginTestContext(t), sign([]TeamContext{proof}))
	if err != nil || len(identity.TeamContexts) != 1 || identity.TeamContexts[0] != proof {
		t.Fatal("signed context lost", identity, err)
	}
	for _, bad := range []any{true, map[string]any{"company_authenticated": true}, []TeamContext{proof, proof}, []map[string]any{{"team_id": proof.TeamID, "identity_connection_id": proof.IdentityConnectionID, "connection_revision": "3", "subject": proof.Subject, "authenticated_at": proof.AuthenticatedAt}}, []TeamContext{{TeamID: "team_company", IdentityConnectionID: "icn_company", ConnectionRevision: 3, Subject: "directory-subject"}}} {
		if _, err = v.Verify(loginTestContext(t), sign(bad)); !errors.Is(err, ErrUnauthenticated) {
			t.Fatal("malformed signed context accepted", err)
		}
	}
}
