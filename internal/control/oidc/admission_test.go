package oidc

import (
	"errors"
	"testing"
	"time"
)

func TestDirectAdmissionUsesVerifiedTypedClaims(t *testing.T) {
	p := newTestProvider(t, "")
	v, err := NewVerifier(VerifierConfig{Issuer: p.issuer, ClientID: "server", HTTPClient: p.client})
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{"iss": p.issuer, "sub": "exact-subject", "aud": "server", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(), "auth_time": time.Now().Unix(), "tid": "tenant-a", "groups": []string{"engineering"}, "email": "shared@example.test", "email_verified": true}
	i, err := v.Verify(t.Context(), p.signer.Token(t, "key-1", claims))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		rule AdmissionRule
		want bool
	}{
		{AdmissionRule{Subjects: []string{"exact-subject"}}, true},
		{AdmissionRule{Subjects: []string{"shared@example.test"}}, false},
		{AdmissionRule{Claim: &AdmissionClaim{Name: TenantClaim, Value: "tenant-a"}}, true},
		{AdmissionRule{Claim: &AdmissionClaim{Name: TenantClaim, Value: "tenant-b"}}, false},
		{AdmissionRule{Claim: &AdmissionClaim{Name: GroupClaim, Value: "engineering"}}, true},
		{AdmissionRule{Claim: &AdmissionClaim{Name: HostedDomainClaim, Value: "example.test"}}, false},
	} {
		if got := test.rule.Allows(i); got != test.want {
			t.Fatalf("admission=%t want=%t", got, test.want)
		}
	}
	claims["tid"] = []string{"tenant-a"}
	if _, err := v.Verify(t.Context(), p.signer.Token(t, "key-1", claims)); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("malformed trusted tenant claim: %v", err)
	}
}
