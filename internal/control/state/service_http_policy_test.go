package state

import (
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/credentials"
)

func TestServiceHTTPRunCredentialBoundary(t *testing.T) {
	run := ServiceHTTPRun{Subject: visitorscope.Scope{Kind: visitorscope.Service, ID: "svc_" + strings.Repeat("A", 22)}, RunID: "srun_" + strings.Repeat("A", 22), Number: 1, Token: credentials.ServiceRunToken(strings.Repeat("A", 43))}
	if !run.valid() {
		t.Fatal("canonical managed run credential was rejected")
	}
	publicToken, _, _, err := credentials.NewPublishRunToken()
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{"", publicToken.String(), run.Token.String() + "=", strings.Repeat("A", 42) + "B"} {
		invalid := run
		invalid.Token = credentials.ServiceRunToken(token)
		if invalid.valid() {
			t.Fatal("public or noncanonical token authorized a service HTTP run")
		}
	}
	public := run
	public.Subject = visitorscope.Scope{Kind: visitorscope.PublicURL, ID: "url_" + strings.Repeat("A", 22)}
	if public.valid() {
		t.Fatal("managed token authorized a public URL subject")
	}
}

func TestServiceHTTPRefreshCredentialBoundary(t *testing.T) {
	id := "shg_" + strings.Repeat("A", 22)
	refresh := "vrf1." + id + "." + strings.Repeat("A", 43)
	actualID, digest, err := visitorRefreshDigest(refresh)
	if err != nil || actualID != id || digest != sha256.Sum256([]byte("tnl visitor refresh v1\x00"+refresh)) {
		t.Fatal("refresh credential lost its identity or purpose", err)
	}
	for _, raw := range []string{"", strings.TrimPrefix(refresh, "vrf1."), refresh + "=", strings.Replace(refresh, "shg_", "url_", 1), refresh[:len(refresh)-1] + "B", refresh + ".extra"} {
		if _, _, err := visitorRefreshDigest(raw); err == nil {
			t.Fatal("noncanonical refresh credential accepted")
		}
	}
}
