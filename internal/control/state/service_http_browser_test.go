package state

import (
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
			t.Fatal("public or noncanonical token authorized a service browser operation")
		}
	}
	public := run
	public.Subject = visitorscope.Scope{Kind: visitorscope.PublicURL, ID: "url_" + strings.Repeat("A", 22)}
	if public.valid() {
		t.Fatal("managed token authorized a public URL subject")
	}
}
