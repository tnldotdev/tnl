package setup

import (
	"strings"
	"testing"

	installedjobs "github.com/tnldotdev/tnl/internal/installed"
)

func TestPrivateInstallationRejectsRetiredOrBroadenedPayloadBeforeResolvingPrivileges(t *testing.T) {
	for _, payload := range []string{
		`{"job":{"kind":"public","public_url_id":"old"},"credential":{}}`,
		`{"job":{"status":{"public_url":"https://old.example"}},"credential":{}}`,
		`{"job":{"target_ca_pem":""},"credential":{}}`,
		`{"job":{"target_tls_name":"target.example"},"credential":{}}`,
		`{"job":{"limits":{}},"credential":{}}`,
		`{"job":{"verify_readiness":true},"credential":{}}`,
		`{"job":{},"credential":{},"access_token":"operator-session"}`,
		`{"job":{},"credential":{}} {}`,
		strings.Repeat(" ", (512<<10)+1),
	} {
		called := false
		err := RegisterInput(t.Context(), func() (installedjobs.ServiceOptions, error) {
			called = true
			return installedjobs.ServiceOptions{}, nil
		}, strings.NewReader(payload), nil, nil)
		if err == nil || called {
			t.Fatal("unsafe input crossed the private installation boundary", called, err)
		}
	}
}
