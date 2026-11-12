package httpaccess_test

import (
	"encoding/json"
	"testing"

	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	"github.com/tnldotdev/tnl/internal/security/credentials"
)

type runtimeJSONClient struct {
	httpaccess.BrowserClient
	httpaccess.ShareClient
	Secret string
}

func TestBrowserAndSharesJSONKeepsRuntimeCredentialsPrivate(t *testing.T) {
	client := &runtimeJSONClient{Secret: "fixture-client-secret"}
	token := credentials.PublishRunToken("fixture-publish-run-secret")
	browser := httpaccess.Browser{Client: client, Token: token, Tokens: &httpaccess.Tokens{}, Policy: &httpaccess.Policy{}}
	shares := httpaccess.Shares{Client: client, Token: token, Browser: &browser, Logf: func(string, ...any) {
		t.Error("JSON encoding called the run logger")
	}}
	for _, test := range []struct {
		name  string
		value any
		want  string
	}{
		{"browser value", browser, "{}"},
		{"browser pointer", &browser, "{}"},
		{"shares value", shares, "{}"},
		{"shares pointer", &shares, "{}"},
		{"server config fields", struct {
			BrowserAccess *httpaccess.Browser
			ShareAccess   *httpaccess.Shares
		}{&browser, &shares}, `{"BrowserAccess":{},"ShareAccess":{}}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := json.Marshal(test.value)
			if err != nil {
				t.Fatal("runtime holder could not be encoded as an opaque object", err)
			}
			if string(encoded) != test.want {
				t.Fatal("runtime holder exposed its credentials or live clients in JSON")
			}
		})
	}
	if browser.Token.String() != string(token) || shares.Token.String() != string(token) {
		t.Fatal("snapshot redaction changed the token used for authentication")
	}
}
