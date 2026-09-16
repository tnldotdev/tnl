package clientauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/oidcauth"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"golang.org/x/oauth2"
)

func TestInteractiveLoginHasBoundedTimeout(t *testing.T) {
	source := testOIDCTokenSource(t)
	source.config.loginTimeout = 25 * time.Millisecond
	_, err := source.login(context.Background())
	if !errors.Is(err, ErrAuthenticationTimeout) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("login error = %v, want authentication timeout", err)
	}
}

func TestInteractiveLoginCancellationIsNotTimeout(t *testing.T) {
	source := testOIDCTokenSource(t)
	ctx, cancel := context.WithCancel(context.Background())
	source.config.AuthenticationPrompt = func(oidcauth.Prompt) error {
		cancel()
		return nil
	}
	_, err := source.login(ctx)
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrAuthenticationTimeout) {
		t.Fatalf("login error = %v, want cancellation without timeout", err)
	}
}

func TestProviderDeviceCodeExpiryIsAuthenticationTimeout(t *testing.T) {
	err := fmt.Errorf("complete login: %w", &oauth2.RetrieveError{ErrorCode: "expired_token"})
	if !interactiveAuthenticationTimedOut(context.Background(), err) {
		t.Fatalf("provider expiry was not classified: %v", err)
	}
	if interactiveAuthenticationTimedOut(context.Background(), &oauth2.RetrieveError{ErrorCode: "access_denied"}) {
		t.Fatal("provider access denial was classified as a timeout")
	}
}

func testOIDCTokenSource(t *testing.T) *tokenSource {
	t.Helper()
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(response, request)
			return
		}
		_ = json.NewEncoder(response).Encode(map[string]any{
			"issuer":                 server.URL,
			"authorization_endpoint": server.URL + "/authorize",
			"token_endpoint":         server.URL + "/token",
			"jwks_uri":               server.URL + "/keys",
		})
	}))
	t.Cleanup(server.Close)
	oidcFacts := &controlv1.OIDCAuthenticationFacts{
		Issuer: server.URL, ClientId: "client", LoginFlow: controlv1.AuthorizationCodePkce,
		Scopes: []string{"openid"},
	}
	return &tokenSource{
		control: control{
			discovery: controlv1.ControlDiscovery{Authentication: controlv1.AuthenticationFacts{
				Methods: []controlv1.AuthenticationFactsMethods{controlv1.Oidc}, Oidc: oidcFacts,
			}},
			rawHTTP: server.Client(),
		},
		config: Config{Diagnostics: io.Discard},
	}
}
