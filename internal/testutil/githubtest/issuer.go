// package githubtest serves signed GitHub workload fixtures without allowing
// tests to substitute a production issuer or contact GitHub.
package githubtest

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/tnldotdev/tnl/internal/control/oidc"
)

type Issuer struct {
	key    *rsa.PrivateKey
	Client *http.Client
}

func New(t *testing.T) *Issuer {
	return NewProvider(t, oidc.GitHubIssuer)
}

// NewProvider keeps the production issuer and redirects only its key fetches.
func NewProvider(t *testing.T, issuer string) *Issuer {
	t.Helper()
	trusted, err := url.Parse(issuer)
	if err != nil || trusted.Scheme != "https" || trusted.Host == "" {
		t.Fatal("invalid fixture issuer")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/.well-known/jwks") {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "github-test", Algorithm: "RS256", Use: "sig"}}})
	}))
	t.Cleanup(server.Close)
	target, _ := url.Parse(server.URL)
	client := server.Client()
	client.Transport = transport{base: client.Transport, target: target, issuer: trusted}
	return &Issuer{key: key, Client: client}
}

type transport struct {
	base   http.RoundTripper
	target *url.URL
	issuer *url.URL
}

func (t transport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "https" || r.URL.Host != t.issuer.Host || r.URL.Path != strings.TrimSuffix(t.issuer.Path, "/")+"/.well-known/jwks" {
		return nil, &url.Error{Op: "fixture", URL: "", Err: http.ErrNotSupported}
	}
	copy := r.Clone(r.Context())
	u := *r.URL
	u.Scheme = t.target.Scheme
	u.Host = t.target.Host
	copy.URL = &u
	copy.Host = t.target.Host
	return t.base.RoundTrip(copy)
}

func (i *Issuer) Sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: i.key}, (&jose.SignerOptions{}).WithHeader("kid", "github-test"))
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign(data)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func Claims(audience string, now time.Time) map[string]any {
	return map[string]any{
		"iss": oidc.GitHubIssuer, "aud": audience, "sub": "repo:example/repository:ref:refs/heads/main", "jti": "job-assertion-one", "iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		"repository": "example/repository", "repository_id": "12345", "repository_owner_id": "6789", "workflow_ref": "example/repository/.github/workflows/test.yml@refs/heads/main", "ref": "refs/heads/main", "event_name": "push", "run_id": "111", "run_attempt": "1", "check_run_id": "222",
	}
}
