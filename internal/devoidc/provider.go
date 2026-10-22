// Package devoidc is a local development OIDC provider. it has one explicitly
// named account and must only listen on a development machine or private stack.
package devoidc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type Config struct {
	Issuer, ClientID, ClientSecret, Subject string
	RedirectURLs                            []string
}
type grant struct {
	challenge, nonce, redirect string
	expires                    time.Time
}
type Provider struct {
	config Config
	signer jose.Signer
	key    jose.JSONWebKey
	mu     sync.Mutex
	grants map[string]grant
}

func New(c Config) (*Provider, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "local"))
	if err != nil {
		return nil, err
	}
	return &Provider{config: c, signer: signer, key: jose.JSONWebKey{Key: &key.PublicKey, KeyID: "local", Algorithm: "RS256", Use: "sig"}, grants: map[string]grant{}}, nil
}

func (p *Provider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	switch r.Method + " " + r.URL.Path {
	case "GET /.well-known/openid-configuration":
		p.json(w, map[string]any{"issuer": p.config.Issuer, "authorization_endpoint": p.config.Issuer + "/authorize", "token_endpoint": p.config.Issuer + "/token", "jwks_uri": p.config.Issuer + "/keys", "response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256"}, "code_challenge_methods_supported": []string{"S256"}, "token_endpoint_auth_methods_supported": []string{"client_secret_post", "none"}})
	case "GET /keys":
		p.json(w, map[string]any{"keys": []jose.JSONWebKey{p.key}})
	case "GET /authorize":
		if !p.validAuthorization(r.URL.Query()) {
			http.Error(w, "invalid authorization", 400)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = loginPage.Execute(w, struct {
			Subject string
			Fields  url.Values
		}{p.config.Subject, r.URL.Query()})
	case "POST /authorize":
		r.Body = http.MaxBytesReader(w, r.Body, 8192)
		if r.ParseForm() != nil || !p.validAuthorization(r.PostForm) {
			http.Error(w, "invalid authorization", 400)
			return
		}
		var material [32]byte
		if _, err := rand.Read(material[:]); err != nil {
			http.Error(w, "random source unavailable", http.StatusServiceUnavailable)
			return
		}
		code := base64.RawURLEncoding.EncodeToString(material[:])
		now := time.Now()
		p.mu.Lock()
		for key, g := range p.grants {
			if !g.expires.After(now) {
				delete(p.grants, key)
			}
		}
		if len(p.grants) >= 1024 {
			p.mu.Unlock()
			http.Error(w, "too many pending logins", http.StatusTooManyRequests)
			return
		}
		p.grants[code] = grant{r.PostForm.Get("code_challenge"), r.PostForm.Get("nonce"), r.PostForm.Get("redirect_uri"), now.Add(time.Minute)}
		p.mu.Unlock()
		u, _ := url.Parse(r.PostForm.Get("redirect_uri"))
		q := u.Query()
		q.Set("state", r.PostForm.Get("state"))
		q.Set("code", code)
		u.RawQuery = q.Encode()
		http.Redirect(w, r, u.String(), http.StatusSeeOther)
	case "POST /token":
		w.Header().Set("Content-Type", "application/json")
		r.Body = http.MaxBytesReader(w, r.Body, 8192)
		if r.ParseForm() != nil || r.PostForm.Get("client_id") != p.config.ClientID || subtle.ConstantTimeCompare([]byte(r.PostForm.Get("client_secret")), []byte(p.config.ClientSecret)) != 1 {
			w.WriteHeader(401)
			p.json(w, map[string]string{"error": "invalid_client"})
			return
		}
		p.mu.Lock()
		g, ok := p.grants[r.PostForm.Get("code")]
		delete(p.grants, r.PostForm.Get("code"))
		p.mu.Unlock()
		digest := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if !ok || !g.expires.After(time.Now()) || r.PostForm.Get("grant_type") != "authorization_code" || r.PostForm.Get("redirect_uri") != g.redirect || base64.RawURLEncoding.EncodeToString(digest[:]) != g.challenge {
			w.WriteHeader(400)
			p.json(w, map[string]string{"error": "invalid_grant"})
			return
		}
		now := time.Now()
		raw, err := jwt.Signed(p.signer).Claims(map[string]any{"iss": p.config.Issuer, "sub": p.config.Subject, "name": p.config.Subject, "aud": p.config.ClientID, "iat": now.Unix(), "auth_time": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "nonce": g.nonce}).Serialize()
		if err != nil {
			http.Error(w, "signing unavailable", http.StatusServiceUnavailable)
			return
		}
		p.json(w, map[string]any{"id_token": raw, "access_token": "unused-local-provider-token", "token_type": "Bearer", "expires_in": 300})
	default:
		http.NotFound(w, r)
	}
}
func (p *Provider) json(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
func (p *Provider) validAuthorization(q url.Values) bool {
	allowed := false
	for _, redirect := range p.config.RedirectURLs {
		if q.Get("redirect_uri") == redirect {
			allowed = true
		}
	}
	return allowed && q.Get("client_id") == p.config.ClientID && q.Get("response_type") == "code" && q.Get("code_challenge_method") == "S256" && len(q.Get("code_challenge")) == 43 && len(q.Get("nonce")) == 43 && len(q.Get("state")) >= 32 && len(q.Encode()) <= 8192
}

var loginPage = template.Must(template.New("login").Parse(`<!doctype html><html><head><title>local tnl identity</title></head><body><h1>local development sign-in</h1><p>sign in as {{.Subject}}</p><form method="post" action="/authorize">{{range $key,$values := .Fields}}{{range $values}}<input type="hidden" name="{{$key}}" value="{{.}}">{{end}}{{end}}<button>sign in</button></form></body></html>`))
