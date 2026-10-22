package controlapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	authorityclient "github.com/tnldotdev/tnl/internal/client/authority"
	authorityapi "github.com/tnldotdev/tnl/internal/control/api/authority"
	oidcauth "github.com/tnldotdev/tnl/internal/control/oidc"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/oidctest"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"golang.org/x/oauth2"
)

const companyWebsiteSecret = "website-secret-01234567890123456789"

type companyHTTPFixture struct {
	t              *testing.T
	d              *controlstate.Database
	sql            *pgx.Conn
	signer         *oidctest.Signer
	issuer, server *httptest.Server
	mux            *http.ServeMux
	now            time.Time
	sequence       int
	mu             sync.Mutex
	browserSubject string
	browserProof   []oidcauth.TeamContext
}

func newCompanyHTTPFixture(t *testing.T, name string) *companyHTTPFixture {
	t.Helper()
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	f := &companyHTTPFixture{t: t, signer: oidctest.NewSigner(t), mux: http.NewServeMux()}
	dbURL := testutil.NewDisposablePostgresDatabaseURL(t, name)
	if err := controlstate.Migrate(t.Context(), dbURL); err != nil {
		t.Fatal(err)
	}
	var err error
	f.d, err = controlstate.Open(t.Context(), dbURL, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.d.Close)
	f.sql, err = pgx.Connect(t.Context(), dbURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.sql.Close(t.Context()) })
	issuerMux := http.NewServeMux()
	grants := map[string]url.Values{}
	issuerMux.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	issuerMux.HandleFunc("POST /authorize", func(w http.ResponseWriter, r *http.Request) {
		if r.ParseForm() != nil || r.PostForm.Get("code_challenge_method") != "S256" || r.PostForm.Get("redirect_uri") != f.server.URL+"/v1/auth/device/callback" {
			http.Error(w, "invalid authorization", 400)
			return
		}
		code := oauth2.GenerateVerifier()
		f.mu.Lock()
		grants[code] = r.PostForm
		f.mu.Unlock()
		u, _ := url.Parse(r.PostForm.Get("redirect_uri"))
		q := u.Query()
		q.Set("state", r.PostForm.Get("state"))
		q.Set("code", code)
		u.RawQuery = q.Encode()
		http.Redirect(w, r, u.String(), http.StatusSeeOther)
	})
	issuerMux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		if r.ParseForm() != nil {
			http.Error(w, "invalid exchange", 400)
			return
		}
		f.mu.Lock()
		grant, ok := grants[r.PostForm.Get("code")]
		delete(grants, r.PostForm.Get("code"))
		sub, proof := f.browserSubject, f.browserProof
		f.mu.Unlock()
		digest := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if !ok || grant.Get("code_challenge") != base64.RawURLEncoding.EncodeToString(digest[:]) || r.PostForm.Get("redirect_uri") != grant.Get("redirect_uri") {
			http.Error(w, "invalid grant", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"id_token": f.token(sub, grant.Get("nonce"), proof), "access_token": "unused", "token_type": "Bearer"})
	})
	issuerMux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": "https://" + r.Host, "jwks_uri": "https://" + r.Host + "/jwks", "authorization_endpoint": "https://" + r.Host + "/authorize", "token_endpoint": "https://" + r.Host + "/token"})
	})
	issuerMux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{f.signer.JWK("key-1")}})
	})
	f.issuer = httptest.NewTLSServer(issuerMux)
	t.Cleanup(f.issuer.Close)
	verifier, err := oidcauth.NewVerifier(oidcauth.VerifierConfig{Issuer: f.issuer.URL, ClientID: "tnl-control", HTTPClient: f.issuer.Client()})
	if err != nil {
		t.Fatal(err)
	}
	f.server = httptest.NewTLSServer(f.mux)
	t.Cleanup(f.server.Close)
	if _, err = authorityapi.Register(f.mux, authorityapi.Config{ControlURL: f.server.URL, OIDCIssuer: f.issuer.URL, OIDCClientID: "tnl-control", OIDCScopes: []string{"openid"}, HTTPClient: f.issuer.Client(), OIDCVerifier: verifier, WebServiceSecret: companyWebsiteSecret, ManagedDomain: "example.test", AccessTokenLifetime: time.Hour, RefreshTokenLifetime: 24 * time.Hour}, f.d); err != nil {
		t.Fatal(err)
	}
	f.now = time.Now().UTC()
	return f
}

func (f *companyHTTPFixture) token(sub, nonce string, proofs []oidcauth.TeamContext) string {
	f.t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sequence++
	claims := map[string]any{"iss": f.issuer.URL, "sub": sub, "aud": "tnl-control", "name": "Company user", "nonce": nonce, "iat": f.now.Unix(), "auth_time": f.now.Unix(), "exp": f.now.Add(5 * time.Minute).Unix(), "jti": fmt.Sprint(f.sequence), "roles": []string{"owner", "admin"}}
	if proofs != nil {
		claims["tnl_team_contexts"] = proofs
	}
	return f.signer.Token(f.t, "key-1", claims)
}

func (f *companyHTTPFixture) activationRequest(setup controlstate.IdentityConnectionSetup) authorityv1.ActivateIdentityConnectionJSONRequestBody {
	// one connection retains its chosen credential through exact retries.
	token := sha256.Sum256([]byte("company-fixture-provisioning:" + setup.ID))
	return authorityv1.ActivateIdentityConnectionJSONRequestBody{
		ExpectedRevision:  setup.Revision,
		SetupToken:        setup.SetupToken,
		ProvisioningToken: base64.RawURLEncoding.EncodeToString(token[:]),
	}
}

func (f *companyHTTPFixture) encode(value any) []byte {
	f.t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		f.t.Fatal(err)
	}
	return raw
}

func (f *companyHTTPFixture) call(method, path, bearer, actor string, raw []byte) *httptest.ResponseRecorder {
	f.t.Helper()
	r := httptest.NewRequest(method, path, bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	if actor != "" {
		r.Header.Set("X-Tnl-Actor-Token", actor)
	}
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, r)
	return w
}

func (f *companyHTTPFixture) ownerCall(method, path, sub string, proofs []oidcauth.TeamContext, body any) *httptest.ResponseRecorder {
	f.t.Helper()
	var raw []byte
	if body != nil {
		raw = f.encode(body)
	}
	return f.call(method, path, companyWebsiteSecret, f.token(sub, controlstate.CompanyActorNonce(method, path, raw), proofs), raw)
}

func (f *companyHTTPFixture) decode(w *httptest.ResponseRecorder, status int, out any) {
	f.t.Helper()
	if w.Code != status {
		f.t.Fatalf("HTTP %d want %d: %s", w.Code, status, w.Body.String())
	}
	if out != nil {
		if err := json.Unmarshal(w.Body.Bytes(), out); err != nil {
			f.t.Fatal(err)
		}
	}
}

func (f *companyHTTPFixture) basic(sub string) authorityv1.ControlSessionResponse {
	f.t.Helper()
	return f.deviceLogin(sub, "", nil)
}

// assertion-only tests exercise the atomic store boundary. production callers
// reach it only after control redeems a browser-bound authorization code.
func (f *companyHTTPFixture) exchangeIntent(ctx context.Context, id, binding, token string) (controlstate.ControlSession, error) {
	intent, err := f.d.ResolveCompanyLoginIntent(ctx, id, binding, time.Now())
	if err != nil {
		return controlstate.ControlSession{}, err
	}
	v, err := oidcauth.NewVerifier(oidcauth.VerifierConfig{Issuer: f.issuer.URL, ClientID: "tnl-control", HTTPClient: f.issuer.Client()})
	if err != nil {
		return controlstate.ControlSession{}, err
	}
	i, err := v.Verify(ctx, token)
	if err != nil {
		return controlstate.ControlSession{}, err
	}
	return f.d.CreateOIDCControlSession(ctx, "example.test", controlstate.OIDCIdentity{Issuer: i.Issuer, Subject: i.Subject, DisplayName: i.DisplayName, AssertionDigest: i.AssertionDigest, AssertionExpiry: i.ExpiresAt, TeamContexts: i.TeamContexts, Nonce: i.Nonce, ClientID: i.ClientID, IssuedAt: i.IssuedAt, CompanyIntent: &controlstate.CompanyIntentBinding{ID: id, BindingToken: binding, RedirectURI: intent.RedirectURI}}, time.Hour, 24*time.Hour, time.Now())
}

func (f *companyHTTPFixture) proof(c controlstate.IdentityConnection, subject string) []oidcauth.TeamContext {
	return []oidcauth.TeamContext{{TeamID: c.TeamID, IdentityConnectionID: c.ID, ConnectionRevision: c.Revision, SourceID: c.SourceID, Subject: subject, AuthenticatedAt: f.now.Unix()}}
}

func (f *companyHTTPFixture) login(c controlstate.IdentityConnection, sub, subject string) authorityv1.ControlSessionResponse {
	return f.deviceLogin(sub, c.TeamID, f.proof(c, subject))
}

func (f *companyHTTPFixture) deviceLogin(sub, team string, proof []oidcauth.TeamContext) authorityv1.ControlSessionResponse {
	f.t.Helper()
	client, err := authorityclient.New(f.server.URL, f.server.Client(), "")
	if err != nil {
		f.t.Fatal(err)
	}
	f.mu.Lock()
	f.browserSubject, f.browserProof = sub, proof
	f.mu.Unlock()
	challenge, err := client.StartDeviceLogin(f.t.Context(), authorityv1.StartDeviceLoginRequest{Team: &team})
	if err != nil {
		f.t.Fatal(err)
	}
	if err := oidctest.Approve(f.t.Context(), f.server.Client(), challenge.ApprovalUrl); err != nil {
		f.t.Fatal(err)
	}
	s, err := client.PollDeviceLogin(f.t.Context(), challenge.PollingCredential)
	if err != nil {
		f.t.Fatal(err)
	}
	if s.Session == nil {
		f.t.Fatal("device login did not issue a session")
	}
	return *s.Session
}

func (f *companyHTTPFixture) principal(s authorityv1.ControlSessionResponse) controlstate.ControlPrincipal {
	f.t.Helper()
	p, err := f.d.AuthenticateAccessToken(f.t.Context(), credentials.AccessToken(s.AccessToken), time.Now().UTC())
	if err != nil {
		f.t.Fatal(err)
	}
	return p
}

func (f *companyHTTPFixture) provision(c controlstate.IdentityConnection, capability, account, directory string, revision int64, eligible bool, slug string) *httptest.ResponseRecorder {
	f.t.Helper()
	raw := f.encode(authorityv1.CompanyEligibilityRequest{TeamId: c.TeamID, IdentityConnectionId: c.ID, ConnectionRevision: c.Revision, AccountSubject: account, Subject: directory, Revision: revision, Eligible: eligible, ValidUntil: f.now.Add(4 * time.Hour), MemberSlug: slug})
	r := httptest.NewRequest("POST", "/v1/service/company-eligibility", bytes.NewReader(raw))
	r.Header.Set("Authorization", "Bearer "+companyWebsiteSecret)
	r.Header.Set("X-Tnl-Provisioning-Token", capability)
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, r)
	return w
}
