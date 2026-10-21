package tnldruntime

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/oidcauth"
	"github.com/tnldotdev/tnl/internal/testutil/oidctest"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"golang.org/x/oauth2"
)

// this local issuer exercises the hosted canonical claim and real PKCE callback.
// company setup uses the same explicit verified-source seam as authority tests.
type managedHTTPTestOIDC struct {
	t                *testing.T
	signer           *oidctest.Signer
	client, callback string
	mu               sync.Mutex
	grants           map[string]url.Values
	proof            []oidcauth.TeamContext
}

func newManagedHTTPTestOIDC(t *testing.T, client, callback string) *managedHTTPTestOIDC {
	return &managedHTTPTestOIDC{t: t, signer: oidctest.NewSigner(t), client: client, callback: callback, grants: map[string]url.Values{}}
}
func (p *managedHTTPTestOIDC) setProof(proof []oidcauth.TeamContext) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.proof = proof
}
func (p *managedHTTPTestOIDC) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	write := func(value any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(value)
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /.well-known/openid-configuration":
		write(map[string]any{"issuer": testOIDCIssuer, "authorization_endpoint": testOIDCIssuer + "/authorize", "token_endpoint": testOIDCIssuer + "/token", "jwks_uri": testOIDCIssuer + "/jwks", "response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256"}})
	case "GET /jwks":
		write(map[string]any{"keys": []any{p.signer.JWK("managed-http")}})
	case "POST /authorize":
		if r.ParseForm() != nil || r.PostForm.Get("redirect_uri") != p.callback || r.PostForm.Get("client_id") != p.client || r.PostForm.Get("code_challenge_method") != "S256" {
			http.Error(w, "invalid authorization", 400)
			return
		}
		code := oauth2.GenerateVerifier()
		p.mu.Lock()
		p.grants[code] = r.PostForm
		p.mu.Unlock()
		u, _ := url.Parse(p.callback)
		q := u.Query()
		q.Set("code", code)
		q.Set("state", r.PostForm.Get("state"))
		u.RawQuery = q.Encode()
		http.Redirect(w, r, u.String(), http.StatusSeeOther)
	case "POST /token":
		if r.ParseForm() != nil {
			http.Error(w, "invalid exchange", 400)
			return
		}
		p.mu.Lock()
		grant, ok := p.grants[r.PostForm.Get("code")]
		delete(p.grants, r.PostForm.Get("code"))
		proof := p.proof
		p.mu.Unlock()
		digest := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if !ok || grant.Get("code_challenge") != base64.RawURLEncoding.EncodeToString(digest[:]) || r.PostForm.Get("redirect_uri") != p.callback {
			http.Error(w, "invalid grant", 400)
			return
		}
		now := time.Now()
		claims := map[string]any{"iss": testOIDCIssuer, "sub": "operator", "name": "operator", "aud": p.client, "nonce": grant.Get("nonce"), "iat": now.Unix(), "auth_time": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "jti": r.PostForm.Get("code")}
		if proof != nil {
			claims["tnl_team_contexts"] = proof
		}
		write(map[string]any{"id_token": p.signer.Token(p.t, "managed-http", claims), "access_token": "unused-local", "token_type": "Bearer"})
	default:
		http.NotFound(w, r)
	}
}

func checkManagedHTTPCompany(t *testing.T, f *privateSeparatedFixture, issuer *managedHTTPTestOIDC, client *http.Client, base string, service controlv1.PrivateService, identity string) {
	t.Helper()
	ctx, now := t.Context(), time.Now()
	seed, err := f.database.CreateOIDCControlSession(ctx, f.controlConfig.ManagedDomain, controlstate.OIDCIdentity{Issuer: testOIDCIssuer, Subject: "operator", DisplayName: "operator", AssertionDigest: sha256.Sum256([]byte("managed-http-company-owner")), AssertionExpiry: now.Add(time.Minute)}, time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := f.database.AuthenticateAccessToken(ctx, seed.AccessToken, now)
	if err != nil {
		t.Fatal(err)
	}
	setup, err := f.database.BeginIdentityConnectionSetup(ctx, principal, controlstate.CreateIdentityConnectionRequest{TeamID: service.TeamId, Issuer: testOIDCIssuer, SourceID: "managed-http-company", Admission: "managed"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.database.ProvisionCompanyEligibility(ctx, setup.SetupToken, controlstate.ProvisionCompanyEligibilityRequest{TeamID: service.TeamId, IdentityConnectionID: setup.ID, ConnectionRevision: setup.Revision, IdentityID: identity, Subject: "directory-operator", Revision: 1, Eligible: true, ValidUntil: now.Add(time.Hour), MemberSlug: "operator"}, now); err != nil {
		t.Fatal(err)
	}
	proof := []oidcauth.TeamContext{{TeamID: service.TeamId, IdentityConnectionID: setup.ID, ConnectionRevision: setup.Revision, SourceID: setup.SourceID, Subject: "directory-operator", AuthenticatedAt: now.Unix()}}
	active, err := f.database.ActivateIdentityConnection(ctx, principal, service.TeamId, setup.ID, setup.SetupToken, setup.Revision, controlstate.OIDCIdentity{Issuer: testOIDCIssuer, Subject: "operator", AssertionDigest: sha256.Sum256([]byte("managed-http-company-consent")), AssertionExpiry: now.Add(time.Minute), TeamContexts: proof}, now)
	if err != nil {
		t.Fatal(err)
	}
	proof[0].ConnectionRevision = active.Revision
	login := func(proofs []oidcauth.TeamContext, allowed bool) *http.Client {
		t.Helper()
		issuer.setProof(proofs)
		browser := *client
		browser.Jar, _ = cookiejar.New(nil)
		closeBody := func(r *http.Response) { _, _ = io.Copy(io.Discard, r.Body); _ = r.Body.Close() }
		response, err := browser.Get(base + "/__tnl/team/login?return=/")
		if err != nil {
			t.Fatal(err)
		}
		endpoint := response.Header.Get("Location")
		closeBody(response)
		response, err = browser.Get(endpoint)
		if err != nil {
			t.Fatal(err)
		}
		authorize, err := url.Parse(response.Header.Get("Location"))
		closeBody(response)
		if err != nil {
			t.Fatal(err)
		}
		fields := authorize.Query()
		intent, err := f.database.ResolveCompanyLoginIntent(ctx, fields.Get("tnl_company_intent"), fields.Get("tnl_company_binding"), time.Now())
		if err != nil || intent.TeamID != service.TeamId || intent.RedirectURI != issuer.callback || fields.Get("max_age") != "0" {
			t.Fatal("browser company step-up lost exact team/callback", intent, err)
		}
		authorize.RawQuery = ""
		response, err = browser.PostForm(authorize.String(), fields)
		if err != nil {
			t.Fatal(err)
		}
		callback := response.Header.Get("Location")
		closeBody(response)
		response, err = browser.Get(callback)
		if err != nil {
			t.Fatal(err)
		}
		if !allowed {
			if response.StatusCode == 303 {
				t.Fatal("personal or wrong-team company proof bypassed step-up")
			}
			closeBody(response)
			return &browser
		}
		handoff := response.Header.Get("Location")
		if response.StatusCode != 303 {
			body, _ := io.ReadAll(response.Body)
			t.Fatalf("company callback status=%d body=%s", response.StatusCode, body)
		}
		closeBody(response)
		if u, _ := url.Parse(handoff); u.Scheme+"://"+u.Host != base {
			t.Fatal("company handoff changed managed port")
		}
		response, err = browser.Get(handoff)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != 303 {
			t.Fatal("company handoff failed", response.StatusCode)
		}
		closeBody(response)
		response, err = browser.Get(base + "/")
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != 200 {
			t.Fatal("company browser denied", response.StatusCode)
		}
		closeBody(response)
		return &browser
	}
	login(nil, false)
	wrong := append([]oidcauth.TeamContext(nil), proof...)
	wrong[0].TeamID = "team_wrong"
	login(wrong, false)
	browser := login(proof, true)
	origin, _ := url.Parse(base)
	var digest [32]byte
	for _, cookie := range browser.Jar.Cookies(origin) {
		if cookie.Name == "__Host-tnl-browser" {
			raw, _ := base64.RawURLEncoding.DecodeString(cookie.Value)
			digest = sha256.Sum256(raw)
		}
	}
	var member string
	if err = f.inspect.QueryRowContext(ctx, `SELECT session.control_session_id,m.id FROM control.managed_http_browser_sessions session JOIN control.team_memberships m ON m.team_id=$2 AND m.identity_id=$3 WHERE session.cookie_digest=$1`, digest[:], service.TeamId, identity).Scan(&principal.SessionID, &member); err != nil {
		t.Fatal(err)
	}
	principal.IdentityID = identity
	companyCtx := controlstate.WithControlPrincipal(ctx, principal)
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	device, err := f.database.EnrollVisitorDevice(ctx, identity, public, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	material, err := f.database.IssueServiceClientCertificate(companyCtx, service.Id, identity, device.ID, csr, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	certificate, err := tls.X509KeyPair([]byte(material.CertificatePEM), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	transport := client.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.Certificates = []tls.Certificate{certificate}
	defer transport.CloseIdleConnections()
	mtls := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	response, err := mtls.Get(base + "/")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("company client certificate denied", response.StatusCode)
	}
	response, err = browser.Get(base + "/watch")
	if err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(response.Body)
	if line, err := reader.ReadString('\n'); err != nil || line != "data: ready\n" {
		t.Fatal(line, err)
	}
	if err = f.database.SetCompanyMembershipDecision(ctx, principal, service.TeamId, member, true, false, false, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err = io.Copy(io.Discard, reader); err == nil {
		t.Fatal("company suspension retained live HTTP stream")
	}
	_ = response.Body.Close()
	for _, visitor := range []*http.Client{browser, mtls} {
		response, err = visitor.Get(base + "/")
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == 200 {
				t.Fatal("company suspension retained HTTP access")
			}
		}
	}
}
