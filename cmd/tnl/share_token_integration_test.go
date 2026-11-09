package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	controlauthority "github.com/tnldotdev/tnl/internal/control/api/authority"
	controlpublic "github.com/tnldotdev/tnl/internal/control/api/public"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/zalando/go-keyring"
)

func TestIntegrationShareTokenPreparesExactPermission(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	keyring.MockInit()
	ctx := t.Context()
	databaseURL := testutil.NewDisposablePostgresDatabaseURL(t, "share_token_cli")
	if err := controlstate.Migrate(ctx, databaseURL); err != nil {
		t.Fatal(err)
	}
	d, err := controlstate.Open(ctx, databaseURL, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	now := time.Now()
	person, err := controltest.Session(ctx, d, "example.test", time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	member := person.Identity.Memberships[0]
	domains, err := d.ListTeamDomains(ctx, person.Identity.Identity.ID, member.TeamID)
	if err != nil || len(domains) == 0 {
		t.Fatal("missing managed domain", err)
	}
	publicURL, err := d.CreatePublicURL(ctx, controlstate.CreatePublicURLRequest{
		TeamID: member.TeamID, DomainID: domains[0].ID, MembershipID: member.ID, ActingIdentityID: person.Identity.Identity.ID,
		IdempotencyKey: "share-token", RequestDigest: sha256.Sum256([]byte("share-token")),
		CanonicalHostname: "token." + member.ManagedLabel + ".example.test", Target: "http://127.0.0.1:3000",
		PublicURLScope: controlstate.PublicURLScopeMember, Purpose: controlstate.PublicURLPurposeApp, DNSState: controlstate.PublicURLDNSUnmanaged,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	control, err := controlpublic.NewHandler(controlpublic.Config{ControlURL: server.URL, ManagedDomain: "example.test", OIDCIssuer: server.URL + "/oidc", OIDCClientID: "fixture", OIDCClientSecret: "fixture", OIDCScopes: []string{"openid"}}, controlpublic.DatabaseStores(d), d, nil)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := controlauthority.NewHandler(controlauthority.Config{ControlURL: server.URL, ManagedDomain: "example.test", OIDCIssuer: server.URL + "/oidc", OIDCClientID: "fixture", OIDCClientSecret: "fixture", OIDCScopes: []string{"openid"}}, d)
	if err != nil {
		t.Fatal(err)
	}
	scope := controlv1.VisitorResourceScope{Kind: "public_url", Id: publicURL.ID}
	created := make(chan controlv1.Share, 1)
	var exchanges atomic.Int64
	var mode atomic.Value
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/visitor-tokens" {
			exchanges.Add(1)
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if r.URL.Path == "/v1/shares" && r.Method == http.MethodPost {
			recorded := httptest.NewRecorder()
			control.ServeHTTP(recorded, r)
			var share controlv1.Share
			if recorded.Code != http.StatusCreated || json.Unmarshal(recorded.Body.Bytes(), &share) != nil {
				t.Errorf("share creation returned %d", recorded.Code)
				w.WriteHeader(recorded.Code)
				return
			}
			created <- share
			switch mode.Load().(string) {
			case "unavailable":
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			case "wrong-scope":
				share.PublicUrlIds = []string{"url_" + strings.Repeat("B", 22)}
			case "wrong-id":
				share.Id = "invalid"
			case "wrong-expiry":
				share.ExpiresAt = share.ExpiresAt.Add(time.Hour)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(share)
			return
		}
		if _, pattern := authority.Handler(r); pattern != "/" {
			authority.ServeHTTP(w, r)
		} else {
			control.ServeHTTP(w, r)
		}
	}))
	original := http.DefaultTransport
	http.DefaultTransport = server.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = original })
	conn, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(ctx) })
	state := filepath.Join(t.TempDir(), "state")
	for _, item := range []struct{ name, output, lifetime, mode string }{
		{"raw", "human", "7d", "success"},
		{"json", "json", "7d", "success"},
		{"parent expiry", "json", "1m", "success"},
		{"creation unavailable", "human", "24h", "unavailable"},
		{"wrong scope", "json", "24h", "wrong-scope"},
		{"wrong ID", "json", "24h", "wrong-id"},
		{"wrong expiry", "json", "24h", "wrong-expiry"},
	} {
		t.Run(item.name, func(t *testing.T) {
			mode.Store(item.mode)
			var output, diagnostics bytes.Buffer
			err := run(ctx, []string{"--no-config", "--no-telemetry", "share", "token", "create", publicURL.ID, "--name=automation", "--expires-in=" + item.lifetime,
				"--server", server.URL, "--access-token", person.AccessToken.String(), "--team", member.TeamID, "--state-dir", state, "--output=" + item.output}, &output, &diagnostics)
			var result controlv1.Share
			select {
			case result = <-created:
			default:
				t.Fatalf("CLI did not create a share: %v", err)
			}
			if item.mode != "success" {
				if err == nil || output.Len() != 0 {
					t.Fatal("failed share creation printed a credential")
				}
				return
			}
			if err != nil || diagnostics.Len() != 0 {
				t.Fatal("CLI share creation failed", err)
			}
			token := strings.TrimSuffix(output.String(), "\n")
			if item.output == "json" {
				var printed struct {
					SchemaVersion int       `json:"schema_version"`
					ShareID       string    `json:"share_id"`
					ShareToken    string    `json:"share_token"`
					PublicURLID   string    `json:"public_url_id"`
					ExpiresAt     time.Time `json:"expires_at"`
				}
				if json.Unmarshal(output.Bytes(), &printed) != nil || printed.SchemaVersion != 1 || printed.ShareID != result.Id || printed.PublicURLID != scope.Id || !printed.ExpiresAt.Equal(result.ExpiresAt) {
					t.Fatal("JSON lost the exact permission scope or expiry")
				}
				token = printed.ShareToken
			}
			parts := strings.Split(token, ".")
			if len(parts) != 3 || parts[0] != "vsh1" || parts[1] != result.Id {
				t.Fatal("CLI did not print a directly usable opaque share token")
			}
			secret, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
			if err != nil || len(secret) != 32 {
				t.Fatal("invalid printed secret")
			}
			digest := sha256.Sum256(secret)
			if strings.Contains(diagnostics.String(), token) || strings.Contains(diagnostics.String(), parts[2]) {
				t.Fatal("diagnostics disclosed credential")
			}
			at := time.Now()
			if item.lifetime == "7d" {
				at = at.Add(6 * 24 * time.Hour)
			}
			var stored []byte
			var until time.Time
			if err := conn.QueryRow(ctx, `SELECT secret_digest,expires_at FROM control.visitor_share_authority($1,$2) WHERE share_id=$3`, publicURL.ID, at, result.Id).Scan(&stored, &until); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(stored, digest[:]) || !until.Equal(result.ExpiresAt) {
				t.Fatal("printed credential lost its persisted lifetime or secret binding")
			}
			view := visitortoken.View{Issuer: server.URL, Scope: visitorscope.Scope{Kind: visitorscope.PublicURL, ID: publicURL.ID}, Hostname: publicURL.CanonicalHostname, Port: 443, VisitorPolicyRevision: 1, ObservedAt: at, ValidUntil: at.Add(visitortoken.PolicyLifetime)}.WithShareVerifiers(map[string]visitortoken.ShareVerifier{result.Id: {Digest: digest, ExpiresAt: until}})
			verified, err := visitortoken.VerifyBearer(visitortoken.Token(token), view, at)
			if err != nil || verified.Facts().Subject != (visitortoken.Share{ShareID: result.Id}) || !verified.Facts().ExpiresAt.Equal(result.ExpiresAt) {
				t.Fatal("exact printed token failed within advertised lifetime", err)
			}
		})
	}
	if exchanges.Load() != 0 {
		t.Fatal("CLI required a visitor-token exchange")
	}
}
