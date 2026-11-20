package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	controlauthority "github.com/tnldotdev/tnl/internal/control/api/authority"
	controlpublic "github.com/tnldotdev/tnl/internal/control/api/public"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationShareTokenPreparesExactPermission(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	clientstate.UseMemoryKeychainForTesting()
	ctx := t.Context()
	databaseURL := testutil.NewDisposablePostgresDatabaseURL(t, "share_token_cli")
	if err := controlstate.Migrate(ctx, databaseURL); err != nil {
		t.Fatal(err)
	}
	d, err := controlstate.Open(ctx, databaseURL, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", naming.ManagedURLModeGenerated)
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
	service, err := d.CreateServiceAt(ctx, member.TeamID, person.Identity.Identity.ID, "token", "share-token", controlstate.ServicePlacement{}, now, controlstate.ServiceMetadata{},
		&controlstate.ProjectServiceConfiguration{Target: "127.0.0.1:3000", Protocol: "http", DomainID: domains[0].ID,
			Hostname: "token." + member.ManagedLabel + ".example.test", Public: new(true)})
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
	scope := controlv1.VisitorResourceScope{Kind: "service", Id: service.ID}
	type preparation struct {
		source     controlv1.VisitorTokenShareSource
		permission controlv1.VisitorTokenResponse
	}
	prepared := make(chan preparation, 1)
	var mode atomic.Value
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/visitor-tokens" {
			var request controlv1.VisitorTokenRequest
			var source controlv1.VisitorTokenShareSource
			data, err := io.ReadAll(r.Body)
			if err != nil || json.Unmarshal(data, &request) != nil || json.Unmarshal(request.Source, &source) != nil || request.Resource != scope || source.Kind != "share" || r.Header.Get("Authorization") != "" {
				t.Error("CLI did not exchange the exact share source independently of its management session")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(data))
			recorded := httptest.NewRecorder()
			control.ServeHTTP(recorded, r)
			var permission controlv1.VisitorTokenResponse
			if recorded.Code != http.StatusOK || json.Unmarshal(recorded.Body.Bytes(), &permission) != nil {
				t.Errorf("permission preparation returned %d", recorded.Code)
				w.WriteHeader(recorded.Code)
				return
			}
			prepared <- preparation{source, permission}
			switch mode.Load().(string) {
			case "unavailable":
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			case "wrong-host":
				permission.Hostname = "other.example.test"
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(permission)
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
		{"raw", "human", "24h", "success"},
		{"json", "json", "24h", "success"},
		{"parent expiry", "json", "1m", "success"},
		{"preparation unavailable", "human", "24h", "unavailable"},
		{"wrong host", "json", "24h", "wrong-host"},
	} {
		t.Run(item.name, func(t *testing.T) {
			mode.Store(item.mode)
			var output, diagnostics bytes.Buffer
			before := time.Now()
			err := run(ctx, []string{"--no-config", "--no-telemetry", "share", "token", "create", service.ID, "--name=automation", "--expires-in=" + item.lifetime,
				"--server", server.URL, "--access-token", person.AccessToken.String(), "--team", member.TeamID, "--state-dir", state, "--output=" + item.output}, &output, &diagnostics)
			var result preparation
			select {
			case result = <-prepared:
			default:
				t.Fatalf("CLI did not prepare permission: %v", err)
			}
			if item.mode != "success" {
				if err == nil || output.Len() != 0 {
					t.Fatal("failed preparation printed a credential")
				}
				return
			}
			if err != nil || diagnostics.Len() != 0 {
				t.Fatal("CLI permission preparation failed", err)
			}
			token := strings.TrimSuffix(output.String(), "\n")
			if item.output == "json" {
				var printed struct {
					SchemaVersion int       `json:"schema_version"`
					ShareID       string    `json:"share_id"`
					ShareToken    string    `json:"share_token"`
					ServiceID     string    `json:"service_id"`
					ExpiresAt     time.Time `json:"expires_at"`
				}
				if json.Unmarshal(output.Bytes(), &printed) != nil || printed.SchemaVersion != 1 || printed.ShareID != result.source.ShareId || printed.ServiceID != service.ID || !printed.ExpiresAt.Equal(result.permission.ExpiresAt) {
					t.Fatal("JSON lost the exact permission scope or expiry")
				}
				token = printed.ShareToken
			}
			if token != result.permission.VisitorToken || strings.Contains(output.String(), result.source.Secret) {
				t.Fatal("CLI printed the authority source instead of the signed permission")
			}
			var keyID string
			var public []byte
			if err := conn.QueryRow(ctx, `SELECT id,public_key FROM control.visitor_token_keys WHERE retired_at IS NULL AND revoked_at IS NULL`).Scan(&keyID, &public); err != nil {
				t.Fatal(err)
			}
			at := time.Now()
			view := visitortoken.View{Issuer: server.URL, Scope: visitorscope.Scope{Kind: visitorscope.Service, ID: service.ID}, Hostname: service.Endpoint.Hostname, Port: 443,
				VisitorPolicyRevision: result.permission.VisitorPolicyRevision, ObservedAt: at, ValidUntil: at.Add(visitortoken.PolicyLifetime)}.WithVerificationKeys(map[string]ed25519.PublicKey{keyID: public})
			verified, err := visitortoken.VerifyBearer(visitortoken.Token(token), view, at)
			if err != nil || verified.Facts().Subject != (visitortoken.Share{ShareID: result.source.ShareId}) || !verified.Facts().ExpiresAt.Equal(result.permission.ExpiresAt) {
				t.Fatal("CLI output is not a locally verifiable share permission", err)
			}
			var parent time.Time
			if err := conn.QueryRow(ctx, `SELECT expires_at FROM control.shares WHERE id=$1`, result.source.ShareId).Scan(&parent); err != nil {
				t.Fatal(err)
			}
			if item.lifetime == "1m" {
				if !result.permission.ExpiresAt.Equal(parent.Truncate(time.Second)) {
					t.Fatal("short share lifetime did not cap the permission")
				}
			} else if !result.permission.ExpiresAt.Before(parent) || result.permission.ExpiresAt.Before(before.Add(visitortoken.RenewableLifetime-time.Second)) || result.permission.ExpiresAt.After(at.Add(visitortoken.RenewableLifetime)) {
				t.Fatal("CLI permission did not retain the five-minute preparation lifetime")
			}
		})
	}
}
