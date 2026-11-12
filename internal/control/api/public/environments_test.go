package public

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
	"github.com/tnldotdev/tnl/internal/testutil"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestEnvironmentManagementRequiresExplicitStore(t *testing.T) {
	handler, err := NewHandler(Config{ControlURL: "https://control.example.test"}, Stores{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ method, path string }{
		{http.MethodPost, "/v1/projects/accounts/service-definitions"},
		{http.MethodPost, "/v1/projects/accounts/environments"},
		{http.MethodGet, "/v1/projects/accounts/environments?team_id=team"},
		{http.MethodGet, "/v1/projects/accounts/environments/environment?team_id=team"},
		{http.MethodDelete, "/v1/projects/accounts/environments/environment?team_id=team&expected_revision=1"},
		{http.MethodPost, "/v1/projects/accounts/environments/environment/apply"},
		{http.MethodPost, "/v1/projects/accounts/environments/apply"},
	} {
		t.Run(test.method+" "+test.path, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, strings.NewReader(`{}`))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			var problem controlv1.Problem
			if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
				t.Fatal(err)
			}
			if response.Code != http.StatusServiceUnavailable || problem.Code != controlv1.Unavailable {
				t.Fatal("missing explicit environment store did not fail closed", response.Code, problem)
			}
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("environment management response may be cached")
			}
		})
	}
}

func TestEnvironmentTargetTrustShorthand(t *testing.T) {
	for _, test := range []struct{ address, hostname string }{
		{"db.staging.internal:5432", "db.staging.internal"},
		{"[::1]:5432", "::1"},
		{"https://api.example.test", "api.example.test"},
		{"https://api.example.test:8443/", "api.example.test"},
	} {
		t.Run(test.address, func(t *testing.T) {
			trust, err := environmentTargetTrust(t.Context(), test.address, controlv1.EnvironmentTargetTLS{})
			if err != nil || trust == nil || trust.Hostname != test.hostname || trust.CAPEM != "" {
				t.Fatal("empty TLS block did not approve system trust for the destination", trust, err)
			}
			snapshot, err := (targettrust.Declaration{Hostname: trust.Hostname, CAPEM: []byte(trust.CAPEM), Digest: trust.Digest}).Snapshot()
			if err != nil || !snapshot.System {
				t.Fatal("captured trust is not a validated system-CA declaration", err)
			}
		})
	}
	ca, leaf := testutil.TLSCertificate(t, []string{"database.example.test"}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	trust, err := environmentTargetTrust(t.Context(), "db.internal:5432", controlv1.EnvironmentTargetTLS{Hostname: new("database.example.test"), CaPem: new(string(ca))})
	if err != nil || trust == nil || trust.Hostname != "database.example.test" || trust.CAPEM == "" {
		t.Fatal("explicit CA and hostname were not captured", err)
	}
	if _, err := (targettrust.Declaration{Hostname: trust.Hostname, CAPEM: []byte(trust.CAPEM), Digest: trust.Digest}).Snapshot(); err != nil {
		t.Fatal("CA-only approval is not portable", err)
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Certificate[0]})
	for _, input := range []controlv1.EnvironmentTargetTLS{
		{CaPem: new("/private/ca.pem")},
		{CaPem: new("https://untrusted.example.test/ca.pem")},
		{CaPem: new(string(leafPEM))},
		{Digest: new(strings.Repeat("0", 64))},
		{Hostname: new("*.example.test")},
	} {
		if _, err := environmentTargetTrust(t.Context(), "db.internal:5432", input); !errors.Is(err, controlstate.ErrEnvironmentInvalid) {
			t.Fatal("invalid or non-CA trust was accepted", err)
		}
	}
}

func TestEnvironmentTargetTrustPreservesCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := environmentTargetTrust(ctx, "db.internal:5432", controlv1.EnvironmentTargetTLS{})
	if !errors.Is(err, context.Canceled) || errors.Is(err, controlstate.ErrEnvironmentInvalid) {
		t.Fatal("canceled capture was classified as invalid configuration", err)
	}
}

func TestEnvironmentTargetTrustDoesNotReadCAReferences(t *testing.T) {
	ca, _ := testutil.TLSCertificate(t, []string{"database.example.test"}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write(ca)
	}))
	t.Cleanup(server.Close)
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, ca, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, reference := range []string{path, server.URL + "/ca.pem"} {
		if _, err := environmentTargetTrust(t.Context(), "database.example.test:5432", controlv1.EnvironmentTargetTLS{CaPem: &reference}); !errors.Is(err, controlstate.ErrEnvironmentInvalid) {
			t.Fatal("CA reference was read instead of requiring inline CA-only PEM", err)
		}
	}
	if requests.Load() != 0 {
		t.Fatal("control fetched a CA reference supplied by the caller")
	}
}
