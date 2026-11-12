package connector

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	"github.com/tnldotdev/tnl/internal/connector/workload"
)

func TestConnectionActionRefreshRequiresSelectedGitHubPolicy(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*connectorConnectionBackend, *connectorruntime.EnvironmentStart)
	}{
		{"selected explicit source", nil},
		{"other audience", func(_ *connectorConnectionBackend, r *connectorruntime.EnvironmentStart) {
			r.GitHubActionsRefresh.Audience = "https://other.example.test"
		}},
		{"initial native acquisition required", func(_ *connectorConnectionBackend, r *connectorruntime.EnvironmentStart) {
			r.Acquisition = nil
		}},
		{"one refresh source", func(_ *connectorConnectionBackend, r *connectorruntime.EnvironmentStart) {
			r.Environment = &connectorruntime.SDKEnvironment{GitHubRequestToken: "other.private.bearer"}
		}},
		{"SDK parent is not Action ownership", func(b *connectorConnectionBackend, _ *connectorruntime.EnvironmentStart) {
			b.parentPID = 123
		}},
		{"SDK registry is not Action ownership", func(b *connectorConnectionBackend, _ *connectorruntime.EnvironmentStart) {
			b.sdk = &SDKOptions{}
		}},
		{"other native method with the same OIDC kind", func(_ *connectorConnectionBackend, r *connectorruntime.EnvironmentStart) {
			r.Acquisition.Method = "fly-machine-api"
		}},
		{"selected file is not job runtime acquisition", func(_ *connectorConnectionBackend, r *connectorruntime.EnvironmentStart) {
			r.Acquisition = &workload.Acquisition{Method: "token-file", TokenFile: "/run/current.jwt"}
		}},
		{"insecure source", func(_ *connectorConnectionBackend, r *connectorruntime.EnvironmentStart) {
			r.GitHubActionsRefresh.RequestURL = "http://runtime.example.test/token"
		}},
		{"missing source credential", func(_ *connectorConnectionBackend, r *connectorruntime.EnvironmentStart) {
			r.GitHubActionsRefresh.RequestToken = ""
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			b := &connectorConnectionBackend{}
			request := explicitEnvironmentStart()
			request.Acquisition = &workload.Acquisition{Method: "github-actions", Audience: request.Selection.Environment.Server}
			request.GitHubActionsRefresh = &connectorruntime.GitHubActionsRefresh{Audience: request.Acquisition.Audience, RequestURL: "https://runtime.example.test/token", RequestToken: "private-runtime-bearer"}
			if test.change != nil {
				test.change(b, &request)
			}
			err := b.configureEnvironmentAcquisition(request)
			if test.change == nil && err != nil || test.change != nil && !errors.Is(err, connectorruntime.ErrInvalid) {
				t.Fatal("Action refresh did not retain its selected source boundary", err)
			}
			if err != nil && (b.environmentAcquire != nil || b.environmentAcquisition != nil || b.refreshAssertion != nil) {
				t.Fatal("invalid private job source installed acquisition or refresh")
			}
		})
	}
}

func TestConnectionActionRefreshPinsManifestSelection(t *testing.T) {
	// retain this selector while moving its pin from an implicit manifest to the
	// explicit private source. saved provider policy is authority-owned, not read
	// from the checkout. the external suite proves its exact Prepare 403 boundary.
	var calls atomic.Int32
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Query().Get("audience") != "approved-audience" || r.Header.Get("Authorization") != "Bearer private.original.bearer" {
			t.Error("native resampled its selected job source")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"value": "private.original.proof"})
	}))
	defer provider.Close()
	previous := http.DefaultTransport
	http.DefaultTransport = provider.Client().Transport
	defer func() { http.DefaultTransport = previous }()
	request := explicitEnvironmentStart()
	request.Acquisition = &workload.Acquisition{Method: "github-actions", Audience: "approved-audience"}
	request.GitHubActionsRefresh = &connectorruntime.GitHubActionsRefresh{Audience: request.Acquisition.Audience, RequestURL: provider.URL, RequestToken: "private.original.bearer"}
	client, err := workload.New(request.Selection.Environment.Server, nil)
	if err != nil { t.Fatal(err) }
	directory := t.TempDir()
	b := &connectorConnectionBackend{scope: environmentContext(request.Selection, directory), directory: directory, environmentSource: request.Source, connectorConnectionSession: connectorConnectionSession{workload: client}}
	if err := b.configureEnvironmentAcquisition(request); err != nil { t.Fatal(err) }
	if calls.Load() != 0 { t.Fatal("source selection acquired an assertion") }
	request.Acquisition.Method = "fly-machine-api"
	request.Acquisition.Audience = "replacement-audience"
	request.GitHubActionsRefresh.RequestURL = "https://must-not-read.invalid/token"
	request.GitHubActionsRefresh.RequestToken = "private.replacement.bearer"
	if err := os.WriteFile(filepath.Join(directory, "workloads.json"), []byte(`{"provider":"fly","max_duration_seconds":1}`), 0o600); err != nil { t.Fatal(err) }
	for _, acquire := range []func() (string, error){
		func() (string, error) { return b.acquireEnvironmentAssertion(t.Context()) },
		func() (string, error) { return b.refreshAssertion(t.Context()) },
	} {
		proof, err := acquire()
		if err != nil || proof != "private.original.proof" { t.Fatal("native switched its pinned private source", err) }
	}
	if calls.Load() != 2 { t.Fatal("startup and refresh did not each acquire exactly once", calls.Load()) }
}
