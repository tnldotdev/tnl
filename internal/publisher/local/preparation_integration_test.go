package local

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/config"
	controlauthority "github.com/tnldotdev/tnl/internal/control/api/authority"
	controlpublic "github.com/tnldotdev/tnl/internal/control/api/public"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
)

func TestIntegrationAppPreparationReturnsSelectedEndpointWithoutPublication(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	ctx := t.Context()
	databaseURL := testutil.NewDisposablePostgresDatabaseURL(t, "app_preparation")
	if err := controlstate.Migrate(ctx, databaseURL); err != nil {
		t.Fatal(err)
	}
	database, err := controlstate.Open(ctx, databaseURL, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", naming.ManagedURLModeSimple)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(database.Close)
	session, err := controltest.Session(ctx, database, "example.test", time.Hour, 24*time.Hour, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	var mu sync.Mutex
	var mutations []string
	remote := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			mu.Lock()
			mutations = append(mutations, r.Method+" "+r.URL.Path)
			mu.Unlock()
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(remote.Close)
	handler, err := controlpublic.NewHandler(controlpublic.Config{ControlURL: remote.URL, ManagedDomain: "example.test", ManagedURLMode: naming.ManagedURLModeSimple,
		DNSAutomation: true, OIDCIssuer: "https://identity.fixture.test", OIDCClientID: "fixture", OIDCClientSecret: "fixture-secret", OIDCScopes: []string{"openid"}},
		controlpublic.DatabaseStores(database), database, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controlauthority.Register(handler, controlauthority.Config{ControlURL: remote.URL, ManagedDomain: "example.test"}, database); err != nil {
		t.Fatal(err)
	}
	mux.Handle("/", handler)
	original := http.DefaultTransport
	http.DefaultTransport = remote.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = original })
	t.Setenv("TNL_ACCESS_TOKEN", "")
	t.Setenv("TNL_SERVER", "")
	a, owner := testAppRuntime(t)
	a.project.Config.Server = &remote.URL
	a.project.Config.Services["web"] = config.Service{Public: new(true)}
	a.project.Config.Services["api"] = config.Service{Target: &config.ServiceTarget{Type: "docker", Container: new("unrelated"), Port: new(443),
		TLS: &config.TargetTLS{CA: new("system")}}}
	if err := controltest.SaveSession(ctx, a.state, remote.URL, session); err != nil {
		t.Fatal(err)
	}
	web := "web"
	var endpoint publisherprotocol.Endpoint
	if err := publisherprotocol.Call(ctx, owner, http.MethodPost, "/v1/capabilities",
		publisherprotocol.CapabilityRequest{Scope: "app", Service: &web}, &endpoint); err != nil {
		t.Fatal(err)
	}
	var assigned publisherprotocol.Assignment
	if err := publisherprotocol.Call(ctx, endpoint, http.MethodPost, "/v1/prepare", publisherprotocol.Prepare{
		Version: 1, Service: web, Directory: a.project.Root, Framework: publisherprotocol.FrameworkNode,
		Owner: strings.Repeat("a", 32), PID: os.Getpid(),
	}, &assigned); err != nil {
		t.Fatal(err)
	}
	selected := assigned.Project.Services[web]
	if assigned.RegistrationID == "" || assigned.Service != web || assigned.Hostname == "" ||
		assigned.PublicURL != "https://"+assigned.Hostname || len(assigned.Project.Services) != 1 ||
		selected.URL != assigned.PublicURL || selected.Hostname != assigned.Hostname || !selected.Public || selected.Port != 443 {
		t.Fatalf("app preparation lost its selected public endpoint: %+v", assigned)
	}
	metadata, err := os.ReadFile(a.project.Root + "/.tnl/local/project.json")
	if err != nil || bytes.Contains(metadata, []byte("invalid unrelated trust")) || bytes.Contains(metadata, []byte("unrelated")) {
		t.Fatal("app preparation leaked unrelated target configuration", err)
	}
	var snapshot publisherapp.Snapshot
	if err := publisherprotocol.Call(ctx, owner, http.MethodGet, "/v1/status", nil, &snapshot); err != nil {
		t.Fatal(err)
	}
	for _, service := range snapshot.Services {
		if service.Registered || service.Routable || service.Ready || service.RunNumber != 0 || service.TunnelID != "" ||
			service.Name != web && service.RegistrationID != "" {
			t.Fatal("preparation registered or published an application", snapshot.Services)
		}
	}
	inspect, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer inspect.Close(context.Background())
	var services, runs, publishers int
	if err := inspect.QueryRow(ctx, `SELECT (SELECT count(*) FROM control.services),
		(SELECT count(*) FROM control.service_runs), (SELECT count(*) FROM control.publisher_identities)`).Scan(&services, &runs, &publishers); err != nil ||
		services != 1 || runs != 0 || publishers != 0 {
		t.Fatalf("preparation realized unrelated work or started publication: services=%d runs=%d publishers=%d: %v", services, runs, publishers, err)
	}
	mu.Lock()
	gotMutations := append([]string(nil), mutations...)
	mu.Unlock()
	want := []string{"PUT /v1/projects/" + a.project.LocalPublicationIdentity().Key + "/local-services/web"}
	if !reflect.DeepEqual(gotMutations, want) {
		encoded, _ := json.Marshal(gotMutations)
		t.Fatalf("preparation changed another authority: %s", encoded)
	}
}
