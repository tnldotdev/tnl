package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	controlauthority "github.com/tnldotdev/tnl/internal/control/api/authority"
	controlpublic "github.com/tnldotdev/tnl/internal/control/api/public"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationCLIDeploymentCRUD(t *testing.T) {
	if !cliWorkflowInChild(t) {
		return
	}
	databaseURL := testutil.NewDisposablePostgresDatabaseURL(t, "deployment_cli")
	if err := controlstate.Migrate(t.Context(), databaseURL); err != nil {
		t.Fatal(err)
	}
	database, err := controlstate.Open(t.Context(), databaseURL, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", naming.ManagedURLModeSimple)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(database.Close)
	now := time.Now().UTC()
	session, err := controltest.Session(t.Context(), database, "example.test", time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	team := session.Identity.Memberships[0].TeamID
	_, err = database.ApplyProjectConfiguration(t.Context(), controlstate.ApplyProjectConfigurationRequest{
		TeamID: team, ActorID: session.Identity.Identity.ID, ProjectKey: "shop", SourceFingerprint: strings.Repeat("a", 64), Now: now,
		Configuration: controlstate.ProjectConfiguration{Services: map[string]controlstate.ProjectServiceConfiguration{
			"db": {Protocol: "postgres", Target: "localhost:5432"}, "cache": {Protocol: "tcp", Target: "localhost:6379"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	public, err := controlpublic.NewHandler(controlpublic.Config{ControlURL: server.URL, ManagedURLMode: naming.ManagedURLModeSimple, OIDCIssuer: "https://identity.fixture.test"}, controlpublic.DatabaseStores(database), database, nil)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := controlauthority.NewHandler(controlauthority.Config{ControlURL: server.URL, ManagedDomain: "example.test"}, database)
	if err != nil {
		t.Fatal(err)
	}
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, pattern := authority.Handler(r); pattern != "/" {
			authority.ServeHTTP(w, r)
		} else {
			public.ServeHTTP(w, r)
		}
	}))
	previous := http.DefaultTransport
	http.DefaultTransport = server.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = previous })
	root := filepath.Join(t.TempDir(), "state")
	local, err := clientstate.OpenWithOptions(t.Context(), root, clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	if err = local.Close(); err != nil {
		t.Fatal(err)
	}
	call := func(operation ...string) ([]byte, error) {
		args := append([]string{"--no-config", "--no-telemetry", "deployment"}, operation...)
		args = append(args, "--server", server.URL, "--state-dir", root, "--access-token", session.AccessToken.String(), "--team", team, "--project-key", "shop", "--output", "json")
		var output, diagnostics bytes.Buffer
		err := run(t.Context(), args, &output, &diagnostics)
		return output.Bytes(), err
	}
	read := func(operation ...string) controlv1.Deployment {
		t.Helper()
		payload, err := call(operation...)
		if err != nil {
			t.Fatal(operation[0], err)
		}
		var deployment controlv1.Deployment
		if err = json.Unmarshal(payload, &deployment); err != nil {
			t.Fatal(err)
		}
		return deployment
	}
	create := []string{"create", "customer", "--target", "db=orders.abc.us-east-1.rds.amazonaws.com:5432", "--target-tls", "db=aws-rds", "--target", "cache=cache.internal:6379", "--idempotency-key", "customer-setup"}
	created := read(create...)
	recovered := read(create...)
	if recovered.Id != created.Id || created.Targets["db"].Tls == nil {
		t.Fatal("CLI recovery changed deployment identity or lost verified target TLS")
	}
	updated := read("update", created.Id, "--target", "db=replacement.internal:5432")
	if updated.Revision != created.Revision+1 || updated.Services["db"].Id != created.Services["db"].Id || *updated.Targets["cache"].Address != "cache.internal:6379" {
		t.Fatal("CLI update changed service identity or an omitted target")
	}
	shown := read("show", "customer")
	if shown.Id != created.Id || *shown.Targets["db"].Address != "replacement.internal:5432" {
		t.Fatal("CLI name lookup lost the saved update")
	}
	other := read("create", "sibling", "--target", "db=sibling.internal:5432")
	listing, err := call("list", "--limit", "1")
	var page controlv1.DeploymentPage
	if err != nil || json.Unmarshal(listing, &page) != nil || len(page.Deployments) != 1 || page.NextCursor == nil {
		t.Fatal("CLI list did not preserve pagination", err)
	}
	listing, err = call("list", "--limit", "1", "--after", *page.NextCursor)
	first := page.Deployments[0].Id
	if err != nil || json.Unmarshal(listing, &page) != nil || len(page.Deployments) != 1 || page.Deployments[0].Id == first {
		t.Fatal("CLI pagination repeated a deployment", err)
	}
	deleted, err := call("delete", "customer")
	if err != nil || !bytes.Contains(deleted, []byte(`"deleted":true`)) {
		t.Fatal("CLI deletion did not report its finite result", err)
	}
	if _, err = call("show", created.Id); !errors.Is(err, clientcontrol.ErrNotFound) {
		t.Fatal("CLI deletion left the deployment readable", err)
	}
	if _, err = call(create...); !errors.Is(err, clientcontrol.ErrStatusConflict) {
		t.Fatal("CLI original-key replay recreated a deleted deployment", err)
	}
	if read("show", other.Id).Id != other.Id {
		t.Fatal("CLI deletion affected its sibling")
	}
}
