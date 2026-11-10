package connector

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/client/credentialfile"
	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	controlauthority "github.com/tnldotdev/tnl/internal/control/api/authority"
	controlpublic "github.com/tnldotdev/tnl/internal/control/api/public"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	"github.com/tnldotdev/tnl/internal/testutil/githubtest"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationWorkloadApplicationOwnerUsesOneSourceForPublication(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	for _, mixed := range []bool{false, true} {
		name := "publish only"
		if mixed {
			name = "mixed"
		}
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			databaseURL := testutil.NewDisposablePostgresDatabaseURL(t, "workload_application_owner")
			if err := controlstate.Migrate(ctx, databaseURL); err != nil {
				t.Fatal(err)
			}
			d, err := controlstate.Open(ctx, databaseURL, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", naming.ManagedURLModeSimple)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(d.Close)
			human, err := controltest.Session(ctx, d, "example.test", time.Hour, 24*time.Hour, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			mux := http.NewServeMux()
			server := httptest.NewTLSServer(mux)
			t.Cleanup(server.Close)
			issuer := githubtest.New(t)
			if _, err := controlauthority.Register(mux, controlauthority.Config{ControlURL: server.URL, HTTPClient: issuer.Client}, d); err != nil {
				t.Fatal(err)
			}
			handler, err := controlpublic.NewHandler(controlpublic.Config{ControlURL: server.URL, ManagedURLMode: naming.ManagedURLModeSimple}, controlpublic.DatabaseStores(d), d, nil)
			if err != nil {
				t.Fatal(err)
			}
			mux.Handle("/", handler)
			owner, err := clientcontrol.New(server.URL, server.Client(), human.AccessToken)
			if err != nil {
				t.Fatal(err)
			}
			var resource controlv1.ProjectWorkloadResource
			if err := resource.FromProjectWorkloadResource0(controlv1.ProjectWorkloadResource0{Service: "api"}); err != nil {
				t.Fatal(err)
			}
			resources := []controlv1.ProjectWorkloadResource{resource}
			grants := controlv1.ProjectWorkloadGrants{Publish: &resources}
			if mixed {
				grants.Visit = &resources
			}
			team := human.Identity.Memberships[0].TeamID
			group := "production"
			policies := map[string]controlv1.ProjectWorkload{"job": {Provider: controlv1.WorkloadGitHub, Github: &controlv1.ProjectWorkloadGitHub{Repository: "example/repository", RepositoryId: "12345", RepositoryOwnerId: "6789", WorkflowRef: "example/repository/.github/workflows/test.yml@refs/heads/main", Ref: "refs/heads/main", Events: []string{"push"}}, Grants: grants, MaxDurationSeconds: 3600}}
			fingerprint := strings.Repeat("a", 64)
			request := controlv1.ApplyProjectConfigurationRequest{TeamId: team, SourceFingerprint: fingerprint, Configuration: controlv1.ProjectConfiguration{Workloads: &policies, PublisherGroups: map[string]controlv1.ProjectPublisherGroup{group: {}}, Services: map[string]controlv1.ProjectServiceConfiguration{"api": {PublisherGroup: &group, Target: "api.internal:3000"}}, Webhooks: map[string]controlv1.ProjectWebhook{}}}
			applied, err := owner.ApplyProjectConfiguration(ctx, "example", request)
			if err != nil {
				t.Fatal(err)
			}
			services := []string{}
			if mixed {
				services = []string{"api"}
			}
			directory, err := connectorruntime.NewDirectory(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			scope := connectorruntime.Context{Schema: 1, Directory: directory, ConfigDigest: strings.Repeat("c", 64), Server: server.URL, Audience: server.URL, TeamID: team, ProjectKey: "example", SourceID: fingerprint, WorktreeKey: "deployment", ProjectLabel: "app", Workload: "job", Services: services}
			assertion := issuer.Sign(t, githubtest.Claims(server.URL, time.Now().Truncate(time.Second)))
			backend := &connectorConnectionBackend{project: projectConfiguration{Project: clientproject.Project{Root: directory, Config: config.TNL{Services: config.Services{"api": {}}, Workloads: map[string]config.Workload{"job": {}}}}}, scope: scope, assertion: assertion, directory: directory, httpClient: server.Client(), parentPID: os.Getpid()}
			lifetime, cancel := context.WithCancel(ctx)
			reader, writer := io.Pipe()
			done := make(chan error, 1)
			go func() {
				err := connectorruntime.Serve(lifetime, scope, directory, "/installed/tnl", backend, writer)
				_ = writer.CloseWithError(err)
				done <- err
			}()
			t.Cleanup(func() {
				cancel()
				_ = reader.Close()
				select {
				case <-done:
				case <-time.After(20 * time.Second):
					t.Error("source owner did not join cleanup")
				}
			})
			var status connectorruntime.Status
			if err := json.NewDecoder(reader).Decode(&status); err != nil {
				t.Fatal(err)
			}
			prepared, err := applicationSnapshot(ctx, status, assertion)
			if err != nil || prepared.Validate() != nil {
				t.Fatal("authenticated native IPC could not prepare application", err)
			}
			first, err := backend.workload.Session()
			if err != nil || prepared.SourceSessionID != first.Id || prepared.Credential.KeyID != first.Application.KeyId || (len(first.ServiceIds) > 0) != mixed {
				t.Fatal("publication did not use the visitor source session", err)
			}
			var serviceID string
			for _, grant := range prepared.Credential.Grants {
				if grant.Operation == controlv1.ApplicationPublish {
					serviceID = *grant.ServiceID
				}
			}
			identity, key, err := prepared.Credential.Publisher(serviceID)
			if err != nil {
				t.Fatal(err)
			}
			control, err := clientcontrol.New(server.URL, server.Client(), "")
			if err != nil {
				t.Fatal(err)
			}
			authority, err := clientauthority.New(server.URL, server.Client(), "")
			if err != nil {
				t.Fatal(err)
			}
			native, err := publisheridentity.NewNative(control, authority, identity, key)
			if err != nil {
				t.Fatal(err)
			}
			if saved, err := native.SavedService(ctx); err != nil || saved.Id != serviceID {
				t.Fatal("session-backed native publication used personal authority or another resource", err)
			}
			if _, err := backend.Renew(ctx); err != nil {
				t.Fatal(err)
			}
			again, err := applicationSnapshot(ctx, status, "")
			if err != nil || again.SourceSessionID != prepared.SourceSessionID || again.Credential.PrivateKey != prepared.Credential.PrivateKey {
				t.Fatal("renewal replaced source identity or key", err)
			}
			policy := policies["job"]
			policy.Grants = controlv1.ProjectWorkloadGrants{Visit: &resources}
			policies["job"] = policy
			request.ExpectedRevision = applied.Revision
			if _, err := owner.ApplyProjectConfiguration(ctx, "example", request); err != nil {
				t.Fatal(err)
			}
			if _, err := native.Access(ctx); err == nil {
				t.Fatal("source retained a removed publish operation")
			}
			if _, err := backend.Renew(ctx); err != nil {
				t.Fatal(err)
			}
			narrowed, err := applicationSnapshot(ctx, status, "")
			if mixed {
				if err != nil {
					t.Fatal(err)
				}
				if _, err := narrowed.Credential.Select(controlv1.ApplicationPublish, serviceID); !errors.Is(err, credentialfile.ErrGrant) {
					t.Fatal("native source retained publication after narrowing", err)
				}
			} else if err == nil {
				t.Fatal("new visitor operation upgraded a publish-only source")
			}
			if err := Stop(ctx, status.ConnectionHandle); err != nil {
				t.Fatal(err)
			}
			if _, err := native.Access(ctx); err == nil {
				t.Fatal("publisher credential outlived joined source cleanup")
			}
		})
	}
}
