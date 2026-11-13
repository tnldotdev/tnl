package invocation

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/naming"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestLocalServiceRealizationKeepsIdentityAcrossGitTransitions(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "development.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"tnl":{"services":{
		"api":{"target":{"type":"address","address":"http://127.0.0.1:3000"},"access":{"team":true}},
		"web":{"target":{"type":"address","address":"http://127.0.0.1:3000"},"public_url":{},"access":{"team":true}},
		"sdk":{"access":{"team":true}}
	}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	type received struct {
		project string
		request controlv1.RealizeLocalProjectServiceRequest
	}
	requests := make(chan received, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /v1/projects/{project}/local-services/{service}", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fixture-token" {
			t.Error("realization lost its control credential")
		}
		var request controlv1.RealizeLocalProjectServiceRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		requests <- received{r.PathValue("project"), request}
		name := r.PathValue("service")
		response := controlv1.LocalProjectService{Service: name, WorktreeKey: request.WorktreeKey, ServiceId: "svc_" + name, ServiceKind: "service"}
		if request.PublicUrlId != nil {
			response.ServiceId, response.ServiceKind = *request.PublicUrlId, "public_url"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()
	control, err := clientcontrol.New(server.URL, server.Client(), "fixture-token")
	if err != nil {
		t.Fatal(err)
	}
	current := NewTeamSelection(authorityv1.Team{Id: "team_1"}, authorityv1.Membership{}, nil, naming.ManagedURLModeSimple)
	original := map[string]received{}
	for _, phase := range []struct {
		name string
		git  []string
	}{
		{name: "without git"},
		{name: "git init", git: []string{"init", "--quiet", root}},
		{name: "first origin", git: []string{"-C", root, "remote", "add", "origin", "https://example.test/first.git"}},
		{name: "changed origin", git: []string{"-C", root, "remote", "set-url", "origin", "https://elsewhere.test/second.git"}},
	} {
		t.Run(phase.name, func(t *testing.T) {
			if phase.git != nil {
				if output, err := exec.CommandContext(t.Context(), "git", phase.git...).CombinedOutput(); err != nil {
					t.Fatalf("Git transition: %v\n%s", err, output)
				}
			}
			project, err := clientproject.Resolve(t.Context(), clientproject.Selection{Path: path}, root, [32]byte{1})
			if err != nil {
				t.Fatal(err)
			}
			encoded, _, err := project.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			project, err = clientproject.ReadSnapshot(bytes.NewReader(encoded))
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"api", "web", "sdk"} {
				selected := LocalService{Project: project, Team: current, Name: name}
				if name == "web" {
					selected.PublicURLID = "url_web"
				}
				if _, err := RealizeLocalService(t.Context(), control, selected); err != nil {
					t.Fatal(err)
				}
				got := <-requests
				source := project.LocalPublicationIdentity()
				if got.project != source.Key || got.request.SourceFingerprint != source.Fingerprint || got.request.WorktreeKey != project.LocalWorktreeKey() || got.request.TeamId != "team_1" || got.request.Configuration.Access == nil || !bool(got.request.Configuration.Access.Team) {
					t.Fatalf("%s lost its local scope or team access: %+v", name, got)
				}
				wantTarget := "http://127.0.0.1:3000"
				if name == "sdk" {
					wantTarget = "app"
				}
				if got.request.Configuration.Target != wantTarget || (got.request.Configuration.PublicUrl != nil) != (name == "web") || (got.request.PublicUrlId != nil) != (name == "web") {
					t.Fatalf("%s changed its declaration: %+v", name, got.request)
				}
				if first, found := original[name]; found {
					if !reflect.DeepEqual(got, first) {
						t.Fatalf("%s realization changed across Git transition:\n%+v\n%+v", name, first, got)
					}
				} else {
					original[name] = got
				}
			}
		})
	}
}
