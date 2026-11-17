package invocation

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/publisher/target"
	"github.com/tnldotdev/tnl/internal/testutil"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestLocalServiceRealizationKeepsIdentityAcrossGitTransitions(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "development.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"tnl":{"services":{"api":{},"web":{},"sdk":{}},"deployments":{"local":{"targets":{
		"api":{"address":"http://127.0.0.1:3000","public":false,"access":{"team":true},"http":{"access":"anonymous"}},
		"web":{"address":"http://127.0.0.1:3000","public":true,"hostname":"web.preview.example.test","domain":"preview.example.test","ephemeral":true,"require_post_quantum":true,
			"traffic":{"connections":8,"rate":2,"rate_per":"1s"},"access":{"team":true},
			"http":{"access":{"mode":"restricted","ip":["192.0.2.1"]},"limits":{"total":100,"concurrency":2,"rate":{"count":5,"per":"2m","burst":2}},"readiness":{"path":"/health"}}},
		"sdk":{"access":{"team":true}}
	}}}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	type received struct {
		project string
		request controlv1.RealizeLocalProjectServiceRequest
	}
	requests := make(chan received, 1)
	serviceIDs := map[string]string{
		"api": "svc_0123456789abcdefghijkl",
		"web": "svc_1123456789abcdefghijkl",
		"sdk": "svc_2123456789abcdefghijkl",
	}
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /v1/projects/{project}/local-services/{service}", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fixture-token" {
			t.Error("realization lost its control credential")
		}
		var request controlv1.RealizeLocalProjectServiceRequest
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		requests <- received{r.PathValue("project"), request}
		name := r.PathValue("service")
		response := controlv1.LocalProjectService{Service: name, WorktreeKey: request.WorktreeKey, ServiceId: serviceIDs[name]}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()
	control, err := clientcontrol.New(server.URL, server.Client(), "fixture-token")
	if err != nil {
		t.Fatal(err)
	}
	current := NewTeamSelection(authorityv1.Team{Id: "team_1"}, authorityv1.Membership{}, []authorityv1.Domain{
		{Id: "domain_preview", CanonicalDomain: "preview.example.test", Kind: authorityv1.Custom, State: authorityv1.DomainStateReady},
		{Id: "domain_alternate", CanonicalDomain: "alternate.example.test", Kind: authorityv1.Custom, State: authorityv1.DomainStateReady},
	}, naming.ManagedURLModeSimple)
	original := map[string]received{}
	state, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
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
			project, err = project.BindLocalIdentity(t.Context(), state)
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
				if name == "api" {
					selected.Domain = "alternate.example.test"
				}
				realized, err := RealizeLocalService(t.Context(), control, selected)
				if err != nil || realized.ServiceId != serviceIDs[name] {
					t.Fatal("realization did not return the selected service", realized, err)
				}
				got := <-requests
				source := project.LocalPublicationIdentity()
				if got.project != source.Key || got.request.SourceFingerprint != source.Fingerprint || got.request.WorktreeKey != project.LocalWorktreeKey() || got.request.TeamId != "team_1" || got.request.Configuration.Access == nil || !bool(got.request.Configuration.Access.Team) {
					t.Fatalf("%s lost its local scope or team access: %+v", name, got)
				}
				wantTarget := "app"
				declaration := got.request.Configuration
				if declaration.Target != wantTarget || declaration.Protocol == nil || *declaration.Protocol != "http" || declaration.Name == nil || *declaration.Name != name {
					t.Fatalf("%s changed its declaration: %+v", name, got.request)
				}
				definition := project.Config.Services[name]
				if !reflect.DeepEqual(declaration.Public, definition.Public) || !reflect.DeepEqual(declaration.Hostname, definition.Hostname) ||
					!reflect.DeepEqual(declaration.Ephemeral, definition.Ephemeral) || !reflect.DeepEqual(declaration.RequirePostQuantum, definition.RequirePostQuantum) {
					t.Fatalf("%s lost its direct service settings: %+v", name, declaration)
				}
				switch name {
				case "api":
					if declaration.DomainId == nil || *declaration.DomainId != "domain_alternate" || declaration.Http == nil || declaration.Http.Access == nil || declaration.Http.Access.Mode == nil || *declaration.Http.Access.Mode != "anonymous" || declaration.Traffic != nil {
						t.Fatalf("connector-only HTTP lost its domain override or independent visitor policy: %+v", declaration)
					}
				case "web":
					if declaration.DomainId == nil || *declaration.DomainId != "domain_preview" || declaration.Traffic == nil ||
						declaration.Traffic.Connections == nil || *declaration.Traffic.Connections != 8 || declaration.Traffic.Rate == nil || *declaration.Traffic.Rate != 2 ||
						declaration.Traffic.RatePer == nil || *declaration.Traffic.RatePer != "1s" || declaration.Traffic.Burst != nil {
						t.Fatalf("public HTTP lost its direct domain or traffic selection: %+v", declaration)
					}
					http := declaration.Http
					if http == nil || http.Access == nil || http.Access.Mode == nil || *http.Access.Mode != "restricted" ||
						http.Access.Ip == nil || !reflect.DeepEqual(*http.Access.Ip, []string{"192.0.2.1/32"}) ||
						http.Limits == nil || http.Limits.Total == nil || *http.Limits.Total != 100 || http.Limits.Concurrency == nil || *http.Limits.Concurrency != 2 ||
						http.Limits.Rate == nil || http.Limits.Rate.Count != 5 || http.Limits.Rate.Per != "2m0s" || http.Limits.Rate.Burst == nil || *http.Limits.Rate.Burst != 2 ||
						http.Readiness != nil || http.Paths != nil || http.Open != nil {
						t.Fatalf("public HTTP lost shared policy or retained local settings: %+v", http)
					}
				case "sdk":
					if declaration.DomainId != nil || declaration.Http != nil || declaration.Traffic != nil || declaration.TargetTls != nil {
						t.Fatalf("app declaration inherited publication or target settings: %+v", declaration)
					}
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

func TestLocalServiceRealizationRejectsAnotherServiceOrWorktree(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*controlv1.LocalProjectService)
	}{
		{"service", func(value *controlv1.LocalProjectService) { value.Service = "another" }},
		{"worktree", func(value *controlv1.LocalProjectService) { value.WorktreeKey = "another" }},
		{"missing ID", func(value *controlv1.LocalProjectService) { value.ServiceId = "" }},
		{"malformed ID", func(value *controlv1.LocalProjectService) { value.ServiceId = "svc_invalid" }},
		{"public URL ID", func(value *controlv1.LocalProjectService) { value.ServiceId = "url_0123456789abcdefghijkl" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var request controlv1.RealizeLocalProjectServiceRequest
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Error(err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				response := controlv1.LocalProjectService{Service: "web", WorktreeKey: request.WorktreeKey, ServiceId: "svc_0123456789abcdefghijkl"}
				test.change(&response)
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(response)
			}))
			defer server.Close()
			control, err := clientcontrol.New(server.URL, server.Client(), "fixture-token")
			if err != nil {
				t.Fatal(err)
			}
			project := clientproject.Project{Root: t.TempDir(), Config: config.TNL{Services: config.Services{"web": {}}}}
			project = bindLocalServiceTestProject(t, project)
			current := NewTeamSelection(authorityv1.Team{Id: "team_1"}, authorityv1.Membership{}, nil, naming.ManagedURLModeSimple)
			_, err = RealizeLocalService(t.Context(), control, LocalService{Project: project, Team: current, Name: "web"})
			if reason, ok := failure.ReasonOf(err); !ok || reason != failure.ServerResponseInvalid {
				t.Fatal("realization accepted another service or lost its failure code", err)
			}
		})
	}
}

func TestLocalServiceRealizationCapturesOnlySelectedTargetTrust(t *testing.T) {
	ca, _ := testutil.TLSCertificate(t, []string{"target.internal"}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	project := clientproject.Project{Root: t.TempDir(), Config: config.TNL{Services: config.Services{
		"web": {Public: new(true), Target: &config.ServiceTarget{Type: "docker", Container: new("selected"), Port: new(8443),
			TLS: &config.TargetTLS{Hostname: new("target.internal"), CA: new(string(ca))}}},
		"other": {Target: &config.ServiceTarget{Type: "docker", Container: new("unselected"), Port: new(443),
			TLS: &config.TargetTLS{CA: new("system")}}},
	}}}
	project = bindLocalServiceTestProject(t, project)
	const address = "https://127.0.0.1:8443"
	var resolved []string
	resolver := target.TargetResolverFunc(func(_ context.Context, _ clientproject.Project, name string) (string, string, error) {
		resolved = append(resolved, name)
		if name != "web" {
			return "", "", errors.New("unselected target was discovered")
		}
		return "127.0.0.1:8443", "selected-container", nil
	})
	requests := make(chan controlv1.RealizeLocalProjectServiceRequest, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /v1/projects/{project}/local-services/web", func(w http.ResponseWriter, r *http.Request) {
		var request controlv1.RealizeLocalProjectServiceRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		requests <- request
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(controlv1.LocalProjectService{Service: "web", WorktreeKey: request.WorktreeKey, ServiceId: "svc_0123456789abcdefghijkl"})
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()
	control, err := clientcontrol.New(server.URL, server.Client(), "fixture-token")
	if err != nil {
		t.Fatal(err)
	}
	current := NewTeamSelection(authorityv1.Team{Id: "team_1"}, authorityv1.Membership{}, nil, naming.ManagedURLModeSimple)
	selected := LocalService{Project: project, Team: current, Name: "web", TargetResolver: resolver}
	if _, err := RealizeLocalService(t.Context(), control, selected); err != nil {
		t.Fatal(err)
	}
	request := <-requests
	want, err := project.CaptureServiceTrust(t.Context(), "web", address)
	if err != nil {
		t.Fatal(err)
	}
	declaration, err := want.Declaration()
	if err != nil {
		t.Fatal(err)
	}
	trust := request.Configuration.TargetTls
	if !reflect.DeepEqual(resolved, []string{"web"}) || request.Configuration.Target != "app" ||
		trust == nil || trust.Hostname != declaration.Hostname || trust.Digest != declaration.Digest || trust.CaPem == nil || *trust.CaPem != string(want.PEM) {
		t.Fatal("realization lost selected portable target trust or sent a discovered address", resolved, request.Configuration)
	}
	project.Config.Services["web"].Target.TLS.CA = new("invalid CA")
	if _, err := RealizeLocalService(t.Context(), control, selected); err == nil {
		t.Fatal("invalid selected target trust reached realization")
	}
	select {
	case <-requests:
		t.Fatal("invalid target trust sent a control mutation")
	default:
	}
}

func bindLocalServiceTestProject(t *testing.T, project clientproject.Project) clientproject.Project {
	t.Helper()
	state, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	project, err = project.BindLocalIdentity(t.Context(), state)
	if err != nil {
		t.Fatal(err)
	}
	return project
}

func TestLocalServiceRealizationRejectsUnavailableDomainBeforeRequest(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("unavailable domain sent a control mutation")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	control, err := clientcontrol.New(server.URL, server.Client(), "fixture-token")
	if err != nil {
		t.Fatal(err)
	}
	project := clientproject.Project{Root: t.TempDir(), Config: config.TNL{Services: config.Services{"web": {}}}}
	project = bindLocalServiceTestProject(t, project)
	current := NewTeamSelection(authorityv1.Team{Id: "team_1"}, authorityv1.Membership{}, nil, naming.ManagedURLModeSimple)
	_, err = RealizeLocalService(t.Context(), control, LocalService{Project: project, Team: current, Name: "web", Domain: "unavailable.example.test"})
	if reason, ok := failure.ReasonOf(err); !ok || reason != failure.DomainNotAvailable {
		t.Fatal("unavailable domain was accepted or lost its failure code", err)
	}
}
