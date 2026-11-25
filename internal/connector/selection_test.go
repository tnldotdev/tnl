package connector

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestConnectConfiguredPrivateSelectionUsesExactVisitorBinding(t *testing.T) {
	const boundID = "svc_0123456789abcdefghijkl"
	root := t.TempDir()
	for _, args := range [][]string{{"init", "--quiet", root}, {"-C", root, "remote", "add", "origin", "https://example.test/connect/project.git"}} {
		if output, err := exec.CommandContext(t.Context(), "git", args...).CombinedOutput(); err != nil {
			t.Fatalf("Git fixture: %v %s", err, output)
		}
	}
	alias, group := "database", "production"
	project := projectConfiguration{Project: clientproject.Project{Root: root, Selection: clientproject.Selection{Path: filepath.Join(root, "tnl.json")}, Worktree: clientproject.Worktree{Root: root, IsGit: true}, Config: config.TNL{Services: config.Services{
		"orders": {Name: &alias, Target: &config.ServiceTarget{Type: "address", Address: new(config.Target("http://do-not-evaluate.internal"))}},
		"remote": {Name: &group},
	}}}}
	state, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	project.Project, err = project.Project.BindLocalIdentity(t.Context(), state)
	if err != nil {
		t.Fatal(err)
	}
	source, err := project.SourceIdentity(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	localSource := project.LocalPublicationIdentity()
	for _, test := range []struct {
		name, team, want string
		status           int
		omitID, corrupt  bool
		noConfig         bool
		wantReason       failure.Reason
	}{
		{name: "orders", team: "team_one", want: boundID},
		{name: alias, team: "team_one", want: boundID},
		{name: "remote", team: "team_one", want: "svc_remote"},
		{name: group, team: "team_one", want: "svc_remote"},
		{name: "remote", team: "team_one", status: 404, wantReason: failure.ServerResourceNotFound},
		{name: group, team: "team_one", omitID: true, wantReason: failure.ServerResourceNotFound},
		{name: boundID, want: boundID},
		{name: boundID, omitID: true, wantReason: failure.ServerResourceNotFound},
		{name: boundID, team: "team_other", wantReason: failure.ServerResourceNotFound},
		{name: "orders", noConfig: true, want: "svc_unrelated"},
		{name: "orders", team: "team_one", status: 404, wantReason: failure.LocalServiceUnavailable},
		{name: alias, team: "team_one", omitID: true, wantReason: failure.LocalServiceUnavailable},
		{name: "orders", team: "team_other", wantReason: failure.LocalServiceUnavailable},
		{name: "orders", team: "team_one", corrupt: true, wantReason: failure.ServerResponseInvalid},
		{name: "orders", team: "team_one", status: 409, wantReason: failure.ServerConflict},
	} {
		t.Run(test.name+"/"+test.team+"/"+test.want+"/"+string(test.wantReason), func(t *testing.T) {
			lookup, remoteLookup, inventory := 0, 0, 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer visitor-token" || r.ContentLength > 0 {
					t.Error("connector selection attempted mutation or changed visitor authentication")
				}
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/v1/projects/" + source.Key + "/services/remote":
					remoteLookup++
					if r.URL.Query().Get("source_fingerprint") != source.Fingerprint || r.URL.Query().Get("team_id") != test.team || r.URL.Query().Get("deployment") != "production" || len(r.URL.Query()) != 3 {
						t.Errorf("applied lookup scope = %s", r.URL)
					}
					if test.status != 0 {
						w.Header().Set("Content-Type", "application/problem+json")
						w.WriteHeader(test.status)
						_ = json.NewEncoder(w).Encode(controlv1.Problem{Status: test.status, Code: controlv1.NotFound, Title: "unavailable", Detail: "binding unavailable"})
						return
					}
					_ = json.NewEncoder(w).Encode(controlv1.Service{Id: "svc_remote", Name: group, TeamId: "team_one"})
				case "/v1/projects/" + localSource.Key + "/local-services/orders":
					lookup++
					if r.URL.Query().Get("source_fingerprint") != localSource.Fingerprint || r.URL.Query().Get("worktree_key") != project.LocalWorktreeKey() || r.URL.Query().Get("team_id") != test.team || len(r.URL.Query()) != 3 {
						t.Errorf("lookup scope = %s", r.URL)
					}
					if test.status != 0 {
						w.Header().Set("Content-Type", "application/problem+json")
						w.WriteHeader(test.status)
						code := controlv1.NotFound
						if test.status == 409 {
							code = controlv1.Conflict
						}
						_ = json.NewEncoder(w).Encode(controlv1.Problem{Status: test.status, Code: code, Title: "unavailable", Detail: "binding unavailable"})
						return
					}
					worktree := project.LocalWorktreeKey()
					if test.corrupt {
						worktree = "other-worktree"
					}
					_ = json.NewEncoder(w).Encode(controlv1.LocalProjectService{Service: "orders", WorktreeKey: worktree, ServiceId: boundID, Metadata: &controlv1.ServiceMetadata{Protocol: controlv1.ServiceProtocolHTTP}})
				case "/v1/visitor/services":
					inventory++
					if r.URL.Query().Get("access_path") != "connector" {
						t.Error("native selection requested public endpoint discovery")
					}
					services := []controlv1.ServiceSummary{{Id: "svc_unrelated", Name: "orders", TeamId: "team_one"}, {Id: "svc_alias", Name: alias, TeamId: "team_one"}, {Id: "svc_other_production", Name: group, TeamId: "team_one"}, {Id: "svc_worktree_b", Name: "orders-other-worktree", TeamId: "team_one"}, {Id: "svc_spoof", Name: boundID, TeamId: "team_other"}}
					if !test.omitID {
						services = append(services,
							controlv1.ServiceSummary{Id: boundID, Name: "database-scoped", TeamId: "team_one"},
							controlv1.ServiceSummary{Id: "svc_remote", Name: group, TeamId: "team_one"})
					}
					_ = json.NewEncoder(w).Encode(controlv1.ServicePage{Services: services})
				default:
					t.Errorf("connector selection requested another API: %s", r.URL)
					w.WriteHeader(500)
				}
			}))
			defer server.Close()
			control, err := clientcontrol.New(server.URL, server.Client(), "visitor-token")
			if err != nil {
				t.Fatal(err)
			}
			selectedProject := project
			if test.name == "remote" || test.name == group {
				selectedProject.Config.Deployment = group
				selectedProject.Config.Services = config.Services{"remote": project.Config.Services["remote"]}
			} else {
				selectedProject.Config.Services = config.Services{"orders": project.Config.Services["orders"]}
			}
			if test.noConfig {
				selectedProject = projectConfiguration{}
			}
			service, err := Select(t.Context(), control, selectedProject.Project, test.name, test.team)
			if test.wantReason != "" {
				if reason, ok := failure.ReasonOf(err); !ok || reason != test.wantReason {
					t.Fatalf("selection error = %v, want %s", err, test.wantReason)
				}
				if test.status == 404 && !errors.Is(err, clientcontrol.ErrNotFound) {
					t.Fatal("missing binding lost its API cause")
				}
			} else if err != nil || service.Id != test.want {
				t.Fatalf("selected %s, %v; want %s", service.Id, err, test.want)
			}
			local := !test.noConfig && (test.name == "orders" || test.name == alias)
			remote := !test.noConfig && (test.name == "remote" || test.name == group)
			if local && lookup != 1 || !local && lookup != 0 || local && (test.status != 0 || test.corrupt) && inventory != 0 {
				t.Fatalf("unexpected lookup/inventory calls: %d/%d", lookup, inventory)
			}
			expectedRemoteInventory := 0
			if remote && test.status == 0 {
				expectedRemoteInventory = 1
			}
			if remote && (remoteLookup != 1 || inventory != expectedRemoteInventory) || !remote && remoteLookup != 0 {
				t.Fatalf("applied selection did not retain its exact source-bound native identity: %d/%d", remoteLookup, inventory)
			}
		})
	}
}

func TestConnectConfiguredNameCollisionIsRejected(t *testing.T) {
	name := "orders"
	project := projectConfiguration{Project: clientproject.Project{Config: config.TNL{Services: config.Services{"orders": {}, "other": {Name: &name}}}}}
	if _, err := ConfiguredService(project.Project, name); err == nil {
		t.Fatal("key/override collision selected an arbitrary declaration")
	}
	project.Config.Services["orders"] = config.Service{Public: new(true)}
	if _, err := ConfiguredService(project.Project, name); err == nil {
		t.Fatal("override overlapping a public service key selected another declaration")
	}
	delete(project.Config.Services, "other")
	if selected, err := ConfiguredService(project.Project, name); err != nil || selected != name {
		t.Fatal("public service key did not select its configured service", selected, err)
	}
	project.Config.Deployment = "production"
	project.Config.Services["orders"] = config.Service{Public: new(true), HTTP: &config.HTTPService{Access: &config.Access{Mode: "anonymous"}}}
	if selected, err := ConfiguredService(project.Project, name); err != nil || selected != name {
		t.Fatal("HTTP visitor policy changed the selected service", err)
	}
	definition, ok := failure.DefinitionFor(failure.LocalServiceUnavailable)
	if !ok || !strings.Contains(definition.Action, "tnl publish") || definition.Retry != failure.RetryAfterChange {
		t.Fatal("missing realization has no actionable publisher diagnostic")
	}
}

func TestConnectAddressSelectsOnlyAnExactVisitorInventoryEndpoint(t *testing.T) {
	const host = "orders.example.test"
	project := clientproject.Project{Config: config.TNL{Services: config.Services{"orders": {Hostname: new(host)}}}}
	services := []controlv1.ServiceSummary{
		{Id: "svc_db", Name: "orders", TeamId: "team_one", Protocol: controlv1.Postgres, Endpoint: &controlv1.ServiceEndpoint{Hostname: host, Port: 45432}},
		{Id: "svc_tcp", Name: "raw", TeamId: "team_one", Protocol: controlv1.Tcp, Endpoint: &controlv1.ServiceEndpoint{Hostname: host, Port: 5432}},
		{Id: "svc_http", Name: "web", TeamId: "team_one", Protocol: controlv1.ServiceProtocolHTTP, Endpoint: &controlv1.ServiceEndpoint{Hostname: host, Port: 443}},
		{Id: "svc_other_team", Name: "orders", TeamId: "team_two", Protocol: controlv1.Postgres, Endpoint: &controlv1.ServiceEndpoint{Hostname: host, Port: 45432}},
		{Id: "svc_only_connector", Name: "private", TeamId: "team_one", Protocol: controlv1.Postgres, Endpoint: &controlv1.ServiceEndpoint{Hostname: "private.example.test"}},
		{Id: "svc_no_endpoint", Name: "missing.example.test", TeamId: "team_one", Protocol: controlv1.Postgres},
		{Id: "svc_suffix", Name: "suffix", TeamId: "team_one", Protocol: controlv1.Postgres, Endpoint: &controlv1.ServiceEndpoint{Hostname: "other." + host, Port: 15432}},
	}
	for _, test := range []struct {
		address, team, want string
		wantReason          failure.Reason
		rejectBeforeLookup  bool
	}{
		{address: "ORDERS.Example.Test.:45432", team: "team_one", want: "svc_db"},
		{address: "postgres://orders.example.test:45432/", team: "team_one", want: "svc_db"},
		{address: "postgresql://orders.example.test", team: "team_one", want: "svc_db"},
		{address: "postgresql://private.example.test", want: "svc_only_connector"},
		{address: "private.example.test", want: "svc_only_connector"},
		{address: "https://orders.example.test/", want: "svc_http"},
		{address: "tcp://orders.example.test:5432", want: "svc_tcp"},
		{address: "orders.example.test:45432", team: "team_two", want: "svc_other_team"},
		{address: "orders.example.test:45432", team: "team_three", wantReason: failure.ServerResourceNotFound},
		{address: "orders.example.test:45432", wantReason: failure.InvalidTunnelFlags},
		{address: "orders.example.test", team: "team_one", wantReason: failure.InvalidTunnelFlags},
		{address: "postgresql://orders.example.test:5432", team: "team_one", wantReason: failure.ServerResourceNotFound},
		{address: "https://orders.example.test:45432", team: "team_one", wantReason: failure.ServerResourceNotFound},
		{address: "orders.example.test:15432", team: "team_one", wantReason: failure.ServerResourceNotFound},
		{address: "private.example.test:5432", wantReason: failure.ServerResourceNotFound},
		{address: "missing.example.test", wantReason: failure.ServerResourceNotFound},
		{address: "https://orders/", wantReason: failure.ServerResourceNotFound},
		{address: "https://orders.example.test/api", wantReason: failure.InvalidTunnelFlags, rejectBeforeLookup: true},
		{address: "https://orders.example.test/?", wantReason: failure.InvalidTunnelFlags, rejectBeforeLookup: true},
		{address: "postgresql://orders.example.test:45432/database", wantReason: failure.InvalidTunnelFlags, rejectBeforeLookup: true},
	} {
		t.Run(test.address+"/"+test.team, func(t *testing.T) {
			reader := &deploymentSelectionReader{services: services}
			service, err := Select(t.Context(), reader, project, test.address, test.team)
			if reason, _ := failure.ReasonOf(err); service.Id != test.want || reason != test.wantReason {
				t.Fatalf("selected %q, %v (%s); want %q (%s)", service.Id, err, reason, test.want, test.wantReason)
			}
			wantCalls := 1
			if test.rejectBeforeLookup {
				wantCalls = 0
			}
			if reader.calls != wantCalls {
				t.Fatalf("visitor inventory calls = %d, want %d", reader.calls, wantCalls)
			}
		})
	}
}

func TestConnectDoesNotTreatGeneratedPsqlURLAsASavedEndpoint(t *testing.T) {
	service := controlv1.ServiceSummary{
		Id: "svc_0123456789abcdefghijkl", Name: "orders", TeamId: "team_one", Protocol: controlv1.Postgres, Enabled: true,
		Endpoint: &controlv1.ServiceEndpoint{Hostname: "orders.example.test", Port: 45432},
	}
	profile, err := serviceConnectionProfile(service, "127.0.0.1:15432")
	if err != nil {
		t.Fatal(err)
	}
	argv, err := clientArgv(profile, "psql", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		address string
		reason  failure.Reason
		calls   int
	}{
		{address: argv[1], reason: failure.InvalidTunnelFlags},
		{address: "postgresql://orders.example.test:15432/", reason: failure.ServerResourceNotFound, calls: 1},
	} {
		reader := &deploymentSelectionReader{services: []controlv1.ServiceSummary{service}}
		selected, err := Select(t.Context(), reader, clientproject.Project{}, test.address, service.TeamId)
		if reason, _ := failure.ReasonOf(err); reason != test.reason || selected.Id != "" || reader.calls != test.calls {
			t.Fatalf("local dial address %q selected %q (%v); %d inventory calls", test.address, selected.Id, err, reader.calls)
		}
	}
}
