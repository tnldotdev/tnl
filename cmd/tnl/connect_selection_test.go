package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestConnectConfiguredPrivateSelectionUsesExactVisitorBinding(t *testing.T) {
	root := t.TempDir()
	for _, args := range [][]string{{"init", "--quiet", root}, {"-C", root, "remote", "add", "origin", "https://example.test/connect/project.git"}} {
		if output, err := exec.CommandContext(t.Context(), "git", args...).CombinedOutput(); err != nil {
			t.Fatalf("Git fixture: %v %s", err, output)
		}
	}
	alias, group := "database", "production"
	project := projectConfiguration{Project: projectconfig.Project{Root: root, Selection: projectconfig.Selection{Path: filepath.Join(root, "tnl.json")}, Worktree: projectconfig.Worktree{Root: root, IsGit: true}, Config: config.TNL{Services: config.Services{
		"orders": {Name: &alias, Target: &config.ServiceTarget{Type: "address", Address: testTarget("http://do-not-evaluate.internal")}},
		"remote": {Name: &group, Publisher: &group},
	}}}}
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
		{name: "orders", team: "team_one", want: "svc_bound"},
		{name: alias, team: "team_one", want: "svc_bound"},
		{name: "remote", team: "team_one", want: "svc_remote"},
		{name: group, team: "team_one", want: "svc_remote"},
		{name: "remote", team: "team_one", status: 404, wantReason: failure.ServerResourceNotFound},
		{name: "svc_bound", want: "svc_bound"},
		{name: "orders", noConfig: true, want: "svc_unrelated"},
		{name: "orders", team: "team_one", status: 404, wantReason: failure.LocalPrivateServiceUnavailable},
		{name: alias, team: "team_one", omitID: true, wantReason: failure.LocalPrivateServiceUnavailable},
		{name: "orders", team: "team_other", wantReason: failure.LocalPrivateServiceUnavailable},
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
				case "/v1/projects/" + source.Key + "/private-services/remote":
					remoteLookup++
					if r.URL.Query().Get("source_fingerprint") != source.Fingerprint || r.URL.Query().Get("team_id") != test.team || len(r.URL.Query()) != 2 {
						t.Errorf("applied lookup scope = %s", r.URL)
					}
					if test.status != 0 {
						w.Header().Set("Content-Type", "application/problem+json")
						w.WriteHeader(test.status)
						_ = json.NewEncoder(w).Encode(controlv1.Problem{Status: test.status, Code: controlv1.NotFound, Title: "unavailable", Detail: "binding unavailable"})
						return
					}
					_ = json.NewEncoder(w).Encode(controlv1.PrivateService{Id: "svc_remote", Name: group, TeamId: "team_one"})
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
					_ = json.NewEncoder(w).Encode(controlv1.LocalProjectService{Service: "orders", WorktreeKey: worktree, ServiceKind: controlv1.LocalProjectServiceServiceKindPrivateService, ServiceId: "svc_bound", PrivateService: &controlv1.PrivateServiceMetadata{Protocol: controlv1.PrivateHttp}})
				case "/v1/visitor/private-services":
					inventory++
					services := []controlv1.PrivateService{{Id: "svc_unrelated", Name: "orders", TeamId: "team_one"}, {Id: "svc_alias", Name: alias, TeamId: "team_one"}, {Id: "svc_remote", Name: group, TeamId: "team_one"}, {Id: "svc_worktree_b", Name: "orders-other-worktree", TeamId: "team_one"}, {Id: "svc_spoof", Name: "svc_bound", TeamId: "team_one"}}
					if !test.omitID {
						services = append(services, controlv1.PrivateService{Id: "svc_bound", Name: "database-scoped", TeamId: "team_one"})
					}
					_ = json.NewEncoder(w).Encode(controlv1.PrivateServicePage{Services: services})
				default:
					t.Errorf("connector selection requested another API: %s", r.URL)
					w.WriteHeader(500)
				}
			}))
			defer server.Close()
			control, err := controlclient.New(server.URL, server.Client(), "visitor-token")
			if err != nil {
				t.Fatal(err)
			}
			selectedProject := project
			if test.noConfig {
				selectedProject = projectConfiguration{}
			}
			service, err := selectConnectService(t.Context(), control, selectedProject, test.name, test.team)
			if test.wantReason != "" {
				if reason, ok := failure.ReasonOf(err); !ok || reason != test.wantReason {
					t.Fatalf("selection error = %v, want %s", err, test.wantReason)
				}
				if test.status == 404 && !errors.Is(err, controlclient.ErrNotFound) {
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
			if remote && (remoteLookup != 1 || inventory != 0) || !remote && remoteLookup != 0 {
				t.Fatalf("applied selection fell back to friendly inventory: %d/%d", remoteLookup, inventory)
			}
		})
	}
}

func TestConnectConfiguredNameCollisionIsRejected(t *testing.T) {
	name := "orders"
	project := projectConfiguration{Project: projectconfig.Project{Config: config.TNL{Services: config.Services{"orders": {}, "other": {Name: &name}}}}}
	if _, err := configuredConnectService(project, name); err == nil {
		t.Fatal("key/override collision selected an arbitrary declaration")
	}
	project.Config.Services["orders"] = config.Service{Tunnel: &config.Tunnel{}}
	if _, err := configuredConnectService(project, name); err == nil {
		t.Fatal("override overlapping a public service key selected another declaration")
	}
	delete(project.Config.Services, "other")
	if _, err := configuredConnectService(project, name); err == nil {
		t.Fatal("public service key fell back to another project's friendly name")
	}
	group := "production"
	project.Config.Services["orders"] = config.Service{Publisher: &group, Tunnel: &config.Tunnel{}}
	if selected, err := configuredConnectService(project, name); err != nil || selected != name {
		t.Fatal("named managed HTTP policy was mistaken for a public URL", err)
	}
	definition, ok := failure.DefinitionFor(failure.LocalPrivateServiceUnavailable)
	if !ok || !strings.Contains(definition.Action, "tnl publish") || definition.Retry != failure.RetryAfterChange {
		t.Fatal("missing realization has no actionable publisher diagnostic")
	}
}

func TestConnectKeyAndOverrideUseEffectiveServerAndTeam(t *testing.T) {
	rootServer, rootTeam := "https://root.example.test", "root-team"
	alias := "database"
	project := projectConfiguration{Project: projectconfig.Project{Config: config.TNL{Server: &rootServer, Team: &rootTeam, Services: config.Services{
		"orders": {Name: &alias},
	}}}}
	for _, name := range []string{"orders", alias, "psvc_arbitrary"} {
		flags := connectStartCommand{Name: name}
		if err := project.applyConnect(&flags); err != nil {
			t.Fatal(err)
		}
		if flags.ServerURL != rootServer || flags.ProjectTeam != rootTeam {
			t.Fatalf("%s selected %s/%s, want %s/%s", name, flags.ServerURL, flags.ProjectTeam, rootServer, rootTeam)
		}
	}
	flags := connectStartCommand{Name: alias, scopedTeamFlags: scopedTeamFlags{remoteFlags: remoteFlags{ServerURL: "https://explicit.example.test"}, teamSelectionFlags: teamSelectionFlags{Team: "explicit-team"}}}
	if err := project.applyConnect(&flags); err != nil || flags.ServerURL != "https://explicit.example.test" || flags.selection().SelectedTeam != "explicit-team" || flags.ProjectTeam != "" {
		t.Fatal("explicit scope retained another server's project team", flags.scopedTeamFlags, err)
	}
}
