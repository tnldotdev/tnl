package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/client/auth"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	clientteam "github.com/tnldotdev/tnl/internal/client/team"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

const (
	shareTestService = "svc_0123456789abcdefghijkl"
	shareTestInvite  = "sivt_0123456789abcdefghijkl"
	shareTestGrant   = "sgr_0123456789abcdefghijkl"
	shareTestHTTP    = "shg_0123456789abcdefghijkl"
	shareTestShare   = "shr_0123456789abcdefghijkl"
	shareTestTeam    = "tm_0123456789abcdefghijkl"
	shareTestPerson  = "ident_0123456789abcdefghijkl"
)

func serviceShareTestClient(t *testing.T, handler http.HandlerFunc) *clientcontrol.Client {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expectedAccess := "Bearer current-person"
		if r.URL.Path == "/v1/visitor-tokens" {
			expectedAccess = ""
		}
		if r.Header.Get("Authorization") != expectedAccess {
			t.Error("service access did not use the current person's control session")
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && r.URL.Path == "/v1/shares" {
			_, _ = io.WriteString(w, `{"schema_version":1,"shares":[]}`)
			return
		}
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	client, err := clientcontrol.New(server.URL, server.Client(), "current-person")
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestServiceShareSyntaxAndEarlyValidation(t *testing.T) {
	for _, test := range []struct {
		args []string
		want string
	}{
		{[]string{"invite", "create", "orders", "--email=visitor@example.test", "--expires-in=4h"}, "invite create <name>"},
		{[]string{"invite", "accept", "secret", "--output=json"}, "invite accept <secret>"},
		{[]string{"list", "orders", "--output=json"}, "list <name>"},
		{[]string{"revoke", "orders", shareTestInvite}, "revoke <name> <access-id>"},
		{[]string{"link", "create", "orders", "--expires-at=2027-01-01T00:00:00Z"}, "link create <name>"},
		{[]string{"token", "create", shareTestService, "--expires-in=1h"}, "token create <name>"},
	} {
		var flags cli
		parser := commandForTest(&flags, io.Discard)
		parsed, err := parser(append([]string{"share", "service"}, test.args...))
		if err != nil || commandID(parsed) != "share service "+test.want || !projectSensitiveCommand(commandID(parsed)) {
			t.Fatalf("service command %v: %v, %v", test.args, parsed, err)
		}
	}
	for _, args := range [][]string{
		{"invite", "create", shareTestService, "--email=visitor@example.test"},
		{"invite", "create", shareTestService, "--email=visitor@example.test", "--expires-in=31d"},
		{"invite", "create", shareTestService, "--email=visitor@example.test", "--expires-in=1h", "--expires-at=2027-01-01T00:00:00Z"},
		{"invite", "create", shareTestService, "--email=visitor@example.test", "--expires-in=1h", "--idempotency-key=stable-key"},
		{"invite", "create", shareTestService, "--email=visitor@example.test", "--expires-at=2027-01-01T00:00:00Z", "--idempotency-key=" + strings.Repeat("a", 129)},
		{"token", "create", shareTestService, "--expires-in=8d"},
		{"link", "create", shareTestService, "--expires-at=2020-01-01T00:00:00Z"},
		{"invite", "accept", "shr_0123456789abcdefghijkl." + strings.Repeat("A", 43)},
		{"revoke", shareTestService, "not-an-access-id"},
		{"list", "unconfigured-friendly-name"},
	} {
		var output, diagnostics bytes.Buffer
		arguments := append([]string{"--no-config", "share", "service"}, args...)
		arguments = append(arguments, "--state-dir="+filepath.Join(t.TempDir(), "state"))
		err := run(t.Context(), arguments, &output, &diagnostics)
		if reason, ok := failure.ReasonOf(err); !ok || reason != failure.InvalidCommand || output.Len() != 0 || diagnostics.Len() != 0 {
			t.Fatalf("invalid service command %v: %v, stdout=%q stderr=%q", args, err, &output, &diagnostics)
		}
	}
}

func TestServiceShareDeadlineMatchesServerBounds(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 123456789, time.UTC)
	for _, f := range []serviceShareDeadline{{ExpiresIn: "30d"}, {ExpiresAt: now.Add(30 * 24 * time.Hour).Format(time.RFC3339Nano)}} {
		at, err := f.deadline(now, 30*24*time.Hour)
		if err != nil || !at.Equal(now.Add(30*24*time.Hour).Truncate(time.Microsecond)) {
			t.Fatalf("invitation deadline = %s, %v", at, err)
		}
		if _, err := f.deadline(now, 7*24*time.Hour); err == nil {
			t.Fatal("service HTTP deadline exceeded seven days")
		}
	}
}

func TestServiceShareSelectionUsesSourceBindingAndManagerRead(t *testing.T) {
	root := t.TempDir()
	for _, args := range [][]string{{"init", "--quiet", root}, {"-C", root, "remote", "add", "origin", "https://example.test/share/project.git"}} {
		if output, err := exec.CommandContext(t.Context(), "git", args...).CombinedOutput(); err != nil {
			t.Fatalf("Git fixture: %v %s", err, output)
		}
	}
	saved, deployment := "orders-saved", "production"
	project := projectConfiguration{Project: clientproject.Project{Root: root, Selection: clientproject.Selection{Path: filepath.Join(root, "tnl.json")}, Worktree: clientproject.Worktree{Root: root, IsGit: true}, Config: config.TNL{Services: config.Services{
		"orders": {Name: &saved}, "remote": {HTTP: &config.HTTPService{}, Target: &config.ServiceTarget{Type: "address", Address: new(config.Target("http://app.internal:3000"))}}, "web": {Public: new(true)},
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
	for _, selector := range []string{"orders", "remote", shareTestService, saved, deployment, "web", "url_0123456789abcdefghijkl"} {
		t.Run(selector, func(t *testing.T) {
			lookups, reads := 0, 0
			scope := controlv1.LocalServiceSource{ProjectKey: source.Key, SourceFingerprint: source.Fingerprint, Service: selector}
			if selector == "orders" || selector == "web" {
				local := project.LocalPublicationIdentity()
				scope.ProjectKey, scope.SourceFingerprint = local.Key, local.Fingerprint
				scope.WorktreeKey = project.LocalWorktreeKey()
			}
			control := serviceShareTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Error("selection mutated server state")
					w.WriteHeader(500)
					return
				}
				switch r.URL.Path {
				case "/v1/projects/" + source.Key + "/deployments/production":
					lookups++
					if selector != "remote" || r.URL.Query().Get("team_id") != shareTestTeam {
						t.Error("deployment lookup lost its exact scope")
					}
					_ = json.NewEncoder(w).Encode(controlv1.Deployment{TeamId: shareTestTeam, ProjectKey: source.Key, Services: map[string]controlv1.DeploymentService{"remote": {Id: shareTestService}}})
				case "/v1/services":
					lookups++
					if r.URL.Query().Get("team_id") != shareTestTeam {
						t.Error("manager inventory lost its selected team")
					}
					if r.URL.Query().Get("cursor") == "" {
						other := scope
						other.ProjectKey = "another-project"
						_ = json.NewEncoder(w).Encode(controlv1.ServicePage{Services: []controlv1.ServiceSummary{{Id: "svc_abcdefghijkl0123456789", Name: selector, TeamId: shareTestTeam, Source: &other}}, NextCursor: new("next")})
					} else {
						_ = json.NewEncoder(w).Encode(controlv1.ServicePage{Services: []controlv1.ServiceSummary{{Id: shareTestService, Name: "saved-name", TeamId: shareTestTeam, Source: &scope}}})
					}
				case "/v1/services/" + shareTestService:
					reads++
					_ = json.NewEncoder(w).Encode(controlv1.Service{Id: shareTestService, TeamId: shareTestTeam, Protocol: "http", Source: &scope})
				default:
					t.Errorf("selection requested a visitor, public URL, or unrelated API: %s", r.URL)
					w.WriteHeader(500)
				}
			})
			s := clientteam.NewSession(nil, nil, &auth.Client{Control: control}, authorityv1.IdentityContext{Memberships: []authorityv1.Membership{{TeamId: shareTestTeam}}}, clientteam.Options{SelectedTeam: shareTestTeam})
			selectedProject := project
			if selector == "remote" {
				selectedProject.Config.Deployment = deployment
				selectedProject.Config.Services = config.Services{"remote": project.Config.Services["remote"]}
			} else {
				selectedProject.Config.Services = config.Services{"orders": project.Config.Services["orders"], "web": project.Config.Services["web"]}
			}
			service, err := selectServiceShare(t.Context(), s, selectedProject, selector)
			valid := selector == "orders" || selector == "web" || selector == "remote" || selector == shareTestService
			if valid {
				wantLookups := 0
				if selector == "orders" || selector == "web" {
					wantLookups = 2
				}
				if selector == "remote" {
					wantLookups = 1
				}
				if err != nil || service.Id != shareTestService || reads != 1 || lookups != wantLookups {
					t.Fatalf("exact service selection = %+v, %v; lookups=%d reads=%d", service, err, lookups, reads)
				}
			} else if err == nil || lookups != 0 || reads != 0 {
				t.Fatalf("non-key selector reached the server: %s %v", selector, err)
			}
		})
	}
	for _, test := range []struct {
		name   string
		reason failure.Reason
	}{
		{"missing source", failure.ServerResourceNotFound},
		{"project", failure.ServerResourceNotFound},
		{"fingerprint", failure.ServerResourceNotFound},
		{"key", failure.ServerResourceNotFound},
		{"worktree", failure.ServerResourceNotFound},
		{"wrong team", failure.ServerResponseInvalid},
		{"invalid ID", failure.ServerResponseInvalid},
		{"ambiguous", failure.InvalidCommand},
		{"binding changed", failure.ServerResponseInvalid},
		{"binding removed", failure.ServerResourceNotFound},
		{"manager denied", failure.ServerResourceNotFound},
	} {
		t.Run(test.name, func(t *testing.T) {
			local := project.LocalPublicationIdentity()
			scope := &controlv1.LocalServiceSource{ProjectKey: local.Key, SourceFingerprint: local.Fingerprint, Service: "orders", WorktreeKey: project.LocalWorktreeKey()}
			switch test.name {
			case "missing source":
				scope = nil
			case "project":
				scope.ProjectKey = "another-project"
			case "fingerprint":
				scope.SourceFingerprint = strings.Repeat("f", 64)
			case "key":
				scope.Service = "another-key"
			case "worktree":
				scope.WorktreeKey = "another-worktree"
			}
			reads := 0
			control := serviceShareTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Error("failed selection mutated server state")
				}
				item := controlv1.Service{Id: shareTestService, Name: "orders", TeamId: shareTestTeam, Source: scope}
				switch r.URL.Path {
				case "/v1/services":
					if test.name == "manager denied" {
						w.WriteHeader(http.StatusNotFound)
						_, _ = io.WriteString(w, `{"code":"not_found"}`)
						return
					}
					if test.name == "wrong team" {
						item.TeamId = "tm_abcdefghijkl0123456789"
					}
					if test.name == "invalid ID" {
						item.Id = ""
					}
					items := []controlv1.ServiceSummary{{Id: item.Id, TeamId: item.TeamId, Name: item.Name, Source: item.Source}}
					if test.name == "ambiguous" {
						item.Id = "svc_abcdefghijkl0123456789"
						items = append(items, controlv1.ServiceSummary{Id: item.Id, TeamId: item.TeamId, Name: item.Name, Source: item.Source})
					}
					_ = json.NewEncoder(w).Encode(controlv1.ServicePage{Services: items})
				case "/v1/services/" + shareTestService:
					reads++
					if test.name == "binding removed" {
						w.WriteHeader(http.StatusNotFound)
						_, _ = io.WriteString(w, `{"code":"not_found"}`)
						return
					}
					item.Source = new(*scope)
					item.Source.WorktreeKey = "another-worktree"
					_ = json.NewEncoder(w).Encode(item)
				default:
					t.Errorf("failed source binding fell back to another API: %s", r.URL)
					w.WriteHeader(500)
				}
			})
			s := clientteam.NewSession(nil, nil, &auth.Client{Control: control}, authorityv1.IdentityContext{Memberships: []authorityv1.Membership{{TeamId: shareTestTeam}}}, clientteam.Options{SelectedTeam: shareTestTeam})
			_, err := selectServiceShare(t.Context(), s, project, "orders")
			if reason, ok := failure.ReasonOf(err); !ok || reason != test.reason {
				t.Fatalf("unsafe source selection = %v; want %s", err, test.reason)
			}
			wantReads := 0
			if test.name == "binding changed" || test.name == "binding removed" {
				wantReads = 1
			}
			if reads != wantReads {
				t.Fatalf("failed inventory selection read %d services, want %d", reads, wantReads)
			}
		})
	}
	server, team := "https://control.example.test", "shop"
	project.Config.Server, project.Config.Team = &server, &team
	var flags cli
	flags.Share.Service.List.Name = "remote"
	if err := applyProjectCommandContext("share service list <name>", project, &flags); err != nil || flags.Share.Service.List.ServerURL != server || flags.Share.Service.List.ProjectTeam != team {
		t.Fatal("service share did not inherit project scope", err)
	}
	flags.Share.Service.List.ServerURL = "https://other.example.test"
	if err := applyProjectCommandContext("share service list <name>", project, &flags); err != nil || flags.Share.Service.List.ProjectTeam != "" {
		t.Fatal("explicit server retained another server's project team", err)
	}
}

func TestServiceShareCommandsSelectTheirExactDeployment(t *testing.T) {
	for _, args := range [][]string{
		{"invite", "create", "db", "--email=reviewer@example.test", "--expires-in=1h"},
		{"list", "db"},
		{"revoke", "db", shareTestGrant},
		{"link", "create", "db", "--expires-in=1h"},
		{"token", "create", "db", "--expires-in=1h"},
	} {
		var flags cli
		parser := commandForTest(&flags, io.Discard)
		command := append([]string{"share", "service"}, args...)
		command = append(command, "--deployment", "staging")
		if _, err := parser(command); err != nil {
			t.Fatal(err)
		}
		if projectOptions(flags).Deployment != "staging" {
			t.Fatal("share command borrowed the default deployment", args)
		}
	}
}

func TestServiceShareInvitationResponsesCannotWidenScopeOrLeakSecrets(t *testing.T) {
	at := time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)
	secret := shareTestInvite + "." + strings.Repeat("A", 43)
	for _, operation := range []string{"create", "accept", "list"} {
		control := serviceShareTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			switch operation {
			case "create":
				_ = json.NewEncoder(w).Encode(controlv1.ServiceInvitationCreation{Invitation: controlv1.ServiceInvitation{Id: shareTestInvite, ServiceId: "svc_abcdefghijkl0123456789", Email: "visitor@example.test", ExpiresAt: at}, Credential: secret})
			case "accept":
				_ = json.NewEncoder(w).Encode(controlv1.ServiceGrant{Id: shareTestGrant, ServiceId: shareTestService, Kind: "team", ExpiresAt: &at})
			case "list":
				if strings.HasSuffix(r.URL.Path, "/grants") {
					_, _ = io.WriteString(w, `{"grants":[]}`)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"invitations": []any{map[string]any{"id": shareTestInvite, "service_id": shareTestService, "email": "visitor@example.test", "expires_at": at, "secret": secret}}})
			}
		})
		var output bytes.Buffer
		var err error
		switch operation {
		case "create":
			err = createServiceShareInvitation(t.Context(), control, shareTestService, serviceShareInviteCreateCommand{Email: "visitor@example.test", Output: statusOutputJSON}, at, &output)
		case "accept":
			err = acceptServiceShareInvitation(t.Context(), control, serviceShareInviteAcceptCommand{Secret: secret, Output: statusOutputJSON}, &output)
		case "list":
			err = listServiceShares(t.Context(), control, shareTestService, shareTestTeam, statusOutputJSON, &output)
		}
		if reason, ok := failure.ReasonOf(err); !ok || reason != failure.ServerResponseInvalid || output.Len() != 0 {
			t.Fatalf("%s widened invitation scope or leaked a secret: %v, %q", operation, err, &output)
		}
		writeCommandError(&output, err)
		if strings.Contains(output.String(), secret) {
			t.Fatal("invitation secret reached diagnostic output")
		}
	}
}

func TestServiceShareInvitationLifecycleUsesExactAPI(t *testing.T) {
	at := time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)
	secret := shareTestInvite + "." + strings.Repeat("A", 43)
	invite := controlv1.ServiceInvitation{Id: shareTestInvite, ServiceId: shareTestService, Email: "visitor@example.test", ExpiresAt: at}
	grant := controlv1.ServiceGrant{Id: shareTestGrant, ServiceId: shareTestService, Kind: "identity", IdentityId: new(shareTestPerson), InvitationId: new(shareTestInvite), ExpiresAt: &at}
	calls := map[string]int{}
	control := serviceShareTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		key := r.Method + " " + r.URL.Path
		calls[key]++
		switch key {
		case "POST /v1/services/" + shareTestService + "/invitations":
			var body controlv1.CreateServiceInvitationRequest
			decoder := json.NewDecoder(r.Body)
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&body); err != nil || body.Email != invite.Email || !body.ExpiresAt.Equal(at) || r.Header.Get("Idempotency-Key") == "" {
				t.Error("invitation lost its deadline, email, or idempotency key", err)
			}
			w.WriteHeader(201)
			_ = json.NewEncoder(w).Encode(controlv1.ServiceInvitationCreation{Invitation: invite, Credential: secret})
		case "POST /v1/service-invitations/accept":
			var body controlv1.AcceptServiceInvitationJSONRequestBody
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Secret != secret {
				t.Error("accept changed invitation secret", err)
			}
			_ = json.NewEncoder(w).Encode(grant)
		case "GET /v1/services/" + shareTestService + "/grants":
			_ = json.NewEncoder(w).Encode(controlv1.ServiceGrantPage{Grants: []controlv1.ServiceGrant{grant}})
		case "GET /v1/services/" + shareTestService + "/invitations":
			listed := invite
			listed.AcceptedAt = new(time.Now())
			_ = json.NewEncoder(w).Encode(controlv1.ServiceInvitationPage{Invitations: []controlv1.ServiceInvitation{listed}})
		case "GET /v1/services/" + shareTestService + "/http-grants":
			_ = json.NewEncoder(w).Encode([]controlv1.ServiceHTTPGrantSummary{{Id: shareTestHTTP, Subject: controlv1.VisitorResourceScope{Kind: "service", Id: shareTestService}, Kind: "token", ExpiresAt: at}})
		case "DELETE /v1/services/" + shareTestService + "/invitations/" + shareTestInvite,
			"DELETE /v1/services/" + shareTestService + "/grants/" + shareTestGrant:
			w.WriteHeader(204)
		default:
			t.Errorf("unexpected service access operation: %s", key)
			w.WriteHeader(500)
		}
	})
	var output bytes.Buffer
	if err := createServiceShareInvitation(t.Context(), control, shareTestService, serviceShareInviteCreateCommand{Email: string(invite.Email)}, at, &output); err != nil || output.String() != secret+"\n" {
		t.Fatal("one-time invitation was not raw stdout", err)
	}
	output.Reset()
	if err := acceptServiceShareInvitation(t.Context(), control, serviceShareInviteAcceptCommand{Secret: secret}, &output); err != nil || strings.Contains(output.String(), secret) || !strings.HasPrefix(output.String(), "Access granted to "+shareTestService+"\n") || !strings.Contains(output.String(), shareTestGrant) {
		t.Fatal("accepted scope or secret presentation", err)
	}
	for _, mode := range []statusOutputMode{statusOutputHuman, statusOutputJSON} {
		output.Reset()
		if err := listServiceShares(t.Context(), control, shareTestService, shareTestTeam, mode, &output); err != nil || strings.Contains(output.String(), secret) || !strings.Contains(output.String(), shareTestGrant) {
			t.Fatal("service access list lost scope or exposed a secret", err)
		}
	}
	for _, id := range []string{shareTestInvite, shareTestGrant} {
		output.Reset()
		if err := revokeServiceShare(t.Context(), control, shareTestService, shareTestTeam, serviceShareRevokeCommand{ID: id, Output: statusOutputJSON}, &output); err != nil || !strings.Contains(output.String(), `"revoked":true`) {
			t.Fatal("exact service revocation", err)
		}
	}
	if len(calls) != 7 {
		t.Fatalf("missing service access operations: %+v", calls)
	}
}

func TestServiceShareHTTPInventoryRejectsMixedScopesAndSecrets(t *testing.T) {
	for _, body := range []string{
		`[{"subject":{"kind":"public_url","id":"` + shareTestService + `"},"id":"` + shareTestHTTP + `","kind":"token","expires_at":"2027-01-01T00:00:00Z"}]`,
		`[{"subject":{"kind":"service","id":"svc_abcdefghijkl0123456789"},"id":"` + shareTestHTTP + `","kind":"token","expires_at":"2027-01-01T00:00:00Z"}]`,
		`[{"subject":{"kind":"service","id":"` + shareTestService + `"},"id":"` + shareTestHTTP + `","kind":"token","expires_at":"2027-01-01T00:00:00Z","secret":"private-value"}]`,
	} {
		control := serviceShareTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/http-grants") {
				_, _ = io.WriteString(w, body)
				return
			}
			if strings.HasSuffix(r.URL.Path, "/grants") {
				_, _ = io.WriteString(w, `{"grants":[]}`)
			} else {
				_, _ = io.WriteString(w, `{"invitations":[]}`)
			}
		})
		var output bytes.Buffer
		err := listServiceShares(t.Context(), control, shareTestService, shareTestTeam, statusOutputJSON, &output)
		if reason, ok := failure.ReasonOf(err); !ok || reason != failure.ServerResponseInvalid || output.Len() != 0 {
			t.Fatal("HTTP credential inventory widened scope or exposed a secret")
		}
	}
}

func TestServiceShareRejectsUnsafeResponsesAndPreservesFailures(t *testing.T) {
	for _, test := range []struct {
		name, body string
		status     int
		want       failure.Reason
	}{
		{"unknown model field", `{"grants":[{"id":"` + shareTestGrant + `","service_id":"` + shareTestService + `","kind":"identity","unexpected":"private-value"}]}`, 200, failure.ServerResponseInvalid},
		{"wrong scope", `{"grants":[{"id":"` + shareTestGrant + `","service_id":"svc_abcdefghijkl0123456789","kind":"identity"}]}`, 200, failure.ServerResponseInvalid},
		{"unknown kind", `{"grants":[{"id":"` + shareTestGrant + `","service_id":"` + shareTestService + `","kind":"future-kind"}]}`, 200, failure.ServerResponseInvalid},
		{"manager denied", `{"code":"forbidden","detail":"private-value"}`, 403, failure.ServerDenied},
	} {
		t.Run(test.name, func(t *testing.T) {
			control := serviceShareTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/invitations") {
					_, _ = io.WriteString(w, `{"invitations":[]}`)
					return
				}
				w.WriteHeader(test.status)
				_, _ = io.WriteString(w, test.body)
			})
			var output bytes.Buffer
			err := listServiceShares(t.Context(), control, shareTestService, shareTestTeam, statusOutputJSON, &output)
			if reason, ok := failure.ReasonOf(err); !ok || reason != test.want || output.Len() != 0 {
				t.Fatalf("unsafe response = %v; output=%q", err, &output)
			}
			writeCommandError(&output, err)
			if strings.Contains(output.String(), "private-value") {
				t.Fatal("diagnostic exposed an untrusted response value")
			}
		})
	}
	for _, kind := range []controlv1.ServiceGrantKind{"team", "identity"} {
		deletes := 0
		control := serviceShareTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodDelete {
				deletes++
				w.WriteHeader(204)
				return
			}
			_ = json.NewEncoder(w).Encode(controlv1.ServiceGrantPage{Grants: []controlv1.ServiceGrant{{Id: shareTestGrant, ServiceId: shareTestService, Kind: kind}}})
		})
		err := revokeServiceShare(t.Context(), control, shareTestService, shareTestTeam, serviceShareRevokeCommand{ID: shareTestGrant}, io.Discard)
		if kind == "team" && (err == nil || deletes != 0) || kind == "identity" && (err != nil || deletes != 1) {
			t.Fatalf("revoking %s grant: deletes=%d err=%v", kind, deletes, err)
		}
	}
}

func TestServiceShareServiceHTTPUsesExplicitSubjectAndOneTimeOutput(t *testing.T) {
	at := time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)
	service := controlv1.Service{Id: shareTestService, TeamId: shareTestTeam, Protocol: "http", Endpoint: &controlv1.ServiceEndpoint{Hostname: "web.production.example.test", Port: 443, Public: true}}
	secret := strings.Repeat("A", 43)
	link := "https://" + service.Endpoint.Hostname + "/__tnl/share/" + shareTestShare + "." + secret
	share := controlv1.Share{SchemaVersion: 1, Id: shareTestShare, TeamId: shareTestTeam, CreatedByIdentityId: shareTestPerson, Scope: "service",
		ServiceIds: []string{shareTestService}, EntryServiceId: shareTestService, CreatedAt: time.Now(), ExpiresAt: at}
	permission := controlv1.VisitorTokenResponse{Resource: controlv1.VisitorResourceScope{Kind: "service", Id: shareTestService}, Hostname: service.Endpoint.Hostname, Port: service.Endpoint.Port, VisitorPolicyRevision: 1, ExpiresAt: time.Now().Add(time.Minute), VisitorToken: "header.permission.signature"}
	for _, token := range []bool{false, true} {
		cases := []string{"", "subject", "id", "kind", "hostname", "secret"}
		if token {
			cases = append(cases, "permission-subject", "permission-id", "permission-hostname")
		}
		for _, corrupt := range cases {
			t.Run(map[bool]string{false: "link", true: "token"}[token]+"/"+corrupt, func(t *testing.T) {
				control := serviceShareTestClient(t, func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodGet && r.URL.Path == "/v1/shares/"+shareTestShare {
						_ = json.NewEncoder(w).Encode(share)
						return
					}
					if r.Method == http.MethodPost && r.URL.Path == "/v1/shares/"+shareTestShare+"/revoke" {
						revoked := share
						revoked.RevokedAt = new(time.Now())
						_ = json.NewEncoder(w).Encode(revoked)
						return
					}
					if r.Method == http.MethodPost && r.URL.Path == "/v1/visitor-tokens" {
						var body controlv1.VisitorTokenRequest
						var source controlv1.VisitorTokenShareSource
						if err := json.NewDecoder(r.Body).Decode(&body); err != nil || json.Unmarshal(body.Source, &source) != nil ||
							body.Resource != permission.Resource || source.Kind != "share" || source.ShareId != shareTestShare || source.Secret != secret {
							t.Error("service token did not independently exchange its exact ordinary share source", err)
						}
						result := permission
						switch corrupt {
						case "permission-subject":
							result.Resource.Kind = "public_url"
						case "permission-id":
							result.Resource.Id = "svc_abcdefghijkl0123456789"
						case "permission-hostname":
							result.Hostname = "other.example.test"
						}
						_ = json.NewEncoder(w).Encode(result)
						return
					}
					if r.Method != http.MethodPost || r.URL.Path != "/v1/shares" {
						t.Errorf("service HTTP used connector credentials or another authority: %s %s", r.Method, r.URL)
					}
					var body controlv1.CreateShareRequest
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.ServiceIds) != 1 || body.ServiceIds[0] != service.Id ||
						body.EntryServiceId != service.Id || !body.ExpiresAt.Equal(at) || r.Header.Get("Idempotency-Key") == "" {
						t.Error("ordinary service share changed its exact scope, key, or deadline", err)
					}
					creation := controlv1.ShareCreation{Share: share, Link: link,
						TokenSource: controlv1.VisitorTokenShareSource{Kind: controlv1.VisitorTokenShare, ShareId: shareTestShare, Secret: secret}}
					switch corrupt {
					case "subject":
						creation.Share.ServiceIds = []string{"svc_abcdefghijkl0123456789"}
					case "id":
						creation.Share.EntryServiceId = "svc_abcdefghijkl0123456789"
					case "kind":
						creation.Share.Scope = "preview"
					case "hostname":
						creation.Link = "https://other.example.test/__tnl/share/" + shareTestShare + "." + secret
					case "secret":
						creation.TokenSource.Secret += "\nprivate-value"
					}
					w.WriteHeader(201)
					_ = json.NewEncoder(w).Encode(creation)
				})
				var output bytes.Buffer
				err := createServiceShareHTTP(t.Context(), control, service, statusOutputHuman, token, at, &output)
				invalid := corrupt != ""
				if invalid {
					if reason, ok := failure.ReasonOf(err); !ok || reason != failure.ServerResponseInvalid || output.Len() != 0 {
						t.Fatalf("unsafe managed credential: %v output=%q", err, &output)
					}
					return
				}
				want := permission.VisitorToken + "\n"
				if !token {
					want = link + "\n"
				}
				if err != nil || output.String() != want || token && strings.Contains(output.String(), secret) {
					t.Fatalf("raw service HTTP credential output = %q, %v", &output, err)
				}
				if err := revokeServiceShare(t.Context(), control, service.Id, service.TeamId, serviceShareRevokeCommand{ID: shareTestShare}, io.Discard); err != nil {
					t.Fatal("service HTTP revocation", err)
				}
				cause := errors.New("private-output-failure")
				err = createServiceShareHTTP(t.Context(), control, service, statusOutputJSON, token, at, errorWriter{cause})
				if reason, ok := failure.ReasonOf(err); !ok || reason != failure.OutputUnavailable || !errors.Is(err, cause) {
					t.Fatal("output failure lost its classification or cause", err)
				}
			})
		}
	}
	control := serviceShareTestClient(t, func(http.ResponseWriter, *http.Request) { t.Error("non-public HTTP credential reached API") })
	for _, protocol := range []controlv1.ServiceProtocol{"tcp", "postgres", "mysql", "kubernetes", "http"} {
		service.Protocol, service.Endpoint.Public = protocol, protocol != "http"
		if err := createServiceShareHTTP(t.Context(), control, service, statusOutputHuman, true, at, io.Discard); err == nil {
			t.Fatalf("created HTTP token for private or non-HTTP service: %s", protocol)
		}
	}
}

func TestServiceShareListsOrdinarySharesWithoutBroadPreviewRevocation(t *testing.T) {
	const previewShareID = "shr_abcdefghijkl0123456789"
	const otherShareID = "shr_1111111111111111111111"
	const otherServiceID = "svc_abcdefghijkl0123456789"
	at := time.Now().Add(time.Hour)
	exact := controlv1.Share{SchemaVersion: 1, Id: shareTestShare, Scope: "service", TeamId: shareTestTeam,
		ServiceIds: []string{shareTestService}, EntryServiceId: shareTestService, ExpiresAt: at}
	preview := exact
	preview.Id, preview.Scope, preview.PreviewId = previewShareID, "preview", new("pv_0123456789abcdefghijkl")
	preview.ServiceIds = []string{shareTestService, otherServiceID}
	other := exact
	other.Id, other.ServiceIds, other.EntryServiceId = otherShareID, []string{otherServiceID}, otherServiceID
	revocations := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer current-person" {
			t.Error("share management used visitor-source authority")
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /v1/services/" + shareTestService + "/grants":
			_ = json.NewEncoder(w).Encode(controlv1.ServiceGrantPage{Grants: []controlv1.ServiceGrant{}})
		case "GET /v1/services/" + shareTestService + "/invitations":
			_ = json.NewEncoder(w).Encode(controlv1.ServiceInvitationPage{Invitations: []controlv1.ServiceInvitation{}})
		case "GET /v1/services/" + shareTestService + "/http-grants":
			_ = json.NewEncoder(w).Encode([]controlv1.ServiceHTTPGrantSummary{})
		case "GET /v1/shares":
			if r.URL.Query().Get("team_id") != shareTestTeam {
				t.Error("share inventory lost its actual service team")
			}
			_ = json.NewEncoder(w).Encode(controlv1.SharePage{SchemaVersion: 1, Shares: []controlv1.Share{exact, preview, other}})
		case "GET /v1/shares/" + shareTestShare:
			_ = json.NewEncoder(w).Encode(exact)
		case "GET /v1/shares/" + previewShareID:
			_ = json.NewEncoder(w).Encode(preview)
		case "GET /v1/shares/" + otherShareID:
			_ = json.NewEncoder(w).Encode(other)
		case "POST /v1/shares/" + shareTestShare + "/revoke":
			revocations++
			_ = json.NewEncoder(w).Encode(exact)
		default:
			t.Errorf("service share used another authority or broadened revocation: %s %s", r.Method, r.URL)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	control, err := clientcontrol.New(server.URL, server.Client(), "current-person")
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := listServiceShares(t.Context(), control, shareTestService, shareTestTeam, statusOutputJSON, &output); err != nil {
		t.Fatal(err)
	}
	var result struct {
		Shares []controlv1.Share `json:"shares"`
	}
	if err := json.Unmarshal(output.Bytes(), &result); err != nil || len(result.Shares) != 2 || strings.Contains(output.String(), otherShareID) ||
		strings.Contains(output.String(), "token_source") || strings.Contains(output.String(), "secret") {
		t.Fatal("service share inventory widened membership or exposed a source", err)
	}
	if err := revokeServiceShare(t.Context(), control, shareTestService, shareTestTeam, serviceShareRevokeCommand{ID: previewShareID}, io.Discard); err == nil || revocations != 0 {
		t.Fatal("exact-service revocation removed broader captured preview access", err)
	}
	if err := revokeServiceShare(t.Context(), control, shareTestService, shareTestTeam, serviceShareRevokeCommand{ID: otherShareID}, io.Discard); err == nil || revocations != 0 {
		t.Fatal("exact-service revocation removed another service's share", err)
	}
	if err := revokeServiceShare(t.Context(), control, shareTestService, shareTestTeam, serviceShareRevokeCommand{ID: shareTestShare}, io.Discard); err != nil || revocations != 1 {
		t.Fatal("exact-service ordinary share did not revoke through its defining operation", err)
	}
}

func TestServiceShareInvitationRetryGivesExplicitRecovery(t *testing.T) {
	at := time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)
	control := serviceShareTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Idempotency-Key") != "retained-key" {
			t.Error("retry replaced its operation key")
		}
		var body controlv1.CreateServiceInvitationRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email != "visitor@example.test" || !body.ExpiresAt.Equal(at) {
			t.Error("retry changed its exact email or deadline", err)
		}
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]any{"code": "credential_delivery_unavailable", "title": "credential delivery unavailable", "details": map[string]string{"resource_id": shareTestInvite}})
	})
	for _, mode := range []statusOutputMode{statusOutputHuman, statusOutputJSON} {
		var output bytes.Buffer
		err := createServiceShareInvitation(t.Context(), control, shareTestService, serviceShareInviteCreateCommand{Email: "visitor@example.test", IdempotencyKey: "retained-key", Output: mode}, at, &output)
		if err == nil || output.Len() != 0 || !strings.Contains(err.Error(), shareTestInvite) || !strings.Contains(err.Error(), "revoke") || !strings.Contains(err.Error(), "new key") {
			t.Fatal("retry omitted explicit revoke/reissue instructions", err)
		}
		writeCommandError(&output, err)
		if !strings.Contains(output.String(), shareTestInvite) || !strings.Contains(output.String(), "revoke") {
			t.Fatal("rendered retry omitted the resource to revoke")
		}
	}
}
