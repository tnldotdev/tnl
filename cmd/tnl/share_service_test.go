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

	"github.com/alecthomas/kong"
	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

const (
	shareTestService = "psvc_0123456789abcdefghijkl"
	shareTestInvite  = "psivt_0123456789abcdefghijkl"
	shareTestGrant   = "psgr_0123456789abcdefghijkl"
	shareTestHTTP    = "mhg_0123456789abcdefghijkl"
	shareTestTeam    = "tm_0123456789abcdefghijkl"
	shareTestPerson  = "ident_0123456789abcdefghijkl"
)

func serviceShareTestClient(t *testing.T, handler http.HandlerFunc) *controlclient.Client {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer current-person" {
			t.Error("service access did not use the current person's control session")
		}
		w.Header().Set("Content-Type", "application/json")
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	client, err := controlclient.New(server.URL, server.Client(), "current-person")
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
		parser, err := kong.New(&flags)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := parser.Parse(append([]string{"share", "service"}, test.args...))
		if err != nil || parsed.Command() != "share service "+test.want || !projectSensitiveCommand(parsed.Command()) {
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
		{"revoke", shareTestService, "shr_0123456789abcdefghijkl"},
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
			t.Fatal("managed HTTP deadline exceeded seven days")
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
	saved, group := "orders-saved", "production"
	project := projectConfiguration{Project: projectconfig.Project{Root: root, Selection: projectconfig.Selection{Path: filepath.Join(root, "tnl.json")}, Worktree: projectconfig.Worktree{Root: root, IsGit: true}, Config: config.TNL{Publishers: map[string]config.Publisher{group: {}}, Services: config.Services{
		"orders": {Name: &saved}, "remote": {Publisher: &group, Tunnel: &config.Tunnel{}, Target: &config.ServiceTarget{Type: "address", Address: testTarget("http://app.internal:3000")}}, "web": {Tunnel: &config.Tunnel{}},
	}}}}
	source, err := project.SourceIdentity(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, selector := range []string{"orders", "remote", shareTestService, saved, group, "web", "url_0123456789abcdefghijkl"} {
		t.Run(selector, func(t *testing.T) {
			lookups, reads := 0, 0
			scope := controlv1.LocalServiceSource{ProjectKey: source.Key, SourceFingerprint: source.Fingerprint, Service: selector}
			if selector == "orders" {
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
				case "/v1/private-services":
					lookups++
					if r.URL.Query().Get("team_id") != shareTestTeam {
						t.Error("manager inventory lost its selected team")
					}
					if r.URL.Query().Get("cursor") == "" {
						other := scope
						other.ProjectKey = "another-project"
						_ = json.NewEncoder(w).Encode(controlv1.PrivateServicePage{Services: []controlv1.PrivateService{{Id: "psvc_abcdefghijkl0123456789", Name: selector, TeamId: shareTestTeam, Source: &other}}, NextCursor: new("next")})
					} else {
						_ = json.NewEncoder(w).Encode(controlv1.PrivateServicePage{Services: []controlv1.PrivateService{{Id: shareTestService, Name: "saved-name", TeamId: shareTestTeam, Source: &scope}}})
					}
				case "/v1/private-services/" + shareTestService:
					reads++
					_ = json.NewEncoder(w).Encode(controlv1.PrivateService{Id: shareTestService, TeamId: shareTestTeam, Protocol: "http", Source: &scope})
				default:
					t.Errorf("selection requested a visitor, public URL, or unrelated API: %s", r.URL)
					w.WriteHeader(500)
				}
			})
			s := &teamSession{authenticated: &clientauth.Client{Control: control}, selectedTeam: shareTestTeam, identity: authorityv1.IdentityContext{Memberships: []authorityv1.Membership{{TeamId: shareTestTeam}}}}
			service, err := selectServiceShare(t.Context(), s, project, selector)
			valid := selector == "orders" || selector == "remote" || selector == shareTestService
			if valid {
				if err != nil || service.Id != shareTestService || reads != 1 || selector != shareTestService && lookups != 2 || selector == shareTestService && lookups != 0 {
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
				item := controlv1.PrivateService{Id: shareTestService, Name: "orders", TeamId: shareTestTeam, Source: scope}
				switch r.URL.Path {
				case "/v1/private-services":
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
					items := []controlv1.PrivateService{item}
					if test.name == "ambiguous" {
						item.Id = "psvc_abcdefghijkl0123456789"
						items = append(items, item)
					}
					_ = json.NewEncoder(w).Encode(controlv1.PrivateServicePage{Services: items})
				case "/v1/private-services/" + shareTestService:
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
			s := &teamSession{authenticated: &clientauth.Client{Control: control}, selectedTeam: shareTestTeam, identity: authorityv1.IdentityContext{Memberships: []authorityv1.Membership{{TeamId: shareTestTeam}}}}
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

func TestServiceShareInvitationResponsesCannotWidenScopeOrLeakSecrets(t *testing.T) {
	at := time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)
	secret := shareTestInvite + "." + strings.Repeat("A", 43)
	for _, operation := range []string{"create", "accept", "list"} {
		control := serviceShareTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			switch operation {
			case "create":
				_ = json.NewEncoder(w).Encode(controlv1.PrivateServiceInvitation{Id: shareTestInvite, PrivateServiceId: "psvc_abcdefghijkl0123456789", Email: "visitor@example.test", ExpiresAt: at, Secret: &secret})
			case "accept":
				_ = json.NewEncoder(w).Encode(controlv1.PrivateServiceGrant{Id: shareTestGrant, PrivateServiceId: shareTestService, Kind: "team", ExpiresAt: &at})
			case "list":
				if strings.HasSuffix(r.URL.Path, "/grants") {
					_, _ = io.WriteString(w, `{"grants":[]}`)
					return
				}
				_ = json.NewEncoder(w).Encode(controlv1.PrivateServiceInvitationPage{Invitations: []controlv1.PrivateServiceInvitation{{Id: shareTestInvite, PrivateServiceId: shareTestService, Email: "visitor@example.test", ExpiresAt: at, Secret: &secret}}})
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
			err = listServiceShares(t.Context(), control, shareTestService, statusOutputJSON, &output)
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
	invite := controlv1.PrivateServiceInvitation{Id: shareTestInvite, PrivateServiceId: shareTestService, Email: "visitor@example.test", ExpiresAt: at, Secret: &secret}
	grant := controlv1.PrivateServiceGrant{Id: shareTestGrant, PrivateServiceId: shareTestService, Kind: "identity", IdentityId: new(shareTestPerson), InvitationId: new(shareTestInvite), ExpiresAt: &at}
	calls := map[string]int{}
	control := serviceShareTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		key := r.Method + " " + r.URL.Path
		calls[key]++
		switch key {
		case "POST /v1/private-services/" + shareTestService + "/invitations":
			var body controlv1.CreatePrivateServiceInvitationRequest
			decoder := json.NewDecoder(r.Body)
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&body); err != nil || body.Email != invite.Email || !body.ExpiresAt.Equal(at) || r.Header.Get("Idempotency-Key") == "" {
				t.Error("invitation lost its deadline, email, or idempotency key", err)
			}
			w.WriteHeader(201)
			_ = json.NewEncoder(w).Encode(invite)
		case "POST /v1/private-service-invitations/accept":
			var body controlv1.AcceptPrivateServiceInvitationJSONRequestBody
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Secret != secret {
				t.Error("accept changed invitation secret", err)
			}
			_ = json.NewEncoder(w).Encode(grant)
		case "GET /v1/private-services/" + shareTestService + "/grants":
			_ = json.NewEncoder(w).Encode(controlv1.PrivateServiceGrantPage{Grants: []controlv1.PrivateServiceGrant{grant}})
		case "GET /v1/private-services/" + shareTestService + "/invitations":
			listed := invite
			listed.Secret, listed.AcceptedAt = nil, new(time.Now())
			_ = json.NewEncoder(w).Encode(controlv1.PrivateServiceInvitationPage{Invitations: []controlv1.PrivateServiceInvitation{listed}})
		case "GET /v1/private-services/" + shareTestService + "/http-grants":
			_ = json.NewEncoder(w).Encode([]controlv1.ManagedHTTPGrantSummary{{Id: shareTestHTTP, Subject: controlv1.HTTPAuthorizationSubject{Kind: "managed_service", Id: shareTestService}, Kind: "token", ExpiresAt: at}})
		case "DELETE /v1/private-services/" + shareTestService + "/invitations/" + shareTestInvite,
			"DELETE /v1/private-services/" + shareTestService + "/grants/" + shareTestGrant:
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
	if err := acceptServiceShareInvitation(t.Context(), control, serviceShareInviteAcceptCommand{Secret: secret}, &output); err != nil || strings.Contains(output.String(), secret) || !strings.Contains(output.String(), shareTestService) {
		t.Fatal("accepted scope or secret presentation", err)
	}
	for _, mode := range []statusOutputMode{statusOutputHuman, statusOutputJSON} {
		output.Reset()
		if err := listServiceShares(t.Context(), control, shareTestService, mode, &output); err != nil || strings.Contains(output.String(), secret) || !strings.Contains(output.String(), shareTestGrant) {
			t.Fatal("service access list lost scope or exposed a secret", err)
		}
	}
	for _, id := range []string{shareTestInvite, shareTestGrant} {
		output.Reset()
		if err := revokeServiceShare(t.Context(), control, shareTestService, serviceShareRevokeCommand{ID: id, Output: statusOutputJSON}, &output); err != nil || !strings.Contains(output.String(), `"revoked":true`) {
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
		`[{"subject":{"kind":"managed_service","id":"psvc_abcdefghijkl0123456789"},"id":"` + shareTestHTTP + `","kind":"token","expires_at":"2027-01-01T00:00:00Z"}]`,
		`[{"subject":{"kind":"managed_service","id":"` + shareTestService + `"},"id":"` + shareTestHTTP + `","kind":"token","expires_at":"2027-01-01T00:00:00Z","secret":"private-value"}]`,
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
		err := listServiceShares(t.Context(), control, shareTestService, statusOutputJSON, &output)
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
		{"unknown model field", `{"grants":[{"id":"` + shareTestGrant + `","private_service_id":"` + shareTestService + `","kind":"identity","unexpected":"private-value"}]}`, 200, failure.ServerResponseInvalid},
		{"wrong scope", `{"grants":[{"id":"` + shareTestGrant + `","private_service_id":"psvc_abcdefghijkl0123456789","kind":"identity"}]}`, 200, failure.ServerResponseInvalid},
		{"unknown kind", `{"grants":[{"id":"` + shareTestGrant + `","private_service_id":"` + shareTestService + `","kind":"future-kind"}]}`, 200, failure.ServerResponseInvalid},
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
			err := listServiceShares(t.Context(), control, shareTestService, statusOutputJSON, &output)
			if reason, ok := failure.ReasonOf(err); !ok || reason != test.want || output.Len() != 0 {
				t.Fatalf("unsafe response = %v; output=%q", err, &output)
			}
			writeCommandError(&output, err)
			if strings.Contains(output.String(), "private-value") {
				t.Fatal("diagnostic exposed an untrusted response value")
			}
		})
	}
	for _, kind := range []controlv1.PrivateServiceGrantKind{"team", "identity"} {
		deletes := 0
		control := serviceShareTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodDelete {
				deletes++
				w.WriteHeader(204)
				return
			}
			_ = json.NewEncoder(w).Encode(controlv1.PrivateServiceGrantPage{Grants: []controlv1.PrivateServiceGrant{{Id: shareTestGrant, PrivateServiceId: shareTestService, Kind: kind}}})
		})
		err := revokeServiceShare(t.Context(), control, shareTestService, serviceShareRevokeCommand{ID: shareTestGrant}, io.Discard)
		if kind == "team" && (err == nil || deletes != 0) || kind == "identity" && (err != nil || deletes != 1) {
			t.Fatalf("revoking %s grant: deletes=%d err=%v", kind, deletes, err)
		}
	}
}

func TestServiceShareManagedHTTPUsesExplicitSubjectAndOneTimeOutput(t *testing.T) {
	at := time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)
	service := controlv1.PrivateService{Id: shareTestService, Protocol: "http", ManagedTls: &controlv1.ManagedServiceTLS{Hostname: "web.production.example.test", Port: 25443, Public: true}}
	secret := shareTestHTTP + "." + strings.Repeat("A", 43)
	for _, kind := range []controlv1.CreateManagedHTTPGrantRequestKind{"share", "token"} {
		for _, corrupt := range []string{"", "subject", "id", "kind", "hostname", "secret"} {
			t.Run(string(kind)+"/"+corrupt, func(t *testing.T) {
				control := serviceShareTestClient(t, func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodDelete && r.URL.Path == "/v1/private-services/"+shareTestService+"/http-grants/"+shareTestHTTP {
						w.WriteHeader(204)
						return
					}
					if r.Method != http.MethodPost || r.URL.Path != "/v1/private-services/"+shareTestService+"/http-grants" {
						t.Errorf("managed HTTP used a public URL or group grant: %s %s", r.Method, r.URL)
					}
					var body controlv1.CreateManagedHTTPGrantRequest
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Kind != kind || !body.ExpiresAt.Equal(at) {
						t.Error("managed HTTP grant changed kind or deadline", err)
					}
					grant := controlv1.ManagedHTTPGrant{Id: shareTestHTTP, Subject: controlv1.HTTPAuthorizationSubject{Kind: "managed_service", Id: shareTestService}, Kind: controlv1.ManagedHTTPGrantKind(kind), Secret: secret, ExpiresAt: at}
					if kind == "share" {
						grant.ShareUrl = new("https://web.production.example.test:25443/__tnl/share/" + secret)
					}
					switch corrupt {
					case "subject":
						grant.Subject.Kind = "public_url"
					case "id":
						grant.Subject.Id = "psvc_abcdefghijkl0123456789"
					case "kind":
						grant.Kind = "other"
					case "hostname":
						grant.ShareUrl = new("https://other.example.test/__tnl/share/" + secret)
					case "secret":
						grant.Secret += "\nprivate-value"
					}
					w.WriteHeader(201)
					_ = json.NewEncoder(w).Encode(grant)
				})
				var output bytes.Buffer
				err := createServiceShareHTTP(t.Context(), control, service, statusOutputHuman, kind, at, &output)
				invalid := corrupt != ""
				if invalid {
					if reason, ok := failure.ReasonOf(err); !ok || reason != failure.ServerResponseInvalid || output.Len() != 0 {
						t.Fatalf("unsafe managed credential: %v output=%q", err, &output)
					}
					return
				}
				want := secret + "\n"
				if kind == "share" {
					want = "https://web.production.example.test:25443/__tnl/share/" + want
				}
				if err != nil || output.String() != want {
					t.Fatalf("raw managed HTTP credential output = %q, %v", &output, err)
				}
				if err := revokeServiceShare(t.Context(), control, service.Id, serviceShareRevokeCommand{ID: shareTestHTTP}, io.Discard); err != nil {
					t.Fatal("managed HTTP revocation", err)
				}
				cause := errors.New("private-output-failure")
				err = createServiceShareHTTP(t.Context(), control, service, statusOutputJSON, kind, at, errorWriter{cause})
				if reason, ok := failure.ReasonOf(err); !ok || reason != failure.OutputUnavailable || !errors.Is(err, cause) {
					t.Fatal("output failure lost its classification or cause", err)
				}
			})
		}
	}
	control := serviceShareTestClient(t, func(http.ResponseWriter, *http.Request) { t.Error("non-public HTTP credential reached API") })
	for _, protocol := range []controlv1.PrivateServiceProtocol{"tcp", "postgres", "mysql", "kubernetes", "http"} {
		service.Protocol, service.ManagedTls.Public = protocol, protocol != "http"
		if err := createServiceShareHTTP(t.Context(), control, service, statusOutputHuman, "token", at, io.Discard); err == nil {
			t.Fatalf("created HTTP token for private or non-HTTP service: %s", protocol)
		}
	}
}

func TestServiceShareInvitationRetryGivesExplicitRecovery(t *testing.T) {
	at := time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)
	control := serviceShareTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Idempotency-Key") != "retained-key" {
			t.Error("retry replaced its operation key")
		}
		var body controlv1.CreatePrivateServiceInvitationRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Email != "visitor@example.test" || !body.ExpiresAt.Equal(at) {
			t.Error("retry changed its exact email or deadline", err)
		}
		_ = json.NewEncoder(w).Encode(controlv1.PrivateServiceInvitation{Id: shareTestInvite, PrivateServiceId: shareTestService, Email: body.Email, ExpiresAt: at})
	})
	for _, mode := range []statusOutputMode{statusOutputHuman, statusOutputJSON} {
		var output bytes.Buffer
		err := createServiceShareInvitation(t.Context(), control, shareTestService, serviceShareInviteCreateCommand{Email: "visitor@example.test", IdempotencyKey: "retained-key", Output: mode}, at, &output)
		if err != nil || !strings.Contains(output.String(), shareTestInvite) || strings.Contains(output.String(), `"secret"`) {
			t.Fatal("retry did not identify the recoverable invitation", err)
		}
		if mode == statusOutputHuman && (!strings.Contains(output.String(), "secret unavailable") || !strings.Contains(output.String(), "revoke") || !strings.Contains(output.String(), "new key")) {
			t.Fatal("human retry omitted explicit revoke/reissue instructions")
		}
	}
}
