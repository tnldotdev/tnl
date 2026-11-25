package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func auditEvent(cursor int64) controlv1.ServiceAuditEvent {
	return controlv1.ServiceAuditEvent{Id: "event-" + strconv.FormatInt(cursor, 10), Cursor: strconv.FormatInt(cursor, 10), TeamId: "team-shop", ServiceId: "svc_0123456789abcdefghijkl", ServiceKind: "service", EventType: "visitor.admit", OccurredAt: time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)}
}

func TestAuditListParsesRequestedWorkflowAndProjectTeam(t *testing.T) {
	var flags cli
	parser := commandForTest(&flags, io.Discard)
	parsed, err := parser([]string{"audit", "list", "--team", "shop", "--service", "eks-api", "--since", "24h", "--output", "json"})
	if err != nil || commandID(parsed) != "audit list" {
		t.Fatalf("audit command: %v", err)
	}
	if flags.Audit.List.Team != "shop" || flags.Audit.List.Service != "eks-api" || flags.Audit.List.Since != "24h" || flags.Audit.List.Output != "json" || flags.Audit.List.Limit != 100 {
		t.Fatalf("audit flags: %+v", flags.Audit.List)
	}
	configured := "configured-team"
	project := projectConfiguration{}
	project.Config.Team = &configured
	if err := applyProjectCommandContext("audit list", project, &flags); err != nil {
		t.Fatal(err)
	}
	if selected := flags.Audit.List.selection(); selected.SelectedTeam != "shop" || selected.ProjectTeam != configured {
		t.Fatalf("audit team precedence: %+v", selected)
	}
}

func TestAuditSinceUsesOneUTCInstantAndRejectsInvalidInput(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.FixedZone("test", 3600))
	for _, value := range []string{"", "24h"} {
		got, err := auditSince(value, now)
		if err != nil || !got.Equal(now.Add(-24*time.Hour)) || got.Location() != time.UTC {
			t.Fatalf("since=%s: %s %v", value, got, err)
		}
	}
	got, err := auditSince("2026-10-16T15:04:05+01:00", now)
	if err != nil || got.Format(time.RFC3339) != "2026-10-16T14:04:05Z" {
		t.Fatalf("timestamp=%s: %v", got, err)
	}
	for _, value := range []string{"0s", "-1h", "not-a-time", "24d"} {
		if _, err := auditSince(value, now); err == nil {
			t.Fatalf("accepted invalid --since %q", value)
		}
	}
}

func TestAuditSelectsOnlyServiceIDsNamesAndHostnames(t *testing.T) {
	const team = "tm_0123456789abcdefghijkl"
	access, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	filters := make(chan url.Values, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/v1/discovery" && r.Header.Get("Authorization") != "Bearer "+access.String() {
			t.Error("audit did not use its management session")
		}
		switch r.URL.Path {
		case "/v1/discovery":
			_ = json.NewEncoder(w).Encode(controlv1.ControlDiscovery{ManagedDomain: "example.test", ManagedUrlMode: "generated",
				Authentication: controlv1.AuthenticationFacts{Methods: []controlv1.AuthenticationFactsMethods{"oidc"}, Oidc: &controlv1.OIDCAuthenticationFacts{Issuer: "https://identity.example.test", LoginFlow: "device_code"}}})
		case "/v1/identity":
			_ = json.NewEncoder(w).Encode(authorityv1.IdentityContext{Memberships: []authorityv1.Membership{{TeamId: team}}})
		case "/v1/teams/" + team:
			_ = json.NewEncoder(w).Encode(authorityv1.Team{Id: team})
		case "/v1/teams/" + team + "/service-audit":
			filters <- r.URL.Query()
			_ = json.NewEncoder(w).Encode(controlv1.ServiceAuditPage{Events: []controlv1.ServiceAuditEvent{}})
		default:
			t.Errorf("unexpected audit request: %s", r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	original := http.DefaultTransport
	http.DefaultTransport = server.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = original })
	for _, selector := range []string{"svc_0123456789abcdefghijkl", "api", "api.example.test"} {
		t.Run(selector, func(t *testing.T) {
			flags := auditListCommand{Service: selector, Limit: 1, Output: statusOutputJSON,
				scopedTeamFlags: scopedTeamFlags{remoteFlags: remoteFlags{ServerURL: server.URL, AccessToken: access.String(), StateDir: filepath.Join(t.TempDir(), "state")}, teamSelectionFlags: teamSelectionFlags{Team: team}}}
			if err := runAuditList(t.Context(), flags, io.Discard, io.Discard); err != nil {
				t.Fatal(err)
			}
			var got url.Values
			select {
			case got = <-filters:
			default:
				t.Fatal("audit did not request service history")
			}
			id := ""
			if strings.HasPrefix(selector, "svc_") {
				id = selector
				selector = ""
			}
			if got.Get("service_id") != id || got.Get("service") != selector {
				t.Fatalf("audit changed service selection: %v", got)
			}
		})
	}
	for _, selector := range []string{"url_0123456789abcdefghijkl", "svc_invalid", " api", "api/path", "https://api.example.test", "api\n", "api\x00", strings.Repeat("a", 254)} {
		t.Run(selector, func(t *testing.T) {
			before := requests.Load()
			state := filepath.Join(t.TempDir(), "state")
			flags := auditListCommand{Service: selector, Limit: 1, scopedTeamFlags: scopedTeamFlags{remoteFlags: remoteFlags{ServerURL: server.URL, AccessToken: access.String(), StateDir: state}}}
			err := runAuditList(t.Context(), flags, io.Discard, io.Discard)
			if reason, _ := failure.ReasonOf(err); reason != failure.InvalidTunnelFlags || requests.Load() != before {
				t.Fatalf("invalid service selector reached control: %v", err)
			}
			if _, err := os.Stat(state); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("invalid service selector opened client state: %v", err)
			}
		})
	}
}

func TestAuditProductionClientPaginatesWithoutChangingFilters(t *testing.T) {
	calls := 0
	since := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	service := "eks-api"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "GET" || r.URL.Path != "/v1/teams/team-shop/service-audit" || r.Header.Get("Authorization") != "Bearer access" || r.URL.Query().Get("service") != service || r.URL.Query().Get("since") != since.Format(time.RFC3339) {
			t.Errorf("audit request lost scope or filters: %s %s", r.Method, r.URL)
		}
		w.Header().Set("Content-Type", "application/json")
		switch calls {
		case 1:
			if r.URL.Query().Get("after") != "" || r.URL.Query().Get("limit") != "3" {
				t.Errorf("first page: %s", r.URL)
			}
			next := "2"
			_ = json.NewEncoder(w).Encode(controlv1.ServiceAuditPage{Events: []controlv1.ServiceAuditEvent{auditEvent(1), auditEvent(2)}, NextCursor: &next})
		case 2:
			if r.URL.Query().Get("after") != "2" || r.URL.Query().Get("limit") != "1" {
				t.Errorf("second page: %s", r.URL)
			}
			next := "3"
			_ = json.NewEncoder(w).Encode(controlv1.ServiceAuditPage{Events: []controlv1.ServiceAuditEvent{auditEvent(3)}, NextCursor: &next})
		default:
			t.Error("audit pagination did not stop at its result limit")
		}
	}))
	defer server.Close()
	client, err := clientcontrol.New(server.URL, server.Client(), "access")
	if err != nil {
		t.Fatal(err)
	}
	page, err := readServiceAudit(t.Context(), client, "team-shop", controlv1.ListServiceAuditParams{Service: &service, Since: &since}, 3)
	if err != nil || calls != 2 || len(page.Events) != 3 || page.NextCursor == nil || *page.NextCursor != "3" {
		t.Fatalf("audit page: %+v %v", page, err)
	}
	var human bytes.Buffer
	scope := commandScope{configArgs: "--no-config ", server: server.URL, team: "team-shop", stateDir: "/client state"}
	if err := renderServiceAudit(&human, page, auditListCommand{Service: service, Limit: 3}, since, scope); err != nil {
		t.Fatal(err)
	}
	want := "\ntnl --no-config audit list --since=2026-10-16T12:00:00Z --service=eks-api --limit=3 --after=3 --server=" + server.URL + " --team=team-shop --state-dir='/client state'\n"
	if strings.Count(human.String(), "visitor.admit") != 3 || !strings.HasSuffix(human.String(), want) {
		t.Fatalf("audit presentation: %s", human.String())
	}
}

type auditReaderFunc func(context.Context, string, controlv1.ListServiceAuditParams) (controlv1.ServiceAuditPage, error)

func (f auditReaderFunc) ListServiceAudit(ctx context.Context, team string, p controlv1.ListServiceAuditParams) (controlv1.ServiceAuditPage, error) {
	return f(ctx, team, p)
}

func TestAuditRejectsStalledBackwardAndCrossTeamPages(t *testing.T) {
	for _, mode := range []string{"stalled", "backward", "empty", "cross-team", "skipped-cursor", "retired-service", "malformed-service"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			reader := auditReaderFunc(func(_ context.Context, _ string, _ controlv1.ListServiceAuditParams) (controlv1.ServiceAuditPage, error) {
				calls++
				next := "1"
				page := controlv1.ServiceAuditPage{Events: []controlv1.ServiceAuditEvent{auditEvent(1)}, NextCursor: &next}
				if calls == 1 && (mode == "stalled" || mode == "backward") {
					return page, nil
				}
				switch mode {
				case "backward":
					page.Events[0] = auditEvent(0)
				case "empty":
					page.Events = nil
				case "cross-team":
					page.Events[0].TeamId = "other-team"
				case "skipped-cursor":
					next = "9"
				case "retired-service":
					page.Events[0].ServiceId = "url_0123456789abcdefghijkl"
				case "malformed-service":
					page.Events[0].ServiceId = "svc_invalid"
				}
				return page, nil
			})
			_, err := readServiceAudit(t.Context(), reader, "team-shop", controlv1.ListServiceAuditParams{}, 10)
			reason, _ := failure.ReasonOf(err)
			if reason != failure.ServerResponseInvalid || calls > 2 {
				t.Fatalf("invalid page was not bounded: calls=%d err=%v", calls, err)
			}
		})
	}
}

func TestAuditPreservesManagerAuthorizationProblem(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(controlv1.Problem{Code: controlv1.Forbidden, Status: http.StatusForbidden, Title: "service audit access denied", Detail: "service audit access denied", Type: "https://tnl.dev/p/forbidden", RequestId: "request-audit"})
	}))
	defer server.Close()
	client, err := clientcontrol.New(server.URL, server.Client(), "access")
	if err != nil {
		t.Fatal(err)
	}
	_, err = readServiceAudit(t.Context(), client, "team-shop", controlv1.ListServiceAuditParams{}, 100)
	var problem *clientcontrol.ProblemError
	if !errors.As(err, &problem) || problem.Problem.Code != controlv1.Forbidden || problem.Problem.Detail != "service audit access denied" {
		t.Fatalf("authored server problem was replaced: %v", err)
	}
	if reason, _ := failure.ReasonOf(err); reason != failure.ServerDenied {
		t.Fatalf("audit authorization classification: %v", err)
	}
}
