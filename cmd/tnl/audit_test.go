package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/alecthomas/kong"
	controlclient "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func auditEvent(cursor int64) controlv1.ServiceAuditEvent {
	return controlv1.ServiceAuditEvent{Id: "event-" + strconv.FormatInt(cursor, 10), Cursor: strconv.FormatInt(cursor, 10), TeamId: "team-shop", ServiceId: "service-api", ServiceKind: "private_service", EventType: "visitor.admit", OccurredAt: time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)}
}

func TestAuditListParsesRequestedWorkflowAndProjectTeam(t *testing.T) {
	var flags cli
	parser, err := kong.New(&flags)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parser.Parse([]string{"audit", "list", "--team", "shop", "--service", "eks-api", "--since", "24h", "--output", "json"})
	if err != nil || parsed.Command() != "audit list" {
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
	client, err := controlclient.New(server.URL, server.Client(), "access")
	if err != nil {
		t.Fatal(err)
	}
	page, err := readServiceAudit(t.Context(), client, "team-shop", controlv1.ListServiceAuditParams{Service: &service, Since: &since}, 3)
	if err != nil || calls != 2 || len(page.Events) != 3 || page.NextCursor == nil || *page.NextCursor != "3" {
		t.Fatalf("audit page: %+v %v", page, err)
	}
	var human bytes.Buffer
	if err := renderServiceAudit(&human, page); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(human.String(), "tnl audit list") || !strings.Contains(human.String(), "continue with --after 3") {
		t.Fatalf("audit presentation: %s", human.String())
	}
	for _, line := range strings.Split(human.String(), "\n") {
		if len(line) > 72 {
			t.Fatalf("audit line exceeds renderer width: %q", line)
		}
	}
}

type auditReaderFunc func(context.Context, string, controlv1.ListServiceAuditParams) (controlv1.ServiceAuditPage, error)

func (f auditReaderFunc) ListServiceAudit(ctx context.Context, team string, p controlv1.ListServiceAuditParams) (controlv1.ServiceAuditPage, error) {
	return f(ctx, team, p)
}

func TestAuditRejectsStalledBackwardAndCrossTeamPages(t *testing.T) {
	for _, mode := range []string{"stalled", "backward", "empty", "cross-team", "skipped-cursor"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			reader := auditReaderFunc(func(_ context.Context, _ string, _ controlv1.ListServiceAuditParams) (controlv1.ServiceAuditPage, error) {
				calls++
				next := "1"
				page := controlv1.ServiceAuditPage{Events: []controlv1.ServiceAuditEvent{auditEvent(1)}, NextCursor: &next}
				if calls == 1 && mode != "empty" && mode != "cross-team" && mode != "skipped-cursor" {
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
	client, err := controlclient.New(server.URL, server.Client(), "access")
	if err != nil {
		t.Fatal(err)
	}
	_, err = readServiceAudit(t.Context(), client, "team-shop", controlv1.ListServiceAuditParams{}, 100)
	var problem *controlclient.ProblemError
	if !errors.As(err, &problem) || problem.Problem.Code != controlv1.Forbidden || problem.Problem.Detail != "service audit access denied" {
		t.Fatalf("authored server problem was replaced: %v", err)
	}
	if reason, _ := failure.ReasonOf(err); reason != failure.ServerDenied {
		t.Fatalf("audit authorization classification: %v", err)
	}
}
