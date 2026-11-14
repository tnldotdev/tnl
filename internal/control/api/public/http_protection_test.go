package public

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/httpprotection"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type httpProtectionFixture struct {
	Store
	report func(context.Context, visitorscope.Scope, string, int64, string, httpprotection.Rejections, time.Time) error
}

func (s *httpProtectionFixture) ReportHTTPProtectionRejections(ctx context.Context, scope visitorscope.Scope, run string, number int64, token string, evidence httpprotection.Rejections, now time.Time) error {
	return s.report(ctx, scope, run, number, token, evidence, now)
}

func protectionReportBody(t *testing.T) string {
	t.Helper()
	now := time.Now()
	raw, err := json.Marshal(controlv1.ReportHTTPProtectionRejectionsRequest{
		Resource: controlv1.VisitorResourceScope{Kind: "public_url", Id: "url_" + strings.Repeat("A", 22)},
		RunId:    "run", RunNumber: 1, Evidence: httpprotection.Rejections{SourceIP: "192.0.2.1", StartedAt: now.Add(-time.Second), EndedAt: now, Count: 10, RuleIDs: []int{942100}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestTemporaryBlockReportInputBoundary(t *testing.T) {
	valid := protectionReportBody(t)
	for _, tc := range []struct {
		body, token string
		status      int
	}{
		{valid, "run-token", 204}, {valid, "", 401}, {"null", "run-token", 400},
		{valid + " {}", "run-token", 400}, {valid + strings.Repeat(" ", 8192), "run-token", 400},
		{strings.Replace(valid, `"count":10`, `"count":9`, 1), "run-token", 400},
		{strings.Replace(valid, `"rule_ids":[942100]`, `"rule_ids":[920420]`, 1), "run-token", 400},
		{strings.Replace(valid, `"source_ip":"192.0.2.1"`, `"source_ip":"192.0.2.0/24"`, 1), "run-token", 400},
		{strings.Replace(valid, `"run_number":"1"`, `"run_number":"0"`, 1), "run-token", 400},
		{strings.Replace(valid, `"run_id":"run"`, `"run_id":"`+strings.Repeat("r", 65)+`"`, 1), "run-token", 400},
	} {
		calls := 0
		store := &httpProtectionFixture{report: func(ctx context.Context, scope visitorscope.Scope, run string, number int64, token string, e httpprotection.Rejections, now time.Time) error {
			calls++
			deadline, ok := ctx.Deadline()
			if !ok || time.Until(deadline) > 2*time.Second || !scope.Valid() || run != "run" || number != 1 || token != "run-token" || e.Validate(now) != nil {
				t.Error("report lost bounded current-run facts")
			}
			return nil
		}}
		h := testHandler(t, Config{}, store, nil, nil, Stores{HTTPProtection: store})
		r := httptest.NewRequest(http.MethodPost, "/v1/http-protection/rejections", strings.NewReader(tc.body))
		if tc.token != "" {
			r.Header.Set("Authorization", "Bearer "+tc.token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.status || (calls == 1) != (tc.status == 204) || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("report validation reached the backend or lost its status", w.Code, tc.status, calls, w.Body.String())
		}
	}
}

func TestTemporaryBlockReportGateDoesNotQueueDatabaseWork(t *testing.T) {
	entered := make(chan struct{}, 4)
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	store := &httpProtectionFixture{report: func(ctx context.Context, _ visitorscope.Scope, _ string, _ int64, _ string, _ httpprotection.Rejections, _ time.Time) error {
		entered <- struct{}{}
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}}
	h := testHandler(t, Config{}, store, nil, nil, Stores{HTTPProtection: store})
	body := protectionReportBody(t)
	request := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/v1/http-protection/rejections", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer run-token")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	var workers sync.WaitGroup
	defer workers.Wait()
	for range 4 {
		workers.Go(func() { request() })
		<-entered
	}
	w := request()
	if w.Code != 503 || w.Header().Get("Retry-After") != "1" {
		t.Fatal("full report gate did not reject before database access", w.Code)
	}
	unblock()
}
