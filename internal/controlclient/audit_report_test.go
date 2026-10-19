package controlclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/serviceaudit"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestPublisherAuditUsesExactRunTokenAndAcknowledgement(t *testing.T) {
	const run = "pr_0123456789ABCDEFGHIJKL"
	const token = credentials.PublishRunToken("private-audit-token")
	o := serviceaudit.Observation{EventID: serviceaudit.NewID(), ServiceID: "url_0123456789ABCDEFGHIJKL", ServiceKind: "public_url", EventType: "http.decision", OccurredAt: time.Now(), RunID: run, RunNumber: 7, VisitorConnectionID: "vc_0123456789ABCDEFGHIJKL", Outcome: "allowed"}
	var calls int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "POST" || r.URL.Path != "/v1/publish-runs/"+run+"/service-observations" || r.Header.Get("Authorization") != "Bearer "+token.String() {
			t.Error("audit used another authentication scope")
		}
		var body controlv1.PublishRunServiceObservations
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.PublishRunNumber != 7 || len(body.Events) != 1 || body.Events[0].EventId != o.EventID {
			t.Error("typed observation changed")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"accepted":0,"duplicates":1}`))
	}))
	defer server.Close()
	c, err := New(server.URL, server.Client(), "person-token")
	if err != nil {
		t.Fatal(err)
	}
	if err = c.ReportPublisherServiceObservations(t.Context(), run, 7, token, serviceaudit.Batch{Events: []serviceaudit.Observation{o}}); err != nil {
		t.Fatal(err)
	}
	if err = c.ReportPublisherServiceObservations(t.Context(), run, 8, token, serviceaudit.Batch{Events: []serviceaudit.Observation{o}}); !errors.Is(err, serviceaudit.ErrInvalid) || !errors.Is(err, serviceaudit.ErrRejected) || calls != 1 {
		t.Fatal("cross-run number reached the network", err)
	}
}

func TestPublisherAuditQueueIsolatesLocalScopeRejection(t *testing.T) {
	o := serviceaudit.Observation{EventID: serviceaudit.NewID(), ServiceID: "url_0123456789ABCDEFGHIJKL", ServiceKind: "public_url", EventType: "http.decision", OccurredAt: time.Now(), RunID: "pr_0123456789ABCDEFGHIJKL", RunNumber: 1, VisitorConnectionID: "vc_0123456789ABCDEFGHIJKL", Outcome: "allowed"}
	stored := map[string]bool{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body controlv1.PublishRunServiceObservations
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		for _, event := range body.Events {
			if event.RunId != o.RunID {
				t.Error("local scope rejection reached the network")
			}
			stored[event.EventId] = true
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]int{"accepted": len(body.Events), "duplicates": 0})
	}))
	defer server.Close()
	c, err := New(server.URL, server.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	var dropped uint64
	queue, err := serviceaudit.NewQueue(t.Context(), serviceaudit.QueueConfig{FlushInterval: time.Hour, Dropped: func(n uint64) { dropped += n },
		Report: func(ctx context.Context, batch serviceaudit.Batch) error {
			return c.ReportPublisherServiceObservations(ctx, o.RunID, 1, "run-token", batch)
		}})
	if err != nil {
		t.Fatal(err)
	}
	bad, next := o, o
	bad.EventID, next.EventID = serviceaudit.NewID(), serviceaudit.NewID()
	bad.RunID = "pr_ABCDEFGHIJKL0123456789"
	for _, event := range []serviceaudit.Observation{o, bad, next} {
		if !queue.Observe(event) {
			t.Fatal("queue rejected syntax-valid event")
		}
	}
	if err = queue.Close(t.Context()); err != nil || len(stored) != 2 || !stored[o.EventID] || !stored[next.EventID] || dropped != 1 {
		t.Fatalf("local rejection discarded valid neighbors: stored=%d dropped=%d %v", len(stored), dropped, err)
	}
}

func TestPublisherAuditErrorsExcludeResponseAndTransportSecrets(t *testing.T) {
	o := serviceaudit.Observation{EventID: serviceaudit.NewID(), ServiceID: "url_0123456789ABCDEFGHIJKL", ServiceKind: "public_url", EventType: "http.decision", OccurredAt: time.Now(), RunID: "pr_0123456789ABCDEFGHIJKL", RunNumber: 1, VisitorConnectionID: "vc_0123456789ABCDEFGHIJKL", Outcome: "allowed"}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(403)
		_, _ = w.Write([]byte(`{"code":"forbidden","title":"never-log-secret","status":403}`))
	}))
	defer server.Close()
	c, _ := New(server.URL, server.Client(), "")
	err := c.ReportPublisherServiceObservations(t.Context(), o.RunID, 1, "secret-token", serviceaudit.Batch{Events: []serviceaudit.Observation{o}})
	if !errors.Is(err, serviceaudit.ErrRejected) || strings.Contains(err.Error(), "never-log-secret") || strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("unsafe report error %v", err)
	}
}

func TestPublisherAuditStatusClassificationDoesNotDependOnProblemBody(t *testing.T) {
	o := serviceaudit.Observation{EventID: serviceaudit.NewID(), ServiceID: "url_0123456789ABCDEFGHIJKL", ServiceKind: "public_url", EventType: "http.decision", OccurredAt: time.Now(), RunID: "pr_0123456789ABCDEFGHIJKL", RunNumber: 1, VisitorConnectionID: "vc_0123456789ABCDEFGHIJKL", Outcome: "allowed"}
	for _, status := range []int{400, 401, 403, 404, 409, 410, 413, 429, 500, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
				_, _ = w.Write([]byte("malformed-problem-never-log-secret"))
			}))
			defer server.Close()
			c, err := New(server.URL, server.Client(), "")
			if err != nil {
				t.Fatal(err)
			}
			err = c.ReportPublisherServiceObservations(t.Context(), o.RunID, 1, "private-token", serviceaudit.Batch{Events: []serviceaudit.Observation{o}})
			if err == nil || errors.Is(err, serviceaudit.ErrRejected) != (status < 429) || strings.Contains(err.Error(), "never-log-secret") || strings.Contains(err.Error(), "private-token") {
				t.Fatalf("status %d classification: %v", status, err)
			}
		})
	}
}
