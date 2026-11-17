package app

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/observability"
	"go.opentelemetry.io/otel/trace"
)

func TestRegistrationObservationsAreTransitionsAndWorkerKeepsOwner(t *testing.T) {
	m := observability.New("publisher")
	defer m.Shutdown(context.Background())
	database, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	started := make(chan context.Context, 1)
	manager, err := New(observability.WithMetrics(t.Context(), m), t.TempDir(), database, []Service{{Name: "api"}}, func(ctx context.Context, service Service, observe func(PublicationUpdate) error) error {
		for range 2 {
			if err := observe(PublicationUpdate{RunNumber: 1, Routable: true, Target: service.Target, TunnelID: service.TunnelID, PublicURL: service.PublicURL}); err != nil {
				return err
			}
		}
		started <- ctx
		<-ctx.Done()
		return ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	id, err := manager.Reserve("api", "owner", 1, "https://api.example")
	if err != nil {
		t.Fatal(err)
	}
	scheduling, cancel := context.WithCancel(observability.ExtractLaunch(t.Context(), "00-11111111111111111111111111111111-2222222222222222-01"))
	if err := manager.RegisterContext(scheduling, id, "owner", "http://127.0.0.1:12345", "node"); err != nil {
		t.Fatal(err)
	}
	worker := <-started
	cancel()
	if worker.Err() != nil || observability.FromContext(worker) != m || trace.SpanContextFromContext(worker).IsValid() {
		t.Fatal("request lifetime, parent or owner crossed the worker boundary")
	}
	if err := manager.RegisterContext(t.Context(), id, "owner", "http://127.0.0.1:12345", "node"); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		_ = manager.Snapshot()
	}
	response := httptest.NewRecorder()
	m.Handler().ServeHTTP(response, httptest.NewRequest("GET", "/metrics", nil))
	for _, event := range []string{"registered", "publication_ready"} {
		if !strings.Contains(response.Body.String(), `tnl_client_lifecycle_events_total{tnl_event="`+event+`"} 1`) {
			t.Fatalf("%s was missing or counted by repeated reads/observations", event)
		}
	}
}
