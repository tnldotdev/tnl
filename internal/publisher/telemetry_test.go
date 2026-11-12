package publisher

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"testing"

	clientserver "github.com/tnldotdev/tnl/internal/client/server"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	clienttelemetry "github.com/tnldotdev/tnl/internal/client/telemetry"
	api "github.com/tnldotdev/tnl/pkg/api/integrations/telemetry/v1"
)

type telemetryTransport func(*http.Request) (*http.Response, error)

func (f telemetryTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestTelemetryReadyFollowsSuccessfulPublicationObservation(t *testing.T) {
	for _, server := range []string{clientserver.DefaultURL, "https://private-control.example"} {
		for _, rejected := range []bool{false, true} {
			root := filepath.Join(t.TempDir(), "state")
			state, err := clientstate.OpenWithOptions(t.Context(), root, clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
			if err != nil {
				t.Fatal(err)
			}
			if err := state.Close(); err != nil {
				t.Fatal(err)
			}
			var events []api.Event
			c, err := clienttelemetry.New(context.WithoutCancel(t.Context()), clienttelemetry.Config{Root: root, Protection: clientstate.ProtectionFile, Client: &http.Client{Transport: telemetryTransport(func(r *http.Request) (*http.Response, error) {
				var batch api.Batch
				if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
					t.Error(err)
				}
				for _, event := range batch.Events {
					events = append(events, event.Event)
				}
				return &http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody}, nil
			})}})
			if err != nil {
				t.Fatal(err)
			}
			scope := c.BeginScope("publisher")
			observed := 0
			wantErr := errors.New("presentation rejected readiness")
			cfg := Config{ControlURL: server, Demo: true, TelemetryFramework: api.PublicationReadyFrameworkVite, telemetry: scope, Observe: func(Event) error {
				observed++
				if rejected {
					return wantErr
				}
				return nil
			}}
			for range 2 {
				err := observe(cfg, Event{Type: EventReady, PublicURL: "https://private-project.example"})
				if rejected && !errors.Is(err, wantErr) || !rejected && err != nil {
					t.Fatal(err)
				}
			}
			scope.Close()
			finish, stop := context.WithTimeout(context.Background(), clienttelemetry.RequestTimeout)
			c.Close(finish)
			stop()
			want := 1
			if rejected {
				want = 0
			}
			if observed != 2 || len(events) != want {
				t.Fatalf("forwarded=%d events=%d want=%d", observed, len(events), want)
			}
			if want == 1 {
				event, _ := events[0].AsReadyEvent()
				kind := api.SelfHosted
				if server == clientserver.DefaultURL {
					kind = api.Hosted
				}
				if event.Payload.ServerKind != kind || event.Payload.PublishMode != api.Demo || event.Payload.Framework == nil || *event.Payload.Framework != api.PublicationReadyFrameworkVite {
					t.Fatalf("ready=%+v", event)
				}
			}
		}
	}
}
