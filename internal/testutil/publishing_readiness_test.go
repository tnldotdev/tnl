package testutil

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestPublishingFixtureRenewJoinsAuthenticatedHandshakes(t *testing.T) {
	for _, name := range []string{"registered", "handshake_failed", "canceled", "closed_run", "replaced_run", "wrong_token"} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				service := controlv1.Service{Id: "service", Enabled: true, EndpointRevision: 1,
					Endpoint: &controlv1.ServiceEndpoint{Public: true}}
				run := &publishingRunState{installed: true, PublishingRun: PublishingRun{
					Service:     service,
					Preparation: controlv1.ServiceRunPreparation{ExpiresAt: time.Now().Add(time.Minute)},
					Setup:       controlv1.ServiceRunSetup{ServiceId: service.Id, ServiceRunId: "run", RunNumber: 1, RunToken: "run-token"},
				}}
				first := &publishingConnection{ref: tunnelv1.ServicePublisherConnectionRef{
					ServiceID: service.Id, ServiceRunID: "run", PublisherConnectionID: "first"}, accepted: make(chan struct{})}
				second := &publishingConnection{ref: tunnelv1.ServicePublisherConnectionRef{
					ServiceID: service.Id, ServiceRunID: "run", PublisherConnectionID: "second"}, accepted: make(chan struct{})}
				other := &publishingConnection{ref: tunnelv1.ServicePublisherConnectionRef{
					ServiceID: "other-service", ServiceRunID: "other-run", PublisherConnectionID: "other"}, accepted: make(chan struct{})}
				f := &PublishingFixture{
					services: map[string]controlv1.Service{service.Id: service},
					runs:     map[string]*publishingRunState{"run": run}, current: map[string]string{service.Id: "run"},
					connections: map[string]*publishingConnection{"first": first, "second": second, "other": other},
				}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				request := httptest.NewRequest(http.MethodPost, "/v1/services/service/runs/run/renew",
					strings.NewReader(`{"healthy":true,"stream_capacity":64,"active_streams":0}`)).WithContext(ctx)
				request.Header.Set("Authorization", "Bearer "+run.Setup.RunToken)
				if name == "wrong_token" {
					request.Header.Set("Authorization", "Bearer another-run-token")
				}
				done := make(chan *httptest.ResponseRecorder, 1)
				go func() {
					response := httptest.NewRecorder()
					f.serve(response, request)
					done <- response
				}()
				synctest.Wait()
				if name == "wrong_token" {
					select {
					case response := <-done:
						if response.Code != http.StatusUnauthorized {
							t.Fatal("pending handshake bypassed run-token authorization", response.Code)
						}
					default:
						t.Fatal("unauthorized renewal waited for publisher setup")
					}
					return
				}
				assertPending := func() {
					t.Helper()
					select {
					case response := <-done:
						t.Fatalf("renew returned before authenticated handshakes settled: HTTP %d %s", response.Code, response.Body.String())
					default:
					}
					if run.healthy || run.notified {
						t.Fatal("pending handshake manufactured a healthy or ready observation")
					}
				}
				assertPending()
				// a completed first slot cannot make the second slot ready. an
				// unrelated run's handshake must not delay this run's response.
				f.mu.Lock()
				first.session = new(tunnel.Session)
				close(first.accepted)
				f.mu.Unlock()
				synctest.Wait()
				assertPending()
				wantStatus := http.StatusOK
				f.mu.Lock()
				switch name {
				case "handshake_failed":
					delete(f.connections, "second")
				case "canceled":
					cancel()
					wantStatus = http.StatusServiceUnavailable
				case "closed_run":
					run.closed = true
					wantStatus = http.StatusNotFound
				case "replaced_run":
					f.current[service.Id] = "replacement"
					wantStatus = http.StatusNotFound
				default:
					second.session = new(tunnel.Session)
				}
				if name != "canceled" {
					close(second.accepted)
					if second.session == nil {
						delete(f.connections, "second")
					}
				}
				f.mu.Unlock()
				synctest.Wait()
				var response *httptest.ResponseRecorder
				select {
				case response = <-done:
				default:
					t.Fatal("settled handshakes or canceled renewal did not join")
				}
				if response.Code != wantStatus {
					t.Fatalf("renew status=%d, want %d", response.Code, wantStatus)
				}
				if wantStatus != http.StatusOK {
					if run.healthy || run.notified {
						t.Fatal("failed renewal changed serving readiness")
					}
					return
				}
				var state controlv1.ServiceRunState
				if err := json.Unmarshal(response.Body.Bytes(), &state); err != nil {
					t.Fatal(err)
				}
				wantReady := name == "registered"
				if (state.State == controlv1.ServiceRunStateStateReady) != wantReady ||
					state.PublicEndpointReady != wantReady || run.notified != wantReady ||
					state.ServiceRunId != "run" || state.RunNumber != 1 || state.EndpointRevision != 1 {
					t.Fatalf("renew lost its exact completed connection facts: %+v", state)
				}
			})
		})
	}
}
