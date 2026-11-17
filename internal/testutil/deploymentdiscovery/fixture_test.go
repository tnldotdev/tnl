package deploymentdiscovery

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func publicationFixture() *Fixture {
	f := &Fixture{Heartbeat: make(chan controlv1.ServiceRunHeartbeat, 1)}
	f.service.Id, f.setup.ServiceRunId = "service", "run"
	f.assignment.Services = []controlv1.DeploymentPublisherServiceAssignment{{ServiceId: "service"}}
	return f
}

var publicationPaths = []string{
	"/v1/services/service/runs/run/renew",
	"/v1/services/service/runs/run/certificate-issuances",
}

func TestHeldPublicationCannotRaceCancellationWithFixtureFailure(t *testing.T) {
	for _, path := range publicationPaths {
		t.Run(path, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := publicationFixture()
				f.HoldPublication.Store(true)
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				request := httptest.NewRequest(http.MethodPost, "https://control.fixture"+path, strings.NewReader(`{"healthy":true}`)).WithContext(ctx)
				response := httptest.NewRecorder()
				done := make(chan struct{})
				go func() { defer close(done); f.serve(t, response, request) }()
				defer func() { cancel(); <-done }()
				synctest.Wait()
				select {
				case <-done:
					t.Fatal("held publication returned an independent fixture response before cancellation", response.Code, response.Body.String())
				default:
				}
				if !f.mu.TryLock() {
					t.Fatal("held publication prevents concurrent control cleanup")
				}
				f.mu.Unlock()
				cancel()
				<-done
				if response.Body.Len() != 0 {
					t.Fatal("cancellation invented an independent fixture failure", response.Body.String())
				}
			})
		})
	}
}

func TestUnheldPublicationRetainsFixtureFailure(t *testing.T) {
	for _, path := range publicationPaths {
		f := publicationFixture()
		request := httptest.NewRequest(http.MethodPost, "https://control.fixture"+path, strings.NewReader(`{"healthy":true}`))
		response := httptest.NewRecorder()
		f.serve(t, response, request)
		if response.Code != http.StatusServiceUnavailable {
			t.Fatal("unheld fixture lost its independent failure", path, response.Code)
		}
	}
}

func TestHeldPublicationJoinsAfterHTTPClientCancellation(t *testing.T) {
	for _, path := range publicationPaths {
		t.Run(path, func(t *testing.T) {
			f := publicationFixture()
			f.HoldPublication.Store(true)
			entered, done := make(chan struct{}), make(chan struct{})
			serverContext, stopServer := context.WithCancel(t.Context())
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(done)
				close(entered)
				f.serve(t, w, r)
			}))
			server.Config.BaseContext = func(net.Listener) context.Context { return serverContext }
			server.StartTLS()
			defer func() { stopServer(); server.Close() }()
			client := server.Client()
			defer client.CloseIdleConnections()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			// trailing data leaves a body unread after the heartbeat decoder's
			// first JSON value, as well as on the certificate request.
			body := `{"healthy":true}` + strings.Repeat(" ", 64<<10)
			request, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+path, strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			go func() {
				response, err := client.Do(request)
				if response != nil {
					_ = response.Body.Close()
				}
				result <- err
			}()
			defer func() { cancel(); <-result }()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("HTTPS request did not reach the fixture")
			}
			cancel()
			select {
			case err := <-result:
				result <- err
				if !errors.Is(err, context.Canceled) {
					t.Fatal("held request returned before client cancellation", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("HTTPS client did not join")
			}
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("held fixture did not observe client cancellation before server shutdown")
			}
		})
	}
}
