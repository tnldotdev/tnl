package deploymentdiscovery

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
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
	for _, test := range []struct {
		name, path      string
		certificateOnly bool
	}{
		{name: "heartbeat", path: publicationPaths[0]},
		{name: "certificate", path: publicationPaths[1]},
		{name: "certificate-with-failed-heartbeat", path: publicationPaths[1], certificateOnly: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := publicationFixture()
				f.HoldPublication.Store(!test.certificateOnly)
				f.HoldCertificate.Store(test.certificateOnly)
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				request := httptest.NewRequest(http.MethodPost, "https://control.fixture"+test.path, strings.NewReader(`{"healthy":true}`)).WithContext(ctx)
				response := httptest.NewRecorder()
				done := make(chan struct{})
				var aborted any
				go func() {
					defer func() { aborted = recover(); close(done) }()
					f.serve(t, response, request)
				}()
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
				if test.certificateOnly {
					heartbeat := httptest.NewRequest(http.MethodPost, "https://control.fixture"+publicationPaths[0], strings.NewReader(`{"healthy":true}`))
					result := httptest.NewRecorder()
					f.serve(t, result, heartbeat)
					if result.Code != http.StatusServiceUnavailable {
						t.Fatal("held certificate hid the independent heartbeat failure", result.Code)
					}
				}
				cancel()
				<-done
				if aborted != http.ErrAbortHandler {
					t.Fatal("held publication did not abort HTTP response after cancellation", aborted)
				}
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

func TestHeldPublicationDisconnectCannotReturnEmptySuccess(t *testing.T) {
	for _, path := range publicationPaths {
		for _, missingBytes := range []int{0, 1} {
			t.Run(fmt.Sprintf("%s/missing_bytes=%d", path, missingBytes), func(t *testing.T) {
				f := publicationFixture()
				f.HoldPublication.Store(true)
				done := make(chan struct{})
				serverContext, stopServer := context.WithCancel(t.Context())
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					defer close(done)
					f.serve(t, w, r)
				}))
				server.Config.BaseContext = func(net.Listener) context.Context { return serverContext }
				server.StartTLS()
				defer func() { stopServer(); server.Close() }()
				connection, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second},
					"tcp", server.Listener.Addr().String(), server.Client().Transport.(*http.Transport).TLSClientConfig)
				if err != nil {
					t.Fatal(err)
				}
				defer connection.Close()
				if err := connection.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
					t.Fatal(err)
				}
				const body = `{"healthy":true}`
				request, err := http.NewRequest(http.MethodPost, server.URL+path, strings.NewReader(body))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := fmt.Fprintf(connection, "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n\r\n%s",
					request.URL.RequestURI(), request.URL.Host, len(body)+missingBytes, body); err != nil {
					t.Fatal(err)
				}
				if strings.HasSuffix(path, "/renew") {
					select {
					case <-f.Heartbeat:
					case <-time.After(3 * time.Second):
						t.Fatal("heartbeat body did not decode before disconnect")
					}
				}
				// ending the write side cancels the server request while its
				// response side remains readable. returning would invent HTTP 200.
				// a missing byte also exercises cancellation during body drainage.
				if err := connection.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				response, err := http.ReadResponse(bufio.NewReader(connection), request)
				if response != nil {
					_ = response.Body.Close()
					t.Fatalf("held publication invented HTTP %d after disconnect", response.StatusCode)
				}
				if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Fatalf("held publication did not abort its response: %v", err)
				}
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Fatal("held publication did not join after disconnect")
				}
			})
		}
	}
}
