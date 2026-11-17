package daemon

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func startPrivateHTTPTestTarget(t *testing.T, owner *runtimeTopology, handler http.Handler, secured *tls.Config) *httptest.Server {
	t.Helper()
	target := httptest.NewUnstartedServer(handler)
	target.Config.ErrorLog = log.New(io.Discard, "", 0)
	if secured == nil {
		target.Start()
	} else {
		target.TLS = secured
		target.StartTLS()
	}
	t.Cleanup(target.Close)
	return target
}

func TestPrivateHTTPTargetOutlivesPublisherJoin(t *testing.T) {
	for _, secured := range []bool{false, true} {
		t.Run(fmt.Sprintf("tls=%t", secured), func(t *testing.T) {
			joined := false
			t.Run("topology", func(t *testing.T) {
				owner := newRuntimeTopology(t)
				var config *tls.Config
				if secured {
					config = serviceRuntimeTLS(t, newTestCertificateAuthority(t), "target.private.integration.test")
				}
				target := startPrivateHTTPTestTarget(t, owner, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					_, _ = io.WriteString(w, "target still available")
				}), config)
				owner.publishers = append(owner.publishers, runtimeProcess{
					name: "private HTTP publisher", cancel: func() {},
					wait: func() error {
						joined = true
						ctx, cancel := context.WithTimeout(context.Background(), time.Second)
						defer cancel()
						request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.URL, nil)
						if err != nil {
							return err
						}
						response, err := target.Client().Do(request)
						if err != nil {
							return fmt.Errorf("target stopped before publisher joined: %w", err)
						}
						body, readErr := io.ReadAll(response.Body)
						closeErr := response.Body.Close()
						if readErr != nil || closeErr != nil || response.StatusCode != http.StatusOK || string(body) != "target still available" {
							return fmt.Errorf("target changed during publisher join: %q, read: %v, close: %v, status: %d", body, readErr, closeErr, response.StatusCode)
						}
						return nil
					},
				})
			})
			if !joined {
				t.Fatal("publisher cleanup did not join")
			}
		})
	}
}
