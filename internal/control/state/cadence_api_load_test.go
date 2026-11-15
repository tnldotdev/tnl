package state_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	controlingress "github.com/tnldotdev/tnl/internal/control/api/private/ingress"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/ingress"
	serverhttp "github.com/tnldotdev/tnl/internal/serverhttp"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
)

func TestLoadCadence(t *testing.T) {
	controlstate.RunCadenceLoad(t, func(database *controlstate.Database, now func() time.Time) (ingress.ControlClient, error) {
		const secret = "cadence-load-cluster-secret-0123456789"
		secrets, err := serverhttp.NewBearerSecrets(secret, "")
		if err != nil {
			return nil, err
		}
		handler, err := controlingress.NewHandler(controlingress.Config{
			Store: database, ClusterSecrets: secrets, LeaseDuration: 30 * time.Second, Now: now,
		})
		if err != nil {
			return nil, err
		}
		var mu sync.Mutex
		requests := make(map[string]int64)
		started := time.Now()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			requests[r.Method+" "+r.URL.Path]++
			mu.Unlock()
			handler.ServeHTTP(w, r)
		}))
		t.Cleanup(func() {
			// RunCadenceLoad joins the controllers before returning. closing the
			// server joins any remaining HTTP handlers before reading the counts.
			server.Close()
			elapsed := time.Since(started)
			mu.Lock()
			defer mu.Unlock()
			var registrations, renewals, total int64
			var renewalPaths int
			for path, count := range requests {
				total += count
				switch {
				case path == "POST /internal/v1/ingresses/register":
					registrations += count
				case strings.HasPrefix(path, "POST /internal/v1/ingresses/") && strings.HasSuffix(path, "/renew"):
					renewals += count
					renewalPaths++
				default:
					t.Errorf("quiet ingress fleet made an unexpected control request: %s calls=%d", path, count)
				}
			}
			// service updates and relay recovery must not introduce per-service
			// polling or re-register a healthy ingress. the upper bound depends
			// only on the 10s lease cadence, not on the saved service count.
			maximumRenewals := int64(elapsed/(10*time.Second)) + 1
			if registrations != 1 || renewalPaths != 1 || renewals < 1 || renewals > maximumRenewals {
				t.Errorf("quiet ingress fleet HTTP counts: registrations=%d renewal_paths=%d renewals=%d maximum=%d elapsed=%s",
					registrations, renewalPaths, renewals, maximumRenewals, elapsed)
			}
			t.Logf("cadence_http_requests=%d registrations=%d renewals=%d elapsed=%s", total, registrations, renewals, elapsed)
		})
		httpClient := server.Client()
		httpClient.Timeout = 30 * time.Second
		generated, err := ingressv1.NewClientWithResponses(server.URL,
			ingressv1.WithHTTPClient(httpClient),
			ingressv1.WithRequestEditorFn(func(_ context.Context, request *http.Request) error {
				request.Header.Set("Authorization", "Bearer "+secret)
				return nil
			}))
		if err != nil {
			return nil, err
		}
		return ingress.NewHTTPControlClient(generated)
	})
}
