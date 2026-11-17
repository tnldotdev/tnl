package daemon

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/connector/workload"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/githubtest"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationWorkloadColdPOSTRestoration(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	f, issuer := newWorkloadTransportFixture(t)
	process := startSeparatedPrivateIngress(t, f, 0, "tls-tcp", nil)
	second := startSeparatedPrivateIngress(t, f, 1, "tls-tcp", nil)
	payload := bytes.Repeat([]byte("\x00workload\xff\n"), 32<<10)
	var echoes, once, unexpected atomic.Int32
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/echo" && r.URL.Path != "/once" {
			unexpected.Add(1)
			t.Error("cold POST fixture received a warmup or an unrelated application request")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.TLS == nil || r.Header.Get("Authorization") != "Bearer application-owned" {
			t.Error("cold POST lost independent target TLS or application authorization")
		}
		if r.Header.Get("Tnl-Visitor-Token") != "" || r.Header.Get("Tnl-Access-Token") != "" ||
			r.Header.Get("Idempotency-Key") != "" || r.Header.Get("X-Idempotency-Key") != "" {
			t.Error("cold POST substituted visitor credentials or replay permission")
		}
		if r.URL.Path == "/once" {
			once.Add(1)
		} else {
			echoes.Add(1)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil || !bytes.Equal(body, payload) {
			t.Error("first application request lost binary POST bytes", len(body), err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.URL.Path == "/once" {
			connection, _, err := http.NewResponseController(w).Hijack()
			if err != nil {
				t.Error("response-loss target could not close its connection", err)
				return
			}
			_ = connection.Close()
			return
		}
		_, _ = w.Write(body)
	}))
	targetCA := newTestCertificateAuthority(t)
	const targetHostname = "workload.private.integration.test"
	target.TLS = serviceRuntimeTLS(t, targetCA, targetHostname)
	target.StartTLS()
	t.Cleanup(target.Close)
	trust := serviceHTTPTestTargetTrust(targetHostname, string(targetCA.certificatePEM))
	group, protocol := "public", controlv1.ServiceProtocolHTTP
	policies := map[string]controlv1.ProjectWorkload{"test": {
		Deployment: group, Provider: controlv1.WorkloadGitHub,
		Github: &controlv1.ProjectWorkloadGitHub{
			Repository: "example/repository", RepositoryId: "12345", RepositoryOwnerId: "6789",
			WorkflowRef: "example/repository/.github/workflows/test.yml@refs/heads/main",
			Ref:         "refs/heads/main", Events: []string{"push"},
		},
		Services: []string{"api"}, MaxDurationSeconds: 120,
	}}
	applied, err := f.identity.routes.ApplyProjectConfiguration(t.Context(), "workload", controlv1.ApplyProjectConfigurationRequest{
		Deployment: group, ServiceDeclarations: controlv1.ProjectServiceDeclarations{"api": protocol},
		TeamId: f.identity.teamID, Source: &testProjectSource,
		Configuration: controlv1.ProjectConfiguration{
			Workloads: &policies, Settings: &controlv1.DeploymentSettings{},
			Services: map[string]controlv1.ProjectServiceConfiguration{
				"api": {Protocol: &protocol, Target: target.URL, TargetTls: &trust, Public: new(true)},
			},
			Webhooks: map[string]controlv1.ProjectWebhook{},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	job, err := workload.New(f.controlConfig.ControlOrigin(), f.publicHTTP)
	if err != nil {
		t.Fatal(err)
	}
	claims := githubtest.Claims(f.controlConfig.ControlOrigin(), time.Now())
	claims["check_run_id"], claims["jti"] = "301", "301"
	if _, err := job.Exchange(t.Context(), f.identity.teamID, "workload", applied.SourceFingerprint, "test", issuer.Sign(t, claims), nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := job.Revoke(ctx); err != nil {
			t.Error("revoke the cold POST fixture's owned workload", err)
		}
	})
	// establish the real session before publishers take their initial policy
	// snapshot. this case tests cold connections, not session-propagation latency.
	startWorkloadPublishers(t, f, group, "tls-tcp")
	inventory, err := job.ListServices(t.Context())
	if err != nil || len(inventory.Services) != 1 || inventory.Services[0].Service != "api" {
		t.Fatal("cold POST workload did not select its exact service", err)
	}
	service := inventory.Services[0]
	// wait on actual routing observations, not an application GET or a
	// manufactured permission. the first HTTP request on each client stays POST.
	var readyAt time.Time
	if err := f.inspect.QueryRowContext(t.Context(),
		`SELECT ready_at FROM control.service_runs WHERE service_id=$1 AND state='ready'`,
		service.Id).Scan(&readyAt); err != nil {
		t.Fatal(err)
	}
	privateWait(t, 10*time.Second, func(context.Context) (bool, error) {
		return !process.ingresses[0].server.RoutingObservedAt().Before(readyAt) &&
			!second.ingresses[0].server.RoutingObservedAt().Before(readyAt), nil
	})
	endpoint := "https://" + net.JoinHostPort(service.Endpoint.Hostname, strconv.Itoa(service.Endpoint.Port))
	for _, test := range []struct {
		name, path string
		count      int
		status     int
	}{
		{"echo", "/echo", 3, http.StatusOK},
		{"response-loss", "/once", 1, http.StatusBadGateway},
	} {
		t.Run(test.name, func(t *testing.T) {
			certificate, err := job.ClientTLSCertificate(t.Context(), service.Id)
			if err != nil {
				t.Fatal(err)
			}
			verification := f.visitorRoots.Clone()
			verification.ServerName = service.Endpoint.Hostname
			verification.Certificates = append(verification.Certificates[:0:0], certificate)
			dial := workloadPublicEndpointDialer(t, process.ingresses[0].server, service.Endpoint.Port)
			var dials atomic.Int32
			transport := &http.Transport{TLSClientConfig: verification, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				dials.Add(1)
				return dial(ctx, network, address)
			}}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second,
				CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			for index := range test.count {
				var acquired, reused atomic.Bool
				trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
					acquired.Store(true)
					if info.Reused {
						reused.Store(true)
					}
				}}
				request, err := http.NewRequestWithContext(httptrace.WithClientTrace(t.Context(), trace), http.MethodPost, endpoint+test.path, bytes.NewReader(payload))
				if err != nil {
					t.Fatal(err)
				}
				request.Header.Set("Authorization", "Bearer application-owned")
				// no GET, delayed body, custom pre-byte promotion, retry loop or
				// idempotency key precedes this fresh client's first POST.
				response, err := client.Do(request)
				if err != nil {
					t.Fatal("cold first POST failed without a retry", err)
				}
				body, readErr := io.ReadAll(response.Body)
				closeErr := response.Body.Close()
				if index == 0 && (!acquired.Load() || reused.Load() || dials.Load() != 1) {
					t.Fatal("first POST was not the fresh client's first connection", acquired.Load(), reused.Load(), dials.Load())
				}
				if response.TLS == nil || !response.TLS.HandshakeComplete || len(response.TLS.VerifiedChains) == 0 ||
					response.TLS.ServerName != service.Endpoint.Hostname {
					t.Fatal("cold POST did not verify the service's actual TLS identity")
				}
				if readErr != nil || closeErr != nil || response.StatusCode != test.status {
					t.Fatal("cold POST response changed", response.StatusCode, readErr, closeErr)
				}
				if test.path == "/echo" && !bytes.Equal(body, payload) {
					t.Fatal("cold POST echo changed its original binary payload", len(body))
				}
			}
			if test.path == "/once" && once.Load() != 1 {
				t.Fatal("response loss replayed the original POST", once.Load())
			}
		})
	}
	if echoes.Load() != 3 || once.Load() != 1 || unexpected.Load() != 0 {
		t.Fatal("cold POST workload changed its exact application counts", echoes.Load(), once.Load(), unexpected.Load())
	}
}
