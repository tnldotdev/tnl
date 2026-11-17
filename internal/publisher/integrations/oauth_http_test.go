package integrations

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	"github.com/tnldotdev/tnl/internal/publisher/requestlimit"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	servicestream "github.com/tnldotdev/tnl/internal/publisher/service/stream"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestOAuthReturnSurvivesReversibleHTTPRejection(t *testing.T) {
	testOAuthReturnSurvivesReversibleHTTPRejection(t, false)
}

func TestAliasOAuthReturnSurvivesReversibleHTTPRejection(t *testing.T) {
	testOAuthReturnSurvivesReversibleHTTPRejection(t, true)
}

type oauthReturnHTTPFixture struct {
	state *clientstate.Database
	owner *clientstate.Tunnel
	run   publisherservice.HTTPRun
	group clientstate.IntegrationScope
	cfg   publisherservice.RunConfig
}

func newOAuthReturnHTTPFixture(t *testing.T, alias bool) oauthReturnHTTPFixture {
	t.Helper()
	if alias {
		f := newAliasFixture(t)
		store, err := f.state.Server(t.Context(), testServer)
		if err != nil {
			t.Fatal(err)
		}
		id, err := opaqueid.New(opaqueid.ServicePrefix)
		if err != nil {
			t.Fatal(err)
		}
		worker := AliasPublisher(f.state, store, f.selection, f.main.ID(), aliasSnapshot(f.selection, id), nil)
		snapshot, err := worker.Prepare(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		prepared := aliasPreparation(t, id, f.selection.Hostname, 1)
		if err := snapshot.Config.Prepared(prepared); err != nil {
			t.Fatal(err)
		}
		if err := f.state.MarkIntegrationURLReady(t.Context(), testServer, prepared.Hostname, "alias", id, 1); err != nil {
			t.Fatal(err)
		}
		if err := snapshot.Readiness(t.Context(), true); err != nil {
			t.Fatal(err)
		}
		return oauthReturnHTTPFixture{state: f.state, owner: f.main, group: f.group, cfg: snapshot.Config,
			run: publisherservice.HTTPRun{ServiceID: id, RunID: prepared.ServiceRunId, Hostname: prepared.Hostname, Number: 1}}
	}
	state, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	owner, run := readyTunnel(t, state, "3000", "feature.example.test")
	run.RunID = "srun_" + strings.Repeat("R", 22)
	return oauthReturnHTTPFixture{state: state, owner: owner, run: run, group: testIntegrationScope,
		cfg: publisherservice.RunConfig{HTTPPrepareRequest: PrepareOAuthReturn(state, testServer)}}
}

func testOAuthReturnSurvivesReversibleHTTPRejection(t *testing.T, alias bool) {
	t.Helper()
	for _, rejection := range []string{"none", "request_budget", "access", "ingress_capacity"} {
		t.Run(rejection, func(t *testing.T) {
			fixture := newOAuthReturnHTTPFixture(t, alias)
			state, owner, run := fixture.state, fixture.owner, fixture.run
			readyIntegrationURL(t, state, testOAuthHost, "publisher")
			if err := Observer(state, testServer, testOAuthHost, fixture.group, owner.ID())(authorizationResponse("return-state", ""), run); err != nil {
				t.Fatal("record login through observer", err)
			}
			callback := httptest.NewRecorder()
			OAuthHandler(state, testServer, testOAuthHost, nil).ServeHTTP(callback,
				httptest.NewRequest(http.MethodGet, "https://"+testOAuthHost+"/api/auth/callback/github?state=return-state&code=a%2fb%2Bc+z&provider=&provider=x%2Fy", nil))
			if callback.Code != http.StatusSeeOther {
				t.Fatal("dispatch callback", callback.Code)
			}
			address := callback.Header().Get("Location")
			budget, err := requestlimit.NewHTTP(&controlv1.ProjectHTTPApplicationLimits{Concurrency: new(1)})
			if err != nil {
				t.Fatal(err)
			}
			release := func() {}
			if rejection == "request_budget" {
				held, ok := budget.Reserve(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "https://"+run.Hostname+"/held", nil))
				if !ok {
					t.Fatal("reserve sole request slot")
				}
				defer held.Finish()
				release = held.Finish
			}
			var saturated atomic.Bool
			saturated.Store(rejection == "ingress_capacity")
			var prepared, consumed, reached atomic.Int32
			scope := visitorscope.Scope{Kind: visitorscope.Service, ID: run.ServiceID}
			lease, _, signed := visitorfixture.ScopePolicy(t, scope, run.Hostname, 443, false)
			certificate := visitorfixture.Certificate(t, run.Hostname)
			header := tunnelv1.ServiceForwardingHeader{ServiceStreamHeader: tunnelv1.ServiceStreamHeader{
				ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.ServiceForwardingStream, ServiceID: run.ServiceID,
				ServiceRunID: run.RunID, RunNumber: uint64(run.Number),
				SourceIP: "192.0.2.1", VisitorConnectionID: "vc_" + strings.Repeat("V", 22),
				PublisherConnectionID: "pc_" + strings.Repeat("P", 22), ConnectionAssignmentRevision: 1, ExpiresAt: time.Now().Add(time.Minute),
				PublicService: &tunnelv1.PublicServiceAdmission{IngressID: "ingress", IngressRunID: "ir_" + strings.Repeat("I", 22), IngressLeaseRevision: 1, DestinationPort: 443}},
				RelayID: "relay", RelayServiceID: "relay-service", RelayRunID: "rr_" + strings.Repeat("R", 22),
				RelayLeaseRevision: 1, ServingUntil: time.Now().Add(time.Minute)}
			if err := header.Validate(); err != nil {
				t.Fatal(err)
			}
			frontend := publisherservice.HTTP{Subject: scope, RunID: header.ServiceRunID, Number: run.Number,
				Token: credentials.ServiceRunToken("fixture-run"), Hostname: run.Hostname, Port: 443,
				Header: header, Source: netip.MustParseAddrPort("192.0.2.1:1234"), Policy: lease, Requests: budget, AdmitRequest: fixture.cfg.AdmitRequest,
				ReserveCapacity: func(context.Context) error {
					if saturated.Load() {
						return &tunnel.ProtocolError{Code: tunnelv1.CapacityExceeded}
					}
					return nil
				},
				PrepareRequest: func(r *http.Request) (func(context.Context) error, error) {
					if fixture.cfg.HTTPPrepareRequest == nil {
						return nil, nil
					}
					commit, err := fixture.cfg.HTTPPrepareRequest(r, run)
					if err != nil || commit == nil {
						return commit, err
					}
					prepared.Add(1)
					return func(ctx context.Context) error {
						if err := commit(ctx); err != nil {
							return err
						}
						consumed.Add(1)
						return nil
					}, nil
				}}
			target := servicestream.HTTPTarget{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.RawQuery != "state=return-state&code=a%2fb%2Bc+z&provider=&provider=x%2Fy" {
					t.Error("application lost provider query bytes", r.URL.RawQuery)
				}
				reached.Add(1)
				w.WriteHeader(http.StatusNoContent)
			})}
			transport := &http.Transport{MaxConnsPerHost: 1, TLSClientConfig: &tls.Config{RootCAs: visitorfixture.Roots(t, certificate)},
				DialContext: func(context.Context, string, string) (net.Conn, error) {
					visitor, raw := net.Pipe()
					server := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13})
					done := make(chan error, 1)
					go func() {
						defer server.Close()
						done <- frontend.Forward(t.Context(), server, target)
					}()
					t.Cleanup(func() {
						_ = visitor.Close()
						select {
						case <-done:
						case <-time.After(5 * time.Second):
							t.Error("HTTP frontend did not join")
						}
					})
					return visitor, nil
				}}
			t.Cleanup(transport.CloseIdleConnections)
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			visit := func(authorize bool, want int) {
				t.Helper()
				r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, address, nil)
				if err != nil {
					t.Fatal(err)
				}
				if authorize {
					r.Header.Set(httpaccess.VisitorTokenHeader, signed.Reveal())
				}
				response, err := client.Do(r)
				if err != nil {
					t.Fatal(err)
				}
				_, readErr := io.Copy(io.Discard, response.Body)
				closeErr := response.Body.Close()
				if readErr != nil || closeErr != nil {
					t.Fatal(readErr, closeErr)
				}
				if response.StatusCode != want {
					t.Fatalf("response=%d want=%d, prepared=%d consumed=%d app calls=%d", response.StatusCode, want, prepared.Load(), consumed.Load(), reached.Load())
				}
				if (rejection == "request_budget" || rejection == "ingress_capacity") && want == http.StatusServiceUnavailable && prepared.Load() == 1 && response.Header.Get("Retry-After") != "1" {
					t.Fatal("capacity rejection lost its retry hint")
				}
			}
			if rejection != "none" {
				want := http.StatusServiceUnavailable
				if rejection == "access" {
					want = http.StatusForbidden
				}
				visit(rejection != "access", want)
				if !alias && prepared.Load() != 1 || consumed.Load() != 0 || reached.Load() != 0 {
					t.Fatal("reversible rejection spent a callback", prepared.Load(), consumed.Load(), reached.Load())
				}
				release()
				saturated.Store(false)
			}
			visit(true, http.StatusNoContent)
			if !alias && consumed.Load() != 1 || reached.Load() != 1 {
				t.Fatal("admitted callback did not reach app exactly once", consumed.Load(), reached.Load())
			}
			visit(true, http.StatusServiceUnavailable)
			if !alias && consumed.Load() != 1 || reached.Load() != 1 {
				t.Fatal("replayed callback reached the app")
			}
		})
	}
}
