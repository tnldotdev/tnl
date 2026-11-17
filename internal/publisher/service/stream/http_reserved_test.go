package stream

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/policy/applicationlimits"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
)

type connectorHTTPProofFixture struct {
	proof ConnectorHTTPAuthorization
	err   error
}

func (f connectorHTTPProofFixture) HTTPAuthorization(context.Context) (ConnectorHTTPAuthorization, error) {
	return f.proof, f.err
}

type connectorHTTPFrontendFixture struct {
	reserved func(http.ResponseWriter, *http.Request, ConnectorHTTPAuthorization) bool
	prepare  func(http.ResponseWriter, *http.Request) *http.Request
}

func (f connectorHTTPFrontendFixture) ConnectorReserved(w http.ResponseWriter, r *http.Request, proof ConnectorHTTPAuthorization) bool {
	return f.reserved(w, r, proof)
}

func (f connectorHTTPFrontendFixture) ConnectorApplication(w http.ResponseWriter, r *http.Request) *http.Request {
	return f.prepare(w, r)
}

type connectorHTTPBudgetFixture struct{ entries atomic.Int64 }

func (*connectorHTTPBudgetFixture) Limits() applicationlimits.Limits {
	return applicationlimits.Limits{}.Defaults(false)
}

func (f *connectorHTTPBudgetFixture) Admit(http.ResponseWriter, *http.Request) (func(), bool) {
	f.entries.Add(1)
	return func() {}, true
}

func TestConnectorHTTPReservedCompositionRequiresExplicitProofAndPreservesBudget(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		for _, boundary := range []string{"available", "missing proof", "missing frontend", "rejected proof",
			"invalid credential", "known outage", "unexpected fault", "outage and fault", "cancellation and fault"} {
			t.Run(boundary+map[bool]string{false: "/http1", true: "/http2"}[h2], func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				const hostname = "service.example.test"
				certificate := visitorfixture.Certificate(t, hostname)
				var reserved, app, preparations atomic.Int64
				budget := new(connectorHTTPBudgetFixture)
				proof := ConnectorHTTPAuthorization{Source: netip.MustParseAddr("192.0.2.17"), PermissionToken: "private-connector-permission"}
				frontend := connectorHTTPFrontendFixture{
					reserved: func(w http.ResponseWriter, r *http.Request, selected ConnectorHTTPAuthorization) bool {
						reserved.Add(1)
						if selected.PermissionToken != proof.PermissionToken || r.RemoteAddr != "192.0.2.17:1" ||
							r.Host != "127.0.0.1:15432" || r.TLS == nil || r.TLS.ServerName != hostname {
							t.Error("connector reserved dispatch lost its explicit proof, local authority, or trusted source")
						}
						_, _ = io.WriteString(w, "reserved")
						return true
					},
					prepare: func(_ http.ResponseWriter, r *http.Request) *http.Request {
						preparations.Add(1)
						return r
					},
				}
				endpoint := Stream{Protocol: config.ProtocolHTTP, Hostname: hostname, HTTPRequests: budget,
					TLS:           &tls.Config{Certificates: []tls.Certificate{certificate}},
					ConnectorHTTP: frontend,
					Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						app.Add(1)
						if strings.HasPrefix(r.URL.Path, "/__tnl/") {
							t.Error("reserved request reached the target")
						}
						_, _ = io.WriteString(w, "application")
					}),
				}
				visitor := ConnectorVisitor{Admission: new(connectorAdapterAdmission), HTTPProof: connectorHTTPProofFixture{proof: proof}}
				switch boundary {
				case "missing proof":
					visitor.HTTPProof = nil
				case "missing frontend":
					endpoint.ConnectorHTTP = nil
				case "rejected proof":
					visitor.HTTPProof = connectorHTTPProofFixture{err: visitortoken.ErrPolicy}
				case "invalid credential":
					visitor.HTTPProof = connectorHTTPProofFixture{err: visitortoken.ErrToken}
				case "known outage":
					visitor.HTTPProof = connectorHTTPProofFixture{err: clientcontrol.ErrUnavailable}
				case "unexpected fault":
					visitor.HTTPProof = connectorHTTPProofFixture{err: errors.New("private proof implementation fault")}
				case "outage and fault":
					visitor.HTTPProof = connectorHTTPProofFixture{err: errors.Join(clientcontrol.ErrUnavailable, errors.New("private independent fault"))}
				case "cancellation and fault":
					visitor.HTTPProof = connectorHTTPProofFixture{err: errors.Join(context.Canceled, errors.New("private independent fault"))}
				}
				endpoint.Visitor = visitor
				incoming, outgoing := net.Pipe()
				done := make(chan error, 1)
				go func() { done <- endpoint.Forward(ctx, incoming) }()
				defer func() {
					cancel()
					_ = outgoing.Close()
					_ = incoming.Close()
					select {
					case <-done:
					case <-time.After(5 * time.Second):
						t.Error("connector HTTP composition did not join stream cleanup")
					}
				}()
				var dials atomic.Int64
				transport := &http.Transport{ForceAttemptHTTP2: h2,
					TLSClientConfig: &tls.Config{RootCAs: visitorfixture.Roots(t, certificate)},
					DialContext: func(context.Context, string, string) (net.Conn, error) {
						if dials.Add(1) != 1 {
							return nil, errors.New("test cannot replace the admitted connector socket")
						}
						return outgoing, nil
					},
				}
				defer transport.CloseIdleConnections()
				client := &http.Client{Transport: transport}
				call := func(path string) (*http.Response, string) {
					t.Helper()
					request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+hostname+path, nil)
					request.Host = "127.0.0.1:15432"
					request.Header.Set("X-Forwarded-For", "203.0.113.99")
					response, err := client.Do(request)
					if err != nil {
						t.Fatal(err)
					}
					body, err := io.ReadAll(response.Body)
					response.Body.Close()
					if err != nil {
						t.Fatal(err)
					}
					return response, string(body)
				}
				response, body := call("/__tnl/feedback")
				if app.Load() != 0 || budget.entries.Load() != 0 || preparations.Load() != 0 ||
					strings.Contains(body, proof.PermissionToken.Reveal()) {
					t.Fatal("reserved work spent an application request, reached the target, or leaked proof")
				}
				if boundary != "available" {
					if response.StatusCode < 400 || reserved.Load() != 0 {
						t.Fatal("missing or rejected explicit capability fell back to local TCP or another frontend")
					}
					want := map[string]int{"invalid credential": 403, "known outage": 503, "unexpected fault": 500,
						"outage and fault": 500, "cancellation and fault": 500}[boundary]
					if want != 0 && response.StatusCode != want || strings.Contains(body, "private") {
						t.Fatal("real HTTP authorization lost its error class or disclosed a cause", response.StatusCode, body)
					}
					return
				}
				wantProtocol := 1
				if h2 {
					wantProtocol = 2
				}
				if response.StatusCode != http.StatusOK || body != "reserved" || reserved.Load() != 1 || response.ProtoMajor != wantProtocol {
					t.Fatal("reserved composition changed HTTP protocol or dispatch", response.StatusCode, response.Proto)
				}
				response, body = call("/application")
				if response.StatusCode != http.StatusOK || body != "application" || app.Load() != 1 ||
					budget.entries.Load() != 1 || preparations.Load() != 1 || dials.Load() != 1 {
					t.Fatal("reserved handling changed the existing admitted application stream or budget")
				}
			})
		}
	}
}
