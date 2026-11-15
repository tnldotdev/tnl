package service

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/publisher/requestlimit"
	servicestream "github.com/tnldotdev/tnl/internal/publisher/service/stream"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestServiceConnectionDeadlineClosesSetupAndIdleVisitors(t *testing.T) {
	for _, boundConnection := range []bool{false, true} {
		for _, stage := range []string{"metadata", "tls-setup", "tls-idle", "authorized-idle"} {
			name := map[bool]string{false: "ordinary", true: "fixed"}[boundConnection] + "/" + stage
			t.Run(name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					prepared, bound, ref, verification := privateFixture(t, "127.0.0.1:1")
					verification.Certificates = nil
					prepared.managedProtocol, prepared.target, prepared.servicePort = config.ProtocolHTTP, "", 443
					prepared.handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
					var err error
					prepared.serviceHTTPRequests, err = requestlimit.NewHTTP(nil)
					if err != nil {
						t.Fatal(err)
					}
					scope := visitorscope.Scope{Kind: visitorscope.Service, ID: prepared.Preparation.ServiceId}
					policy, update, _ := visitorfixture.ScopePolicy(t, scope, prepared.managedHostname, 443, true)
					defer policy.Close()
					update.BoundConnections = boundConnection
					update.View.ValidUntil = time.Now().Add(3 * time.Second)
					if err := policy.Apply(policy.Begin(), update); err != nil {
						t.Fatal(err)
					}
					prepared.policy = policy
					prepared.managedVisitor = func(header tunnelv1.ServiceForwardingHeader) servicestream.Authentication {
						return servicestream.HTTPVisitor{Frontend: HTTP{Control: serviceHTTPAdmissionControl{}, Subject: scope,
							RunID: header.ServiceRunID, Number: int64(header.RunNumber), Token: "run-token",
							Hostname: prepared.managedHostname, Port: 443, Header: header,
							Policy: policy, Requests: prepared.serviceHTTPRequests}}
					}
					header := privateHeader(t, ref)
					header.PublicService.DestinationPort = 443
					release, ok := bound.reserveStream(ref)
					if !ok {
						t.Fatal("current visitor could not reserve its capacity")
					}
					visitor, server := net.Pipe()
					done := make(chan struct{})
					go func() {
						defer close(done)
						defer release()
						defer server.Close()
						_ = bound.serveBody(t.Context(), ref, server, header, nil)
					}()
					defer func() {
						_ = visitor.Close()
						_ = server.Close()
						<-done
					}()
					var client net.Conn = visitor
					if stage != "metadata" {
						metadata, err := proxyproto.Encode(proxyproto.Header{Source: netip.MustParseAddrPort("192.0.2.10:40000"), Destination: netip.MustParseAddrPort("203.0.113.1:443")})
						if err != nil {
							t.Fatal(err)
						}
						if _, err := visitor.Write(metadata); err != nil {
							t.Fatal(err)
						}
						if stage != "tls-setup" {
							secured := tls.Client(visitor, verification)
							if err := secured.HandshakeContext(t.Context()); err != nil {
								t.Fatal(err)
							}
							client = secured
							if stage == "authorized-idle" {
								request, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+prepared.managedHostname+"/", nil)
								if err := request.Write(secured); err != nil {
									t.Fatal(err)
								}
								response, err := http.ReadResponse(bufio.NewReader(secured), request)
								if err != nil {
									t.Fatal(err)
								}
								response.Body.Close()
								if response.StatusCode != http.StatusNoContent {
									t.Fatal("visitor was not authorized", response.StatusCode)
								}
							}
						}
					}
					closed := make(chan error, 1)
					go func() { _, err := client.Read(make([]byte, 1)); closed <- err }()
					time.Sleep(2 * time.Second)
					synctest.Wait()
					select {
					case err := <-closed:
						t.Fatal("connection closed before its authority deadline", err)
					default:
					}
					bound.mu.Lock()
					active, capacity := len(bound.active), bound.reservedStreams
					bound.mu.Unlock()
					if active != 1 || capacity != 1 {
						t.Fatal("visitor did not retain its owned socket and capacity", active, capacity)
					}
					time.Sleep(time.Second)
					synctest.Wait()
					select {
					case err := <-closed:
						if !boundConnection || err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
							t.Fatal("connection was not closed by its fixed local authority guard", err)
						}
					default:
						if boundConnection {
							t.Fatal("fixed-authority connection survived its deadline")
						}
					}
					if !boundConnection {
						return
					}
					select {
					case <-done:
					default:
						t.Fatal("expired visitor cleanup did not join")
					}
					bound.mu.Lock()
					defer bound.mu.Unlock()
					if len(bound.active) != 0 || bound.reservedStreams != 0 {
						t.Fatal("expired visitor retained its socket or capacity")
					}
				})
			})
		}
	}
}

type connectionDeadlinePolicyControl struct {
	*lifecycleControl
	deadline time.Time
}

func (c connectionDeadlinePolicyControl) ReadPublisherVisitorPolicy(ctx context.Context, request controlv1.PublisherVisitorPolicyRequest, token string) (controlv1.VisitorPolicyUpdate, error) {
	update, err := c.lifecycleControl.ReadPublisherVisitorPolicy(ctx, request, token)
	update.Policy.ConnectionDeadline = &c.deadline
	update.Policy.ValidUntil = c.deadline
	return update, err
}

func TestServiceConnectionDeadlineAcceptsCurrentServicePolicy(t *testing.T) {
	cfg, control := lifecycleFixture(t)
	approved, err := control.GetPublisherService(t.Context(), cfg.ServiceID, "")
	if err != nil {
		t.Fatal(err)
	}
	approved.Protocol, approved.Endpoint.Port = controlv1.ServiceProtocolHTTP, 443
	control.approved = &approved
	prepared, err := newManagedPrepared(control.prep, approved, cfg)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := prepared.Activate(control.setup)
	if err != nil {
		t.Fatal(err)
	}
	defer bound.Invalidate()
	fixed := time.Now().Add(3 * time.Second)
	backend := connectionDeadlinePolicyControl{lifecycleControl: control, deadline: fixed}
	if err := bound.PrepareConnectorPolicy(t.Context(), backend, credentials.ServiceRunToken(control.setup.RunToken)); err != nil {
		t.Fatal("a current service-scoped connection deadline could not reach the run-owned policy guard", err)
	}
}
