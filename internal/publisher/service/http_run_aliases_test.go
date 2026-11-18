package service

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/publisher/requestlimit"
	servicestream "github.com/tnldotdev/tnl/internal/publisher/service/stream"
	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

const httpRunAlias = "r-aaaaaaaaaaaaaaaaaaaaaaaaaa.example.test"

var errAliasPolicy = errors.New("alias policy is unavailable")

type aliasHTTPControl struct {
	serviceHTTPControl
	policy visitorfixture.PolicyClient
	refuse string
}

func (*aliasHTTPControl) ControlURL() string { return "https://control.example.test" }

func (c *aliasHTTPControl) ReadPublisherVisitorPolicy(ctx context.Context, body controlv1.PublisherVisitorPolicyRequest, token string) (controlv1.VisitorPolicyUpdate, error) {
	if body.Hostname == c.refuse || body.Hostname != "preview.example.test" && body.Hostname != httpRunAlias {
		return controlv1.VisitorPolicyUpdate{}, errAliasPolicy
	}
	result, err := c.policy.ReadPublisherVisitorPolicy(ctx, body, token)
	result.Policy.Hostname, result.Policy.Anonymous = body.Hostname, true
	result.Policy.PublicEndpoint = &controlv1.VisitorPublicEndpoint{Hostname: body.Hostname, Port: 443, EndpointRevision: 1}
	return result, err
}

func aliasHTTPConfiguration(t *testing.T, control *aliasHTTPControl) HTTP {
	t.Helper()
	control.policy.Key = ed25519.NewKeyFromSeed([]byte(strings.Repeat("a", 32)))
	requests, err := requestlimit.NewHTTP(&controlv1.ProjectHTTPApplicationLimits{Total: new(2)})
	if err != nil {
		t.Fatal(err)
	}
	header := tunnelv1.ServiceForwardingHeader{ServiceStreamHeader: tunnelv1.ServiceStreamHeader{
		ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.ServiceForwardingStream,
		ServiceID: "svc_" + strings.Repeat("S", 22), ServiceRunID: "srun_" + strings.Repeat("R", 22), RunNumber: 1,
		SourceIP: "192.0.2.1", VisitorConnectionID: "vc_" + strings.Repeat("V", 22),
		PublisherConnectionID: "pc_" + strings.Repeat("P", 22), ConnectionAssignmentRevision: 1,
		ExpiresAt: time.Now().Add(time.Minute), PublicService: &tunnelv1.PublicServiceAdmission{
			IngressID: "ingress", IngressRunID: "ir_" + strings.Repeat("I", 22), IngressLeaseRevision: 1, DestinationPort: 443,
		}},
		RelayID: "relay", RelayServiceID: "relay-service", RelayRunID: "rr_" + strings.Repeat("R", 22),
		RelayLeaseRevision: 1, ServingUntil: time.Now().Add(time.Minute),
	}
	return HTTP{Control: control, PublicEndpoint: true, Subject: visitorscope.Scope{Kind: visitorscope.Service, ID: header.ServiceID},
		RunID: header.ServiceRunID, Number: 1, Token: "run-secret", Hostname: "preview.example.test", RunHostname: httpRunAlias,
		Port: 443, Header: header, Source: netip.MustParseAddrPort("192.0.2.1:1234"), Requests: requests,
		ReserveCapacity: func(context.Context) error { return nil }}
}

func TestServiceHTTPRunAliasSharesBudgetsAndRejectsCoalescedHosts(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(map[bool]string{false: "http1", true: "http2"}[h2], func(t *testing.T) {
			control := &aliasHTTPControl{}
			frontend, closeFrontend, err := PrepareHTTP(t.Context(), aliasHTTPConfiguration(t, control))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := closeFrontend(); err != nil {
					t.Error(err)
				}
				if _, enabled, _ := frontend.Policy.Current(); enabled {
					t.Error("canonical policy survived frontend cleanup")
				}
				if _, enabled, _ := frontend.alias.Policy.Current(); enabled {
					t.Error("alias policy survived frontend cleanup")
				}
			})
			if frontend.alias == nil || frontend.Requests != frontend.alias.Requests ||
				frontend.probes != frontend.alias.probes || frontend.preparations != frontend.alias.preparations {
				t.Fatal("an alias created an independent application or readiness budget")
			}
			var forwarded atomic.Int32
			certificate := visitorfixture.Certificate(t, "*.example.test")
			client := func(sni string) *http.Client {
				transport := &http.Transport{ForceAttemptHTTP2: h2, TLSClientConfig: &tls.Config{
					RootCAs: visitorfixture.Roots(t, certificate), ServerName: sni,
				}, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					visitor, raw := net.Pipe()
					done := make(chan struct{})
					stream := servicestream.Stream{Protocol: config.ProtocolHTTP, Public: true,
						Hostname: frontend.Hostname, RunHostname: frontend.RunHostname,
						TLS:     &tls.Config{Certificates: []tls.Certificate{certificate}},
						Visitor: servicestream.HTTPVisitor{Frontend: frontend},
						Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
							forwarded.Add(1)
							w.WriteHeader(http.StatusNoContent)
						}),
					}
					go func() { defer close(done); _ = stream.Forward(t.Context(), raw) }()
					t.Cleanup(func() { _ = visitor.Close(); serviceHTTPAwait(t, done) })
					return visitor, nil
				}}
				t.Cleanup(transport.CloseIdleConnections)
				return &http.Client{Transport: transport, Timeout: 5 * time.Second}
			}
			canonicalClient, aliasClient := client(frontend.Hostname), client(strings.ToUpper(httpRunAlias))
			for _, step := range []struct {
				client *http.Client
				host   string
				status int
			}{
				{aliasClient, frontend.Hostname, http.StatusMisdirectedRequest},
				{canonicalClient, httpRunAlias, http.StatusMisdirectedRequest},
				{canonicalClient, frontend.Hostname, http.StatusNoContent},
				{aliasClient, httpRunAlias, http.StatusNoContent},
				{canonicalClient, frontend.Hostname, http.StatusServiceUnavailable},
				{aliasClient, httpRunAlias, http.StatusServiceUnavailable},
			} {
				request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+step.host+"/", nil)
				if err != nil {
					t.Fatal(err)
				}
				result := serviceHTTPDo(step.client, request)
				if result.err != nil || result.status != step.status || h2 && result.protocol != 2 {
					t.Fatal("alias changed host isolation or the shared budget", step.host, result.status, result.protocol, result.err)
				}
			}
			if forwarded.Load() != 2 {
				t.Fatal("host mismatch spent a request or an alias reset the budget", forwarded.Load())
			}
		})
	}
}

func TestServiceHTTPRunAliasPreparationFailureJoinsPrimaryPolicy(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		control := &aliasHTTPControl{refuse: httpRunAlias}
		if _, closeFrontend, err := PrepareHTTP(t.Context(), aliasHTTPConfiguration(t, control)); !errors.Is(err, errAliasPolicy) || closeFrontend != nil {
			t.Fatal("alias preparation returned an unowned primary frontend", err)
		}
		calls := control.policy.Calls.Load()
		time.Sleep(4 * time.Second)
		synctest.Wait()
		if calls != 1 || control.policy.Calls.Load() != calls {
			t.Fatal("failed alias preparation left the primary refresh worker running")
		}
	})
}
