package service

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	"github.com/tnldotdev/tnl/internal/publisher/requestlimit"
	servicestream "github.com/tnldotdev/tnl/internal/publisher/service/stream"
	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestServiceHTTPFailedIngressRefundsApplicationReservation(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(map[bool]string{false: "http1", true: "http2"}[h2], func(t *testing.T) {
			budget, err := requestlimit.NewHTTP(&controlv1.ProjectHTTPApplicationLimits{Total: new(1), Concurrency: new(1),
				Rate: &controlv1.ProjectApplicationRate{Count: 1, Per: "1h", Burst: new(1)}})
			if err != nil {
				t.Fatal(err)
			}
			var ingress, applications atomic.Int32
			client, _, _, token := serviceHTTPConfiguredFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				applications.Add(1)
				http.Error(w, "application failed", http.StatusInternalServerError)
			}), h2, true, func(frontend *HTTP) {
				frontend.Requests = budget
				frontend.ReserveCapacity = func(context.Context) error {
					if ingress.Add(1) == 1 {
						return errors.New("ingress acknowledgment failed")
					}
					return nil
				}
			})
			for _, step := range []struct {
				path       string
				credential bool
				status     int
			}{
				{"/__tnl/missing", true, http.StatusNotFound},
				{"/", false, http.StatusForbidden},
				{"/", true, http.StatusServiceUnavailable},
				{"/", true, http.StatusInternalServerError},
			} {
				select {
				case <-budget.Completed():
					t.Fatal("internal, rejected, or failed ingress work spent the application total")
				default:
				}
				request, err := http.NewRequestWithContext(t.Context(), "GET", "https://preview.example.test"+step.path, nil)
				if err != nil {
					t.Fatal(err)
				}
				if step.credential {
					request.Header.Set(httpaccess.VisitorTokenHeader, token.Reveal())
				}
				response, err := client.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				_, err = io.Copy(io.Discard, response.Body)
				response.Body.Close()
				if err != nil || response.StatusCode != step.status {
					t.Fatal(response.Status, err)
				}
			}
			serviceHTTPAwait(t, budget.Completed())
			if ingress.Load() != 2 || applications.Load() != 1 {
				t.Fatal("refund retried ingress traffic or an application failure was not counted", ingress.Load(), applications.Load())
			}
		})
	}
}

func TestServiceHTTPSharedCompletionAcrossPublicConnectorAndBase(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(map[bool]string{false: "http1", true: "http2"}[h2], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			b, peer, trust, opening, _ := connectorPeerFixture(t, "127.0.0.1:1")
			b.prepared.managedProtocol = config.ProtocolHTTP
			b.prepared.target = ""
			var err error
			b.prepared.serviceHTTPRequests, err = requestlimit.NewHTTP(&controlv1.ProjectHTTPApplicationLimits{Total: new(3)})
			if err != nil {
				t.Fatal(err)
			}
			budget := b.prepared.serviceHTTPRequests
			entered := make(chan string, 3)
			finishes := map[string]chan struct{}{"/public": make(chan struct{}), "/connector": make(chan struct{}), "/base": make(chan struct{})}
			releases := make(map[string]func())
			for path, finish := range finishes {
				releases[path] = sync.OnceFunc(func() { close(finish) })
			}
			defer func() {
				for _, release := range releases {
					release()
				}
			}()
			b.prepared.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Trailer", "X-Final")
				entered <- r.URL.Path
				<-finishes[r.URL.Path]
				_, _ = io.WriteString(w, r.URL.Path)
				w.Header().Set("X-Final", "complete")
			})
			scope := visitorscope.Scope{Kind: visitorscope.Service, ID: b.prepared.Preparation.ServiceId}
			policy, update, token := visitorfixture.ScopePolicy(t, scope, b.prepared.managedHostname, 443, false)
			defer policy.Close()
			header := privateHeader(t, b.prepared.connectionRef(b.connections[0]))
			header.PublicService.DestinationPort = 443
			frontend := HTTP{Control: serviceHTTPControl{}, Subject: scope, RunID: header.ServiceRunID,
				Number: int64(header.RunNumber), Token: "run-token", Hostname: update.View.Hostname, Port: 443,
				Source: netip.AddrPortFrom(netip.MustParseAddr(header.SourceIP), 4321),
				Header: header, Policy: policy, Requests: budget, ReserveCapacity: func(context.Context) error { return nil }, protection: serviceHTTPInspector(t, b.prepared.httpProtection)}
			certificate := b.prepared.certificate
			// base HTTP uses certificate authorization; connector HTTP proves its
			// signed opening through the real peer owner below.
			baseTrust := trust.Clone()
			baseTrust.Certificates = []tls.Certificate{certificate}
			baseVisitor := servicestream.CertificateVisitor{Check: func(context.Context, *x509.Certificate) (servicestream.Decision, error) {
				return servicestream.Decision{Allowed: true, ValidUntil: time.Now().Add(time.Minute)}, nil
			}}
			var forwards sync.WaitGroup
			newDirect := func(visitor servicestream.Authentication, verification *tls.Config) *http.Transport {
				return &http.Transport{ForceAttemptHTTP2: h2, TLSClientConfig: verification.Clone(), DialContext: func(context.Context, string, string) (net.Conn, error) {
					visitorConn, server := net.Pipe()
					forwards.Go(func() {
						defer server.Close()
						if err := b.forwardManaged(ctx, server, visitor, b.prepared.managedHostname, nil); err != nil {
							t.Error("HTTP forwarding failed", err)
						}
					})
					return visitorConn, nil
				}}
			}
			publicTransport := newDirect(servicestream.HTTPVisitor{Frontend: frontend}, trust)
			baseTransport := newDirect(baseVisitor, baseTrust)
			client, server := connectorInnerPair(t, ctx, trust)
			peerDone := make(chan error, 1)
			go func() { peerDone <- serveConnectorInner(ctx, peer, server) }()
			defer func() {
				for _, release := range releases {
					release()
				}
				cancel()
				peer.Close()
				<-peerDone
				forwards.Wait()
			}()
			control := connectorControl(t, ctx, client, peer)
			connectorTransport := &http.Transport{ForceAttemptHTTP2: h2, TLSClientConfig: trust.Clone(), DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				raw, err := client.OpenStream(ctx)
				if err != nil {
					return nil, err
				}
				entry := opening("J")
				if _, err := tunnelv1.WriteConnectorPeerVisitorOpening(raw, entry, nil); err != nil {
					_ = raw.Close()
					return nil, err
				}
				return &connectorAcceptedTestConn{Conn: raw, visitor: entry.VisitorConnectionID}, nil
			}}
			transports := map[string]*http.Transport{"/public": publicTransport, "/connector": connectorTransport, "/base": baseTransport}
			for _, transport := range transports {
				defer transport.CloseIdleConnections()
			}
			replied := make(chan string, 3)
			for path, transport := range transports {
				go func() {
					request, err := http.NewRequestWithContext(ctx, "GET", "https://"+b.prepared.managedHostname+path, nil)
					if err != nil {
						t.Error(err)
						replied <- path
						return
					}
					if path == "/public" {
						request.Header.Set(httpaccess.VisitorTokenHeader, token.Reveal())
					}
					response, err := transport.RoundTrip(request)
					if err != nil {
						t.Error(path, err)
						replied <- path
						return
					}
					body, err := io.ReadAll(response.Body)
					response.Body.Close()
					protocol := 1
					if h2 {
						protocol = 2
					}
					if err != nil || string(body) != path || response.Trailer.Get("X-Final") != "complete" || response.ProtoMajor != protocol {
						t.Error("shared completion cut off a final response", path, string(body), response.Trailer, response.Proto, err)
					}
					if path == "/connector" {
						entry := opening("J")
						exchange, err := control.Complete(ctx, tunnelv1.ConnectorVisitorTerminalKey{VisitorConnectionID: entry.VisitorConnectionID, DeliveryGeneration: entry.DeliveryGeneration})
						if err != nil || !exchange.Matched || !exchange.ObservedWritten || exchange.Result.Outcome != tunnelv1.ConnectorTerminalAccepted {
							t.Error("acknowledge complete connector response", err)
						}
					}
					replied <- path
				}()
			}
			for range 3 {
				serviceHTTPAwait(t, entered)
			}
			for _, path := range []string{"/public", "/base"} {
				releases[path]()
				serviceHTTPAwait(t, replied)
				select {
				case <-budget.Completed():
					t.Fatal("another path's final application request was still active")
				default:
				}
			}
			releases["/connector"]()
			serviceHTTPAwait(t, budget.Completed())
			if err := b.startDrain(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal("HTTP drain failed to close a pending opening", err)
			}
			if err := b.joinDrain(); err != nil {
				t.Fatal(err)
			}
			serviceHTTPAwait(t, replied)
			// forwarding is fenced before peer or relay transports are closed.
			if err := b.forwardManaged(ctx, nil, baseVisitor, "", nil); !errors.Is(err, ErrPrivateStream) {
				t.Fatal("draining run admitted another visitor", err)
			}
			peer.Close()
			b.mu.Lock()
			active, pending := b.reservedStreams, b.connectorPending
			b.mu.Unlock()
			if active != 0 || pending != 0 {
				t.Fatal("completion left connector work or charges unjoined", active, pending)
			}
		})
	}
}
