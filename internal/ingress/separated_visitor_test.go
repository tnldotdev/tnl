package ingress

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-yamux/v5"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	servicestream "github.com/tnldotdev/tnl/internal/publisher/service/stream"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
	"github.com/tnldotdev/tnl/internal/transport/httpstream"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type separatedHTTPControl struct {
	publisherservice.HTTPControl
	policy       *visitorfixture.PolicyClient
	service, run string
	admitted     <-chan string
	decisions    chan controlv1.AuthorizeServiceHTTPVisitorRequest
}

func (c separatedHTTPControl) ControlURL() string { return "https://control.example.test" }

func (c separatedHTTPControl) ReadPublisherVisitorPolicy(ctx context.Context, request controlv1.PublisherVisitorPolicyRequest, token string) (controlv1.VisitorPolicyUpdate, error) {
	if request.Resource.Kind != "service" || request.Resource.Id != c.service || request.RunId != c.run || request.RunNumber != 1 {
		return controlv1.VisitorPolicyUpdate{}, ErrServiceAdmission
	}
	update, err := c.policy.ReadPublisherVisitorPolicy(ctx, request, token)
	update.Policy.Hostname, update.Policy.Anonymous = "route.example", true
	update.VisitorSourceKey = nil
	return update, err
}

func (c separatedHTTPControl) AuthorizeServiceHTTPVisitor(ctx context.Context, service, run string, token credentials.ServiceRunToken, request controlv1.AuthorizeServiceHTTPVisitorRequest) (controlv1.ServiceClientCertificateDecision, error) {
	if service != c.service || run != c.run || token != "run-secret" || request.RunNumber != 1 || request.DestinationPort != 443 {
		return controlv1.ServiceClientCertificateDecision{}, ErrServiceAdmission
	}
	// the HTTP frontend must wait until ingress has admitted this exact visitor.
	select {
	case visitor := <-c.admitted:
		if visitor != request.VisitorConnectionId {
			return controlv1.ServiceClientCertificateDecision{}, ErrServiceAdmission
		}
	case <-ctx.Done():
		return controlv1.ServiceClientCertificateDecision{}, ctx.Err()
	}
	c.decisions <- request
	return controlv1.ServiceClientCertificateDecision{Allowed: true, Admitted: true, ValidUntil: time.Now().Add(time.Minute)}, nil
}

func TestSeparatedHTTPIPFilterAndReadinessProof(t *testing.T) {
	var transport *serviceTransportFixture
	var opens atomic.Int32
	config := serviceIngressConfig(t, func(ctx context.Context, header tunnelv1.ServiceForwardingHeader) (net.Conn, error) {
		opens.Add(1)
		return transport.open(ctx, header)
	})
	control := config.Control.(*httpsServiceControl)
	control.sources = netip.MustParsePrefix("203.0.113.0/24")
	control.anonymous = true
	relay := control.relays[0]
	ref := tunnelv1.ServicePublisherConnectionRef{
		ServiceID: control.service, ServiceRunID: control.run, RunNumber: 1,
		PublisherConnectionID: relay.PublisherConnectionId, ConnectionSlot: uint8(relay.ConnectionSlot),
		ConnectionAssignmentRevision: uint64(relay.ConnectionAssignmentRevision), RelayServiceID: relay.RelayServiceId,
	}
	transport = newServiceTransportFixture(t, ref, relay)
	control.relays[0] = transport.relay
	admitted := make(chan string, 2)
	config.AuditSink = auditSinkFunc(func(event serviceaudit.Observation) bool {
		if event.EventType == "connection.open" && event.Outcome == "allowed" {
			admitted <- event.VisitorConnectionID
		}
		return true
	})
	httpControl := separatedHTTPControl{
		policy:  &visitorfixture.PolicyClient{Key: ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))},
		service: control.service, run: control.run, admitted: admitted,
		decisions: make(chan controlv1.AuthorizeServiceHTTPVisitorRequest, 2),
	}
	subject := visitorscope.Scope{Kind: visitorscope.Service, ID: control.service}
	proof, err := httpaccess.NewReadinessProof(httpaccess.ReadinessRun{Subject: subject, ID: control.run, Number: 1, Hostname: "route.example"}, "/health")
	if err != nil {
		t.Fatal(err)
	}
	frontend, closeHTTP, err := publisherservice.PrepareHTTP(t.Context(), publisherservice.HTTP{
		Control: httpControl, Subject: subject, RunID: control.run, Number: 1, Token: "run-secret",
		Hostname: "route.example", Port: 443, ReadinessProof: proof,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeHTTP)
	var applications, probes atomic.Int32
	target := servicestream.HTTPTarget{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(httpstream.ReadinessProbeHeader) != "" {
			t.Error("readiness secret reached application")
		}
		if httpstream.IsReadinessProbe(r) {
			probes.Add(1)
		} else {
			applications.Add(1)
		}
		w.WriteHeader(http.StatusNoContent)
	})}
	certificate := testCertificate(t, "route.example")
	publisher := ingressWorker(t, func() { _ = transport.publisher.Close() }, func() error {
		for range 2 {
			incoming, err := transport.publisher.AcceptServiceForwardingStream(ingressContext(t))
			if err != nil {
				return err
			}
			if err := func() error {
				stream := incoming.Stream()
				defer stream.Close()
				header := incoming.Header
				if header.Validate() != nil || tunnel.ServiceForwardingRef(header) != ref || header.PublicService == nil ||
					header.PublicService.DestinationPort != 443 || !control.sources.Contains(netip.MustParseAddr(header.SourceIP)) {
					return errors.New("HTTP stream changed the service, run, or trusted source")
				}
				if err := incoming.Accept(); err != nil {
					return err
				}
				if err := stream.SetDeadline(time.Now().Add(fixtureTimeout)); err != nil {
					return err
				}
				metadata, replay, err := proxyproto.Decode(stream)
				if err != nil {
					return err
				}
				if metadata.Source.Addr().String() != header.SourceIP || metadata.Destination != netip.MustParseAddrPort("203.0.113.10:443") {
					return errors.New("HTTP stream lost trusted PROXY metadata")
				}
				secured := tls.Server(&testReaderConn{Conn: stream, reader: replay}, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13})
				defer secured.Close()
				connectionHTTP := frontend
				connectionHTTP.Header = header
				return connectionHTTP.Forward(t.Context(), secured, target)
			}(); err != nil {
				return err
			}
		}
		return nil
	})
	s, address := startIngress(t, config)
	blocked := ingressClient(t, address, "route.example", "198.51.100.1:40001")
	if err := blocked.Handshake(); err == nil {
		t.Fatal("source outside IP filter completed visitor TLS")
	}
	_ = blocked.Close()
	if opens.Load() != 0 {
		t.Fatal("source rejection opened a relay stream")
	}
	if claim := ingressAwait(t, control.claims); claim.ObservedSourceIp != "198.51.100.1" {
		t.Fatal("source rejection did not use the trusted PROXY address", claim)
	}
	for _, test := range []struct {
		source, proof string
		want          int
	}{{"203.0.113.1:40002", "", 204}, {"203.0.113.2:40003", proof.HeaderValue(), 204}} {
		c := ingressClient(t, address, "route.example", test.source)
		if err := c.Handshake(); err != nil {
			t.Fatal(err)
		}
		_, err := fmt.Fprintf(c, "GET /health HTTP/1.1\r\nHost: route.example\r\nConnection: close\r\n%s\r\n", func() string {
			if test.proof != "" {
				return httpstream.ReadinessProbeHeader + ": " + test.proof + "\r\n"
			}
			return ""
		}())
		if err != nil {
			t.Fatal(err)
		}
		response, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		_ = c.Close()
		if response.StatusCode != test.want {
			t.Fatalf("source %s status %d; want %d", test.source, response.StatusCode, test.want)
		}
		claim := ingressAwait(t, control.claims)
		decision := ingressAwait(t, httpControl.decisions)
		if decision.VisitorConnectionId != claim.VisitorConnectionId || decision.SourceIp != netip.MustParseAddrPort(test.source).Addr().String() {
			t.Fatal("HTTP authorization lost the admitted source or visitor identity", decision, claim)
		}
		transfer := ingressAwait(t, transport.transfers)
		if transfer.LeftToRight <= 0 || transfer.RightToLeft <= 0 || !serviceHTTPStreamClosed(transfer.err) {
			t.Fatal("HTTP relay lost bytes or failed before expected stream closure", transfer)
		}
	}
	if err := ingressAwait(t, publisher); err != nil {
		t.Fatal(err)
	}
	if applications.Load() != 1 || probes.Load() != 1 || opens.Load() != 2 {
		t.Fatal("readiness or source filtering changed application delivery", applications.Load(), probes.Load(), opens.Load())
	}
	s.active.Wait()
	if !publicServiceCapacityReleased(s) {
		t.Fatal("HTTP service retained visitor capacity")
	}
}

func serviceHTTPStreamClosed(err error) bool {
	if err == nil {
		return true
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		children := joined.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !serviceHTTPStreamClosed(child) {
				return false
			}
		}
		return true
	}
	if wrapped := errors.Unwrap(err); wrapped != nil {
		return serviceHTTPStreamClosed(wrapped)
	}
	return err == io.ErrUnexpectedEOF || err == yamux.ErrStreamReset || err == net.ErrClosed
}
