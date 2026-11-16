package ingress

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/ingress/clienthello"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func restorationMaximumClientHello() []byte {
	vector := func(value []byte) []byte {
		return append(binary.BigEndian.AppendUint16(nil, uint16(len(value))), value...)
	}
	name := append([]byte{0}, vector([]byte("route.example"))...)
	extensions := append([]byte{0, 0}, vector(vector(name))...)
	body := append([]byte{3, 3}, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0x13, 0x01, 1, 0)
	// four records contribute twenty bytes outside the handshake.
	padding := clienthello.MaxClientHelloBytes - 20 - 4 - len(body) - 2 - len(extensions) - 4
	extensions = append(extensions, 0, 21)
	extensions = append(extensions, vector(make([]byte, padding))...)
	body = append(body, vector(extensions)...)
	handshake := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	var records []byte
	for len(handshake) != 0 {
		size := min(len(handshake), 16<<10)
		records = append(records, 22, 3, 1)
		records = append(records, vector(handshake[:size])...)
		handshake = handshake[size:]
	}
	return records
}

func restorationForwardedTotals(metrics *testMetrics) (upload, download int64) {
	metrics.forwardedMu.Lock()
	defer metrics.forwardedMu.Unlock()
	return metrics.forwardedBytes["visitor_to_publisher"], metrics.forwardedBytes["publisher_to_visitor"]
}

func TestServiceOpeningRestorationTwoMaximumClientHellosAndExactMeters(t *testing.T) {
	fixture := newAdmissionTransportFixture(t)
	config, control, _ := serviceSelectionConfig(t, 1, true)
	control.runs[0].ServiceId, control.runs[0].ServiceRunId = fixture.header.ServiceID, fixture.header.ServiceRunID
	control.runs[0].RunNumber = int64(fixture.header.RunNumber)
	control.runs[0].ConnectedRelays = []ingressv1.ServiceRelay{fixture.relay}
	config.Forwarder = fixture.forwarder
	metrics := &testMetrics{visitorOutcomes: make(chan string, 2)}
	config.Metrics = metrics
	server, address := startIngress(t, config)
	hello := restorationMaximumClientHello()
	if len(hello) != clienthello.MaxClientHelloBytes {
		t.Fatal("fixture did not reach exact ClientHello wire limit", len(hello))
	}
	headers := make(chan tunnelv1.ServiceForwardingHeader, 2)
	publisher := ingressWorker(t, fixture.closePublisher, func() error {
		for range 2 {
			incoming, err := fixture.publisher.AcceptServiceForwardingStream(ingressContext(t))
			if err != nil {
				return err
			}
			if err := func() error {
				defer incoming.Stream().Close()
				if tunnel.ServiceForwardingRef(incoming.Header) != tunnel.ServiceForwardingRef(fixture.header) {
					return errors.New("maximum opening changed its selected run or assignment")
				}
				if err := incoming.Accept(); err != nil {
					return err
				}
				metadata, reader, err := proxyproto.Decode(incoming.Stream())
				if err != nil {
					return err
				}
				if metadata.Source != netip.MustParseAddrPort("192.0.2.4:42000") ||
					metadata.Destination != netip.MustParseAddrPort("203.0.113.10:443") || metadata.VisitorSourceProof == "" {
					return errors.New("maximum opening changed original socket metadata")
				}
				got, err := io.ReadAll(reader)
				if err != nil {
					return err
				}
				if !bytes.Equal(got, hello) {
					return fmt.Errorf("maximum ClientHello lost or duplicated bytes: got=%d want=%d", len(got), len(hello))
				}
				if err := incoming.RequestCapacity(ingressContext(t)); err != nil {
					return err
				}
				headers <- incoming.Header
				if _, err := incoming.Stream().Write([]byte("ok")); err != nil {
					return err
				}
				return incoming.CloseWrite(ingressContext(t))
			}(); err != nil {
				return err
			}
		}
		return nil
	})
	var previous string
	for index := range 2 {
		connection, err := net.DialTimeout("tcp", address, fixtureTimeout)
		if err != nil {
			t.Fatal(err)
		}
		ownIngressConn(t, connection)
		proxy, err := proxyproto.Encode(proxyproto.Header{Source: netip.MustParseAddrPort("192.0.2.4:42000"), Destination: netip.MustParseAddrPort("203.0.113.10:443")})
		if err != nil {
			t.Fatal(err)
		}
		if err := writeAll(connection, append(proxy, hello...)); err != nil {
			t.Fatal(err)
		}
		if err := connection.(*net.TCPConn).CloseWrite(); err != nil {
			t.Fatal(err)
		}
		response, err := io.ReadAll(connection)
		if err != nil || string(response) != "ok" {
			t.Fatalf("half-close response=%q error=%v", response, err)
		}
		if outcome := ingressAwait(t, metrics.visitorOutcomes); outcome != "forwarded" {
			t.Fatal("maximum opening did not finish cleanly", outcome)
		}
		header := ingressAwait(t, headers)
		if header.VisitorConnectionID == previous || header.PublicService == nil || header.PublicService.DestinationPort != 443 {
			t.Fatal("maximum openings lost per-visitor isolation", header)
		}
		previous = header.VisitorConnectionID
		upload, download := restorationForwardedTotals(metrics)
		if upload != int64((index+1)*len(hello)) || download != int64((index+1)*2) {
			t.Fatalf("cumulative upload=%d download=%d after visitor=%d", upload, download, index+1)
		}
		ingressAwait(t, fixture.released)
	}
	if err := ingressAwait(t, publisher); err != nil {
		t.Fatal(err)
	}
	server.active.Wait()
	if fixture.server.accepted.Load() != 1 || fixture.publisherServer.accepted.Load() != 1 ||
		metrics.visitorOpenSuccesses.Load() != 2 || metrics.visitorOpenFailures.Load() != 0 ||
		len(control.claims) != 0 || server.Load() != 0 || !publicServiceCapacityReleased(server) {
		t.Fatal("maximum openings reconnected, made native claims, or retained capacity")
	}
}

func TestServiceOpeningRestorationWarmStalledAssignmentKeepsSibling(t *testing.T) {
	material := newForwardingTestMaterial(t)
	warmed := make(chan struct{}, 1)
	stalled := make(chan *tunnel.IncomingServiceForwardingStream, 1)
	checkSibling := make(chan struct{})
	check := sync.OnceFunc(func() { close(checkSibling) })
	t.Cleanup(check)
	server := startForwardingTestServer(t, material, func(ctx context.Context, transport muxsession.Session) error {
		session, err := restorationAcceptIngress(ctx, transport)
		if err != nil {
			return err
		}
		defer session.Close()
		first, err := session.AcceptServiceForwardingStream(ctx)
		if err != nil {
			return err
		}
		defer first.Stream().Close()
		if err := first.Accept(); err != nil {
			return err
		}
		warmed <- struct{}{}
		second, err := session.AcceptServiceForwardingStream(ctx)
		if err != nil {
			return err
		}
		defer second.Stream().Close()
		stalled <- second
		select {
		case <-checkSibling:
			if _, err := first.Stream().Write([]byte("ok")); err != nil {
				return err
			}
		case <-ctx.Done():
			return nil
		}
		<-ctx.Done()
		return nil
	})
	forwarder := newTestForwarder(t, material)
	fallback := newServiceTLSRelay(t)
	var relay ingressv1.ServiceRelay
	config := serviceIngressConfig(t, func(ctx context.Context, header tunnelv1.ServiceForwardingHeader, reserve func(context.Context) error) (net.Conn, error) {
		return forwarder.OpenService(ctx, relay, header, reserve)
	}, fallback.open)
	control := config.Control.(*httpsServiceControl)
	relay = control.relays[0]
	relay.InternalRelayAddress, relay.TlsServerName = server.address(), material.serverName
	control.relays[0] = relay
	header := restorationPoolHeader(t, control.publicServiceControlFixture, config.CurrentLease(), relay)
	warm, err := forwarder.OpenService(ingressContext(t), relay, header, nil)
	if err != nil {
		t.Fatal(err)
	}
	ownIngressConn(t, warm)
	ingressAwait(t, warmed)
	target := restorationTarget(relay)
	session, _, err := forwarder.session(ingressContext(t), target)
	if err != nil {
		t.Fatal(err)
	}
	config.OpenTimeout = 2 * time.Second
	_, address := startIngress(t, config)
	client := ingressClient(t, address, "route.example", "192.0.2.4:42000")
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	if err := client.Handshake(); err != nil {
		t.Fatal("warm stalled assignment prevented fallback", err)
	}
	exchangePing(t, client)
	result := ingressAwait(t, fallback.result)
	request := ingressAwait(t, stalled)
	if result.err != nil || result.request != "ping" || fallback.opens.Load() != 1 ||
		request.Header.VisitorConnectionID != result.visitorConnectionID {
		t.Fatal("fallback changed visitor identity or delivered twice", result, request.Header)
	}
	_ = request.Stream().SetReadDeadline(time.Now())
	if count, _ := request.Stream().Read(make([]byte, 1)); count != 0 {
		t.Fatal("unaccepted stalled assignment received a visitor byte")
	}
	if session.Err() != nil || !forwarder.currentSession(target.key(), session) {
		t.Fatal("stalled visitor discarded its pooled session")
	}
	check()
	var response [2]byte
	_ = warm.SetReadDeadline(time.Now().Add(fixtureTimeout))
	if _, err := io.ReadFull(warm, response[:]); err != nil || string(response[:]) != "ok" {
		t.Fatal("warm sibling did not survive", string(response[:]), err)
	}
	if server.accepted.Load() != 1 {
		t.Fatal("stalled assignment replaced its real pooled session", server.accepted.Load())
	}
}

type restorationWriteFailureForwarder struct {
	*Forwarder
	cause error
	bytes int
}

func (f restorationWriteFailureForwarder) OpenService(ctx context.Context, relay ingressv1.ServiceRelay, header tunnelv1.ServiceForwardingHeader, reserve func(context.Context) error) (net.Conn, error) {
	connection, err := f.Forwarder.OpenService(ctx, relay, header, reserve)
	if err != nil {
		return nil, err
	}
	return &restorationWriteFailureConn{Conn: connection, cause: f.cause, bytes: f.bytes}, nil
}

type restorationWriteFailureConn struct {
	net.Conn
	cause  error
	bytes  int
	writes int
}

func (c *restorationWriteFailureConn) Write(value []byte) (int, error) {
	c.writes++
	if c.writes == 2 {
		n, err := c.Conn.Write(value[:min(c.bytes, len(value))])
		return n, errors.Join(c.cause, err)
	}
	return c.Conn.Write(value)
}

func TestServiceOpeningRestorationCommittedWriteFailureKeepsRealSession(t *testing.T) {
	material := newForwardingTestMaterial(t)
	received := make(chan []byte, 1)
	next := make(chan restorationPoolRequest, 1)
	server := startForwardingTestServer(t, material, func(ctx context.Context, transport muxsession.Session) error {
		session, err := restorationAcceptIngress(ctx, transport)
		if err != nil {
			return err
		}
		defer session.Close()
		failed, err := session.AcceptServiceForwardingStream(ctx)
		if err != nil {
			return err
		}
		if err := failed.Accept(); err != nil {
			return err
		}
		_, reader, err := proxyproto.Decode(failed.Stream())
		if err != nil {
			return err
		}
		payload, err := io.ReadAll(reader)
		_ = failed.Stream().Close()
		if err != nil {
			return err
		}
		received <- payload
		incoming, err := session.AcceptServiceForwardingStream(ctx)
		if err != nil {
			return err
		}
		defer incoming.Stream().Close()
		if err := incoming.Accept(); err != nil {
			return err
		}
		var ping [4]byte
		if _, err := io.ReadFull(incoming.Stream(), ping[:]); err != nil {
			return err
		}
		if _, err := incoming.Stream().Write([]byte("pong")); err != nil {
			return err
		}
		next <- restorationPoolRequest{incoming.Header, string(ping[:])}
		<-ctx.Done()
		return nil
	})
	forwarder := newTestForwarder(t, material)
	relay, header := restorationPoolTuple(t, server.address(), material.serverName)
	target := restorationTarget(relay)
	session, _, err := forwarder.session(ingressContext(t), target)
	if err != nil {
		t.Fatal(err)
	}
	cause := errors.New("accepted service stream write failed")
	p := &Server{config: Config{Forwarder: restorationWriteFailureForwarder{Forwarder: forwarder, cause: cause, bytes: 7}}, backends: make(map[net.Conn]struct{})}
	proxy, err := proxyproto.Encode(proxyproto.Header{Source: netip.MustParseAddrPort("192.0.2.4:42000"), Destination: netip.MustParseAddrPort("203.0.113.10:443")})
	if err != nil {
		t.Fatal(err)
	}
	initial := restorationMaximumClientHello()
	connection, err := p.openPrivateRelay(ingressContext(t), relay, header, proxy, initial, time.Now().Add(fixtureTimeout), nil)
	var opening *tunnel.OpeningError
	if connection != nil || !errors.Is(err, cause) || !errors.As(err, &opening) || !opening.Committed || opening.VisitorBytes != 7 {
		t.Fatal("accepted stream failure lost exact original error and byte commitment", err)
	}
	if got := ingressAwait(t, received); !bytes.Equal(got, initial[:7]) {
		t.Fatal("relay did not receive exactly the committed bytes", len(got))
	}
	if session.Err() != nil || !forwarder.currentSession(target.key(), session) {
		t.Fatal("visitor write failure evicted healthy borrowed session")
	}
	header.VisitorConnectionID = publicServiceTestID(t, "vc_")
	if err := restorationPoolExchange(ingressContext(t), forwarder, relay, header, "ping"); err != nil {
		t.Fatal("next visitor could not reuse session", err)
	}
	if got := ingressAwait(t, next); !restorationSameForwardingHeader(got.header, header) || got.payload != "ping" || server.accepted.Load() != 1 {
		t.Fatal("visitor failure changed next visitor or pooled session", got)
	}
}

func TestServiceOpeningRestorationExistingLastRelaySlotCanAuthorize(t *testing.T) {
	fixture := newAdmissionTransportFixture(t)
	var reserved atomic.Int32
	opened := make(chan net.Conn, 1)
	done := ingressWorker(t, fixture.closePublisher, func() error {
		connection, err := fixture.forwarder.OpenService(ingressContext(t), fixture.relay, fixture.header, func(context.Context) error {
			reserved.Add(1)
			return nil
		})
		if err == nil {
			opened <- connection
		}
		return err
	})
	incoming, err := fixture.publisher.AcceptServiceForwardingStream(ingressContext(t))
	if err != nil {
		t.Fatal(err)
	}
	defer incoming.Stream().Close()
	other := fixture.header
	other.VisitorConnectionID = publicServiceTestID(t, "vc_")
	connection, err := fixture.forwarder.OpenService(ingressContext(t), fixture.relay, other, nil)
	if connection != nil {
		_ = connection.Close()
		t.Fatal("full relay admitted a new stream")
	}
	assertAdmissionCode(t, err, tunnelv1.CapacityExceeded)
	if reserved.Load() != 0 {
		t.Fatal("unaccepted stream already authorized capacity")
	}
	if err := incoming.Accept(); err != nil {
		t.Fatal(err)
	}
	if err := ingressAwait(t, done); err != nil {
		t.Fatal("current last-slot stream could not acknowledge", err)
	}
	current := ingressAwait(t, opened)
	defer current.Close()
	if err := incoming.RequestCapacity(ingressContext(t)); err != nil {
		t.Fatal("existing stream could not authorize on a full relay", err)
	}
	if err := incoming.RequestCapacity(ingressContext(t)); err != nil || reserved.Load() != 1 {
		t.Fatal("same stream duplicated capacity reservation", err, reserved.Load())
	}
	if fixture.server.accepted.Load() != 1 {
		t.Fatal("full relay rejection changed authenticated session")
	}
}

func TestServiceOpeningRestorationClosedStreamCannotAuthorize(t *testing.T) {
	fixture := newAdmissionTransportFixture(t)
	var reserved atomic.Int32
	opened := make(chan net.Conn, 1)
	done := ingressWorker(t, fixture.closePublisher, func() error {
		connection, err := fixture.forwarder.OpenService(ingressContext(t), fixture.relay, fixture.header, func(context.Context) error {
			reserved.Add(1)
			return nil
		})
		if err == nil {
			opened <- connection
		}
		return err
	})
	incoming, err := fixture.publisher.AcceptServiceForwardingStream(ingressContext(t))
	if err != nil {
		t.Fatal(err)
	}
	defer incoming.Stream().Close()
	if err := incoming.Accept(); err != nil {
		t.Fatal(err)
	}
	if err := ingressAwait(t, done); err != nil {
		t.Fatal(err)
	}
	connection := ingressAwait(t, opened)
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	_ = incoming.Stream().Close()
	ingressAwait(t, fixture.released)
	for range 2 {
		err := incoming.RequestCapacity(ingressContext(t))
		var rejected *tunnel.ProtocolError
		if !errors.As(err, &rejected) || rejected.Code != tunnelv1.Unavailable {
			t.Fatal("closed visitor capacity request did not retain exact unavailable outcome", err)
		}
	}
	if reserved.Load() != 0 || fixture.server.accepted.Load() != 1 {
		t.Fatal("closed stream authorized capacity or replaced healthy session", reserved.Load())
	}
}
