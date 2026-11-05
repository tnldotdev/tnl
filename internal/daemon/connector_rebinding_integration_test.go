package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	quic "github.com/quic-go/quic-go"
	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type rebindingControl struct {
	connectorstream.Control
	selections atomic.Int32
}

func (c *rebindingControl) ResolveService(ctx context.Context, service string) (connectorstream.Run, error) {
	c.selections.Add(1)
	return c.Control.ResolveService(ctx, service)
}

// both transports bind real local sockets. no forwarding header or mock remote
// address supplies the relay's source evidence.
type rebindingTransport struct {
	fixture *privateSeparatedFixture
	tcp     bool
	source  atomic.Uint32
	mu      sync.Mutex
	opened  []muxsession.Session
}

func newRebindingTransport(t *testing.T, f *privateSeparatedFixture, tcp bool) *rebindingTransport {
	t.Helper()
	c := &rebindingTransport{fixture: f, tcp: tcp}
	c.source.Store(1)
	t.Cleanup(c.disconnect)
	return c
}

func (c *rebindingTransport) Connect(ctx context.Context, endpoint muxsession.Endpoint) (muxsession.Session, error) {
	local := net.IPv4(127, 0, 0, byte(c.source.Load()))
	var session muxsession.Session
	var err error
	if c.tcp {
		endpoint.Address = c.fixture.tcpAddresses[endpoint.Address]
		connector := muxsession.TLSYamuxConnector{TLSConfig: c.fixture.roots, Config: muxsession.TLSYamuxConfig{Dialer: &net.Dialer{LocalAddr: &net.TCPAddr{IP: local}}}}
		session, err = connector.Connect(ctx, endpoint)
	} else {
		endpoint.Address = c.fixture.quicAddresses[endpoint.Address]
		session, err = c.connectQUIC(ctx, endpoint, local)
	}
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.opened = append(c.opened, session)
	c.mu.Unlock()
	return session, nil
}

func (c *rebindingTransport) connectQUIC(ctx context.Context, endpoint muxsession.Endpoint, local net.IP) (muxsession.Session, error) {
	remote, err := net.ResolveUDPAddr("udp4", endpoint.Address)
	if err != nil {
		return nil, err
	}
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: local})
	if err != nil {
		return nil, err
	}
	transport := &quic.Transport{Conn: socket}
	trust := c.fixture.roots.Clone()
	trust.ServerName, trust.NextProtos = endpoint.ServerName, []string{muxsession.ALPN}
	connection, err := transport.Dial(ctx, remote, trust, &quic.Config{EnableDatagrams: true, MaxIncomingUniStreams: -1, KeepAlivePeriod: 30 * time.Second, InitialPacketSize: 1200})
	if err != nil {
		return nil, errors.Join(err, transport.Close(), socket.Close())
	}
	session, err := muxsession.AdoptQUIC(connection)
	if err != nil {
		return nil, errors.Join(err, transport.Close(), socket.Close())
	}
	owned := &rebindingQUICSession{Session: session, DatagramSession: session.(muxsession.DatagramSession), closed: make(chan struct{})}
	go func() {
		defer close(owned.closed)
		<-session.Done()
		_ = transport.Close()
		_ = socket.Close()
	}()
	return owned, nil
}

func (c *rebindingTransport) disconnect() {
	c.mu.Lock()
	opened := append([]muxsession.Session(nil), c.opened...)
	c.mu.Unlock()
	for _, session := range opened {
		_ = session.Close()
	}
}

type rebindingQUICSession struct {
	muxsession.Session
	muxsession.DatagramSession
	closed chan struct{}
}

func (s *rebindingQUICSession) Close() error {
	err := s.Session.Close()
	<-s.closed
	return err
}

type rebindingObservation struct {
	pairID, runID, relayID, relayServiceID, relayRunID string
	number, generation                                 int64
}

func readRebindingObservation(t *testing.T, f *privateSeparatedFixture, service string) rebindingObservation {
	t.Helper()
	var result rebindingObservation
	var encoded []byte
	err := f.inspect.QueryRowContext(t.Context(), `SELECT id,service_run_id,run_number,delivery_generation,slots
		FROM control.connector_peer_pairs WHERE service_id=$1`, service).Scan(&result.pairID, &result.runID, &result.number, &result.generation, &encoded)
	if err != nil {
		t.Fatal(err)
	}
	var relays [2]controlstate.ConnectorPeerPairRelay
	if err := json.Unmarshal(encoded, &relays); err != nil {
		t.Fatal(err)
	}
	result.relayID, result.relayServiceID, result.relayRunID = relays[0].RelayLease.RelayID, relays[0].RelayLease.RelayServiceID, relays[0].RelayLease.RelayRunID
	return result
}

func restartRebindingRelay(t *testing.T, f *privateSeparatedFixture, id string) {
	t.Helper()
	previous := f.relayProcesses[id]
	if previous == nil {
		t.Fatal("missing selected relay process", id)
	}
	if err := previous.stop(); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	settings := previous.settings
	var err error
	settings.internalListener, err = net.Listen("tcp", settings.internalAddress)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = settings.internalListener.Close() })
	settings.tcpListener, err = net.Listen("tcp", settings.relayAddress)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = settings.tcpListener.Close() })
	settings.udpPacket, err = net.ListenPacket("udp4", settings.udpListen)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = settings.udpPacket.Close() })
	f.runFixtureRelay(t, settings)
}

func TestIntegrationConnectorRebindingRetainsApplicationAndTarget(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	for _, standalone := range []bool{false, true} {
		for _, tcp := range []bool{false, true} {
			for _, fault := range []string{"publisher-connection", "both-connectors", "relay-process", "relay-assignment"} {
				if standalone && (fault == "relay-process" || fault == "relay-assignment") {
					continue
				}
				t.Run(fmt.Sprintf("standalone=%t/tcp=%t/%s", standalone, tcp, fault), func(t *testing.T) {
					qualifyConnectorRebinding(t, standalone, tcp, fault)
				})
			}
		}
	}
}

func TestIntegrationConnectorSourceRebindingRetainsApplicationAndTarget(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	if runtime.GOOS != "linux" {
		t.Skip("real multi-source loopback sockets require the disposable Linux fixture")
	}
	for _, standalone := range []bool{false, true} {
		for _, tcp := range []bool{false, true} {
			t.Run(fmt.Sprintf("standalone=%t/tcp=%t", standalone, tcp), func(t *testing.T) {
				qualifyConnectorRebinding(t, standalone, tcp, "source")
			})
		}
	}
}

type rebindingConnectionFixture struct {
	service   controlv1.Service
	listener  net.Listener
	stop      func()
	control   *rebindingControl
	transport *rebindingTransport
}

func startRebindingConnector(t *testing.T, f *privateSeparatedFixture, tcp bool, target string) rebindingConnectionFixture {
	t.Helper()
	key, err := opaqueid.New(opaqueid.IdempotencyPrefix)
	if err != nil {
		t.Fatal(err)
	}
	service, err := f.identity.routes.CreateService(t.Context(), f.identity.teamID, "rebind", key)
	if err != nil {
		t.Fatal(err)
	}
	startPrivateHTTPPublisher(t, f, service, target)
	person, err := f.identity.authority.IdentityContext(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	production, err := connectorstream.NewControl(f.identity.routes, f.identity.state, person.Identity.Id)
	if err != nil {
		t.Fatal(err)
	}
	control := &rebindingControl{Control: production}
	transport := newRebindingTransport(t, f, tcp)
	config := connectorstream.Config{Control: control, IdentityID: person.Identity.Id, RelayQUIC: transport, RelayTCP: privateDisabledConnector()}
	if tcp {
		config.RelayQUIC, config.RelayTCP = privateDisabledConnector(), transport
	}
	listener, stop := startRuntimeConnector(t, f, service, config)
	return rebindingConnectionFixture{service: service, listener: listener, stop: stop, control: control, transport: transport}
}

func qualifyConnectorRebinding(t *testing.T, standalone, tcp bool, fault string) {
	t.Helper()
	f := newServiceRuntimeFixture(t, standalone, nil)
	f.publisherTCPOnly = tcp
	if fault == "relay-assignment" {
		f.startFixtureRelay(t, "private-relay-spare")
	}
	claimed := make(chan *publisherservice.Claimed, 16)
	f.publisherConnections = claimed
	target := startPrivateEchoTarget(t)
	prepared := startRebindingConnector(t, f, tcp, target.address)
	defer prepared.stop()
	service, listener, control, transport := prepared.service, prepared.listener, prepared.control, prepared.transport
	connection, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	exchange := func(message string) {
		t.Helper()
		_ = connection.SetDeadline(time.Now().Add(20 * time.Second))
		if _, err := io.WriteString(connection, message); err != nil {
			t.Fatal("retained application write", err)
		}
		response := make([]byte, len(message))
		if _, err := io.ReadFull(connection, response); err != nil || string(response) != message {
			t.Fatal("retained application response", err)
		}
	}
	exchange("before-rebind\n")
	before := readRebindingObservation(t, f, service.Id)
	switch fault {
	case "source":
		transport.source.Store(2)
		transport.disconnect()
	case "publisher-connection":
		select {
		case current := <-claimed:
			if err := current.Close(); err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("publisher connection was not observed")
		}
	case "both-connectors":
		transport.disconnect()
	case "relay-process":
		restartRebindingRelay(t, f, before.relayID)
	case "relay-assignment":
		if err := f.relayProcesses[before.relayID].stop(); err != nil && !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
	default:
		t.Fatal("unknown fault", fault)
	}
	if fault != "both-connectors" {
		privateWait(t, 20*time.Second, func(ctx context.Context) (bool, error) {
			var generation int64
			err := f.inspect.QueryRowContext(ctx, `SELECT delivery_generation FROM control.connector_peer_pairs WHERE id=$1`, before.pairID).Scan(&generation)
			return generation > before.generation, err
		})
	}
	exchange("after-rebind\n")
	after := readRebindingObservation(t, f, service.Id)
	if after.pairID != before.pairID || after.runID != before.runID || after.number != before.number || control.selections.Load() != 1 {
		t.Fatal("recovery replaced the owner or selected another run", before.pairID, after.pairID, control.selections.Load())
	}
	if fault == "relay-process" && after.relayRunID == before.relayRunID {
		t.Fatal("relay restart did not replace the process identity")
	}
	if fault == "relay-assignment" && after.relayServiceID == before.relayServiceID {
		t.Fatal("draining did not replace the relay service")
	}
	if fault == "source" {
		// a second handoff must retain this same session, not just replace its
		// sockets once while leaving a one-use recovery path behind.
		transport.source.Store(1)
		transport.disconnect()
		privateWait(t, 20*time.Second, func(ctx context.Context) (bool, error) {
			var generation int64
			err := f.inspect.QueryRowContext(ctx, `SELECT delivery_generation FROM control.connector_peer_pairs WHERE id=$1`, before.pairID).Scan(&generation)
			return generation > after.generation, err
		})
		exchange("after-second-rebind\n")
	}
	target.mu.Lock()
	defer target.mu.Unlock()
	for _, message := range []string{"before-rebind\n", "after-rebind\n"} {
		if target.received[message] != 1 || target.receivedOn[message] != target.receivedOn["before-rebind\n"] {
			t.Fatal("recovery replayed bytes or reopened the target", message)
		}
	}
	if fault == "source" && (target.received["after-second-rebind\n"] != 1 || target.receivedOn["after-second-rebind\n"] != target.receivedOn["before-rebind\n"]) {
		t.Fatal("second source handoff replayed bytes or reopened the target")
	}
}

// opaque TCP carries this disposable PostgreSQL fixture unchanged. a real open
// transaction, backend identity, temporary table and local setting prove that
// recovery preserves application state rather than redialing the target.
func TestIntegrationConnectorRebindingRetainsPostgresTransaction(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	for _, tcp := range []bool{false, true} {
		t.Run(fmt.Sprintf("tcp=%t", tcp), func(t *testing.T) {
			f := newServiceRuntimeFixture(t, false, nil)
			f.publisherTCPOnly = tcp
			claimed := make(chan *publisherservice.Claimed, 16)
			f.publisherConnections = claimed
			database, err := pgx.ParseConfig(f.databaseURL)
			if err != nil {
				t.Fatal(err)
			}
			target := net.JoinHostPort(database.Host, strconv.Itoa(int(database.Port)))
			prepared := startRebindingConnector(t, f, tcp, target)
			defer prepared.stop()
			host, port, err := net.SplitHostPort(prepared.listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			number, err := strconv.ParseUint(port, 10, 16)
			if err != nil {
				t.Fatal(err)
			}
			database.Host, database.Port = host, uint16(number)
			database.TLSConfig, database.Fallbacks = nil, nil
			ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
			defer cancel()
			connection, err := pgx.ConnectConfig(ctx, database)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = connection.Close(context.Background()) }()
			tx, err := connection.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, "CREATE TEMP TABLE rebind_proof(value integer); INSERT INTO rebind_proof VALUES(1); SET LOCAL tnl.rebind_marker='retained'"); err != nil {
				t.Fatal(err)
			}
			var pidBefore int32
			var transactionBefore int64
			if err := tx.QueryRow(ctx, "SELECT pg_backend_pid(),txid_current()").Scan(&pidBefore, &transactionBefore); err != nil {
				t.Fatal(err)
			}
			before := readRebindingObservation(t, f, prepared.service.Id)
			select {
			case current := <-claimed:
				if err := current.Close(); err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal("publisher connection was not observed")
			}
			privateWait(t, 20*time.Second, func(ctx context.Context) (bool, error) {
				var generation int64
				err := f.inspect.QueryRowContext(ctx, `SELECT delivery_generation FROM control.connector_peer_pairs WHERE id=$1`, before.pairID).Scan(&generation)
				return generation > before.generation, err
			})
			var pidAfter int32
			var transactionAfter int64
			var count int
			var marker string
			if err := tx.QueryRow(ctx, "SELECT pg_backend_pid(),txid_current(),current_setting('tnl.rebind_marker'),count(*) FROM rebind_proof").Scan(&pidAfter, &transactionAfter, &marker, &count); err != nil {
				t.Fatal(err)
			}
			if pidBefore != pidAfter || transactionBefore != transactionAfter || marker != "retained" || count != 1 || prepared.control.selections.Load() != 1 {
				t.Fatal("recovery replaced or replayed the PostgreSQL transaction")
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}
