package tailtransport

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tailscale/tailcat"
	"tailscale.com/derp/derpserver"
	"tailscale.com/net/stun/stuntest"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/nettype"
)

func TestLeaseTransport(t *testing.T) {
	region := runTestDERP(t)
	clientKey := key.NewNode()
	handlerResult := make(chan error, 1)
	server, err := NewServer(ServerConfig{
		AllowedClient: clientKey.Public(),
		RelayProfile:  "test",
		Profiles:      map[string]*tailcfg.DERPRegion{"test": region},
		Handler: func(conn net.Conn) {
			request, err := io.ReadAll(conn)
			if err == nil && string(request) != "hello" {
				err = errors.New("unexpected request")
			}
			if err == nil {
				_, err = conn.Write([]byte("goodbye"))
			}
			handlerResult <- err
		},
		Logf: logger.Discard,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { server.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	endpoint, err := server.Start(ctx)
	if err != nil {
		t.Fatalf("server Start: %v", err)
	}
	dialer, err := NewDialer(DialerConfig{
		Endpoint: endpoint,
		Profiles: map[string]*tailcfg.DERPRegion{"test": region},
		Key:      clientKey,
		Logf:     logger.Discard,
	})
	if err != nil {
		t.Fatalf("NewDialer: %v", err)
	}
	t.Cleanup(func() { dialer.Close() })
	if err := dialer.Start(ctx); err != nil {
		t.Fatalf("dialer Start: %v", err)
	}

	conn, err := dialer.Open(ctx)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	response, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(response) != "goodbye" {
		t.Fatalf("response = %q; want goodbye", response)
	}
	if err := <-handlerResult; err != nil {
		t.Fatalf("handler: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if err := dialer.Drain(ctx); err != nil {
		t.Fatalf("dialer Drain: %v", err)
	}
	if err := server.Drain(ctx); err != nil {
		t.Fatalf("server Drain: %v", err)
	}
	if conn, err := dialer.Open(ctx); conn != nil || !errors.Is(err, errDraining) {
		t.Fatalf("Open after Drain = %v, %v; want nil, errDraining", conn, err)
	}
	if err := dialer.Close(); err != nil {
		t.Fatalf("dialer Close: %v", err)
	}
	if conn, err := dialer.Open(ctx); conn != nil || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Open after Close = %v, %v; want nil, net.ErrClosed", conn, err)
	}
}

func TestLeaseTransportRejectsUnauthorizedClient(t *testing.T) {
	region := runTestDERP(t)
	server, err := NewServer(ServerConfig{
		AllowedClient: key.NewNode().Public(),
		RelayProfile:  "test",
		Profiles:      map[string]*tailcfg.DERPRegion{"test": region},
		Handler:       func(net.Conn) {},
		Logf:          logger.Discard,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { server.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	endpoint, err := server.Start(ctx)
	if err != nil {
		t.Fatalf("server Start: %v", err)
	}
	dialer, err := NewDialer(DialerConfig{
		Endpoint: endpoint,
		Profiles: map[string]*tailcfg.DERPRegion{"test": region},
		Key:      key.NewNode(),
		Logf:     logger.Discard,
	})
	if err != nil {
		t.Fatalf("NewDialer: %v", err)
	}
	t.Cleanup(func() { dialer.Close() })
	if err := dialer.Start(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("dialer Start = %v; want context deadline exceeded", err)
	}
}

func TestDialerCloseCancelsStart(t *testing.T) {
	dialer := newTestDialer(t)
	pingStarted := make(chan struct{})
	var closeCalls atomic.Int32
	dialer.newClient = func(*tailcat.Client) tailcatClient {
		return &fakeTailcatClient{
			ping: func(ctx context.Context) (tailcat.PingResult, error) {
				close(pingStarted)
				<-ctx.Done()
				return tailcat.PingResult{}, ctx.Err()
			},
			close: func() error {
				closeCalls.Add(1)
				return nil
			},
		}
	}

	started := make(chan error, 1)
	go func() { started <- dialer.Start(context.Background()) }()
	<-pingStarted
	if err := dialer.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := <-started; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Start = %v; want net.ErrClosed", err)
	}
	if got := closeCalls.Load(); got != 1 {
		t.Fatalf("client close calls = %d; want 1", got)
	}
}

func TestDialerCloseCancelsOpen(t *testing.T) {
	dialer := newTestDialer(t)
	dialStarted := make(chan struct{})
	dialCanceled := make(chan struct{})
	finishDial := make(chan struct{})
	var dialCalls atomic.Int32
	var dialPort atomic.Uint32
	dialer.newClient = func(*tailcat.Client) tailcatClient {
		return &fakeTailcatClient{
			ping: func(context.Context) (tailcat.PingResult, error) {
				return tailcat.PingResult{}, nil
			},
			dial: func(ctx context.Context, port uint16) (net.Conn, error) {
				dialPort.Store(uint32(port))
				dialCalls.Add(1)
				close(dialStarted)
				<-ctx.Done()
				close(dialCanceled)
				<-finishDial
				return nil, ctx.Err()
			},
		}
	}
	if err := dialer.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	type openResult struct {
		conn net.Conn
		err  error
	}
	opened := make(chan openResult, 1)
	go func() {
		conn, err := dialer.Open(context.Background())
		opened <- openResult{conn, err}
	}()
	<-dialStarted
	closed := make(chan error, 1)
	go func() { closed <- dialer.Close() }()
	<-dialCanceled
	select {
	case err := <-closed:
		t.Fatalf("Close returned before DialTCPPort completed: %v", err)
	default:
	}
	close(finishDial)
	if err := <-closed; err != nil {
		t.Fatalf("Close: %v", err)
	}
	result := <-opened
	if result.conn != nil || !errors.Is(result.err, net.ErrClosed) {
		t.Fatalf("Open = %v, %v; want nil, net.ErrClosed", result.conn, result.err)
	}
	if conn, err := dialer.Open(context.Background()); conn != nil || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Open after Close = %v, %v; want nil, net.ErrClosed", conn, err)
	}
	if got := dialCalls.Load(); got != 1 {
		t.Fatalf("dial calls = %d; want 1", got)
	}
	if got := dialPort.Load(); got != uint32(leaseTCPPort) {
		t.Fatalf("DialTCPPort port = %d; want %d", got, leaseTCPPort)
	}
}

func TestDialerStartLifecycle(t *testing.T) {
	dialer := newTestDialer(t)
	dialer.newClient = func(*tailcat.Client) tailcatClient { return &fakeTailcatClient{} }
	if err := dialer.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := dialer.Start(context.Background()); !errors.Is(err, errAlreadyStarted) {
		t.Fatalf("second Start = %v; want errAlreadyStarted", err)
	}
	if err := dialer.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	closed := newTestDialer(t)
	var factories atomic.Int32
	closed.newClient = func(*tailcat.Client) tailcatClient {
		factories.Add(1)
		return &fakeTailcatClient{}
	}
	if err := closed.Close(); err != nil {
		t.Fatalf("Close before Start: %v", err)
	}
	if err := closed.Start(context.Background()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Start after Close = %v; want net.ErrClosed", err)
	}
	if got := factories.Load(); got != 0 {
		t.Fatalf("client factories = %d; want 0", got)
	}
}

func TestServerSnapshotsProfileAndDrainsTCP(t *testing.T) {
	region := testRegion()
	server, err := NewServer(ServerConfig{
		AllowedClient: key.NewNode().Public(),
		RelayProfile:  "test",
		Profiles:      map[string]*tailcfg.DERPRegion{"test": region},
		Handler:       func(net.Conn) {},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	region.Nodes[0].HostName = "mutated.example.com"
	var drained atomic.Bool
	server.newServer = func(config *tailcat.Server) tailcatServer {
		if got := config.Region.Nodes[0].HostName; got != "derp.example.com" {
			t.Fatalf("server region = %q; want immutable snapshot", got)
		}
		if len(config.ServedTCPPorts) != 1 || config.ServedTCPPorts[0].First != leaseTCPPort || config.ServedTCPPorts[0].Last != leaseTCPPort {
			t.Fatalf("served ports = %+v; want only %d", config.ServedTCPPorts, leaseTCPPort)
		}
		if config.OnTCP(leaseTCPPort) == nil || config.OnTCP(leaseTCPPort+1) != nil {
			t.Fatal("OnTCP did not restrict traffic to the lease port")
		}
		return &fakeTailcatServer{drain: func(context.Context) error {
			drained.Store(true)
			return nil
		}}
	}
	if _, err := server.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := server.Drain(context.Background()); err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if !drained.Load() {
		t.Fatal("Drain did not call tailcat Server.DrainTCP")
	}
	if err := server.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestServerDrainTCPFollowsStreams(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := newTestServer(t)
		drainCalled := make(chan struct{})
		server.newServer = func(*tailcat.Server) tailcatServer {
			return &fakeTailcatServer{drain: func(context.Context) error {
				close(drainCalled)
				return nil
			}}
		}
		if _, err := server.Start(context.Background()); err != nil {
			t.Fatalf("Start: %v", err)
		}

		local, peer := net.Pipe()
		defer peer.Close()
		stream, err := server.streams.track(local)
		if err != nil {
			t.Fatalf("track: %v", err)
		}
		drained := make(chan error, 1)
		go func() { drained <- server.Drain(context.Background()) }()
		synctest.Wait()
		select {
		case <-drainCalled:
			t.Fatal("DrainTCP called before application streams closed")
		default:
		}

		if err := stream.Close(); err != nil {
			t.Fatalf("stream Close: %v", err)
		}
		if err := <-drained; err != nil {
			t.Fatalf("Drain: %v", err)
		}
		select {
		case <-drainCalled:
		default:
			t.Fatal("Drain did not call DrainTCP")
		}
		if err := server.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	})
}

func TestDialerSnapshotsProfile(t *testing.T) {
	region := testRegion()
	serverKey := key.NewNode().Public()
	dialer, err := NewDialer(DialerConfig{
		Endpoint: Endpoint{Version: descriptorVersion, ServerPublicKey: serverKey.String(), RelayProfile: "test"},
		Profiles: map[string]*tailcfg.DERPRegion{"test": region},
		Key:      key.NewNode(),
	})
	if err != nil {
		t.Fatalf("NewDialer: %v", err)
	}
	region.Nodes[0].HostName = "mutated.example.com"
	info, err := tailcat.ParseConnBlob(dialer.blob)
	if err != nil {
		t.Fatalf("ParseConnBlob: %v", err)
	}
	if got := info.Region[0].Nodes[0].HostName; got != "derp.example.com" {
		t.Fatalf("dialer region = %q; want immutable snapshot", got)
	}
}

func TestServerCloseWaitsForStart(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		server := newTestServer(t)
		startEntered := make(chan struct{})
		finishStart := make(chan struct{})
		var closeCalls atomic.Int32
		server.newServer = func(*tailcat.Server) tailcatServer {
			return &fakeTailcatServer{
				start: func() error {
					close(startEntered)
					<-finishStart
					return nil
				},
				close: func() error {
					closeCalls.Add(1)
					return nil
				},
			}
		}

		started := make(chan error, 1)
		go func() {
			_, err := server.Start(context.Background())
			started <- err
		}()
		<-startEntered
		closed := make(chan error, 1)
		go func() { closed <- server.Close() }()
		synctest.Wait()
		select {
		case err := <-closed:
			t.Fatalf("Close returned before Start completed: %v", err)
		default:
		}

		close(finishStart)
		if err := <-started; !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Start = %v; want net.ErrClosed", err)
		}
		if err := <-closed; err != nil {
			t.Fatalf("Close: %v", err)
		}
		if got := closeCalls.Load(); got != 1 {
			t.Fatalf("server close calls = %d; want 1", got)
		}
	})
}

func newTestDialer(t *testing.T) *Dialer {
	t.Helper()
	serverKey := key.NewNode().Public()
	dialer, err := NewDialer(DialerConfig{
		Endpoint: Endpoint{Version: descriptorVersion, ServerPublicKey: serverKey.String(), RelayProfile: "test"},
		Profiles: map[string]*tailcfg.DERPRegion{"test": testRegion()},
		Key:      key.NewNode(),
	})
	if err != nil {
		t.Fatalf("NewDialer: %v", err)
	}
	return dialer
}

func newTestServer(t *testing.T) *Server {
	t.Helper()
	server, err := NewServer(ServerConfig{
		AllowedClient: key.NewNode().Public(),
		RelayProfile:  "test",
		Profiles:      map[string]*tailcfg.DERPRegion{"test": testRegion()},
		Handler:       func(net.Conn) {},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return server
}

func testRegion() *tailcfg.DERPRegion {
	return &tailcfg.DERPRegion{
		RegionID:   1,
		RegionCode: "test",
		Nodes:      []*tailcfg.DERPNode{{RegionID: 1, HostName: "derp.example.com"}},
	}
}

type fakeTailcatClient struct {
	ping  func(context.Context) (tailcat.PingResult, error)
	dial  func(context.Context, uint16) (net.Conn, error)
	close func() error
}

func (c *fakeTailcatClient) Ping(ctx context.Context) (tailcat.PingResult, error) {
	if c.ping == nil {
		return tailcat.PingResult{}, nil
	}
	return c.ping(ctx)
}

func (c *fakeTailcatClient) DialTCPPort(ctx context.Context, port uint16) (net.Conn, error) {
	return c.dial(ctx, port)
}

func (c *fakeTailcatClient) Close() error {
	if c.close == nil {
		return nil
	}
	return c.close()
}

type fakeTailcatServer struct {
	start func() error
	drain func(context.Context) error
	close func() error
}

func (s *fakeTailcatServer) Start() error {
	if s.start == nil {
		return nil
	}
	return s.start()
}

func (s *fakeTailcatServer) DrainTCP(ctx context.Context) error {
	if s.drain == nil {
		return nil
	}
	return s.drain(ctx)
}

func (s *fakeTailcatServer) Close() error {
	if s.close == nil {
		return nil
	}
	return s.close()
}

func runTestDERP(t *testing.T) *tailcfg.DERPRegion {
	t.Helper()
	d := derpserver.New(key.NewNode(), logger.Discard)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	httpsrv := httptest.NewUnstartedServer(derpserver.Handler(d))
	httpsrv.Listener.Close()
	httpsrv.Listener = ln
	httpsrv.Config.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
	httpsrv.StartTLS()
	stunAddr, stunCleanup := stuntest.ServeWithPacketListener(t, nettype.Std{})
	t.Cleanup(func() {
		httpsrv.CloseClientConnections()
		httpsrv.Close()
		d.Close()
		stunCleanup()
	})
	return &tailcfg.DERPRegion{
		RegionID:   1,
		RegionCode: "test",
		Nodes: []*tailcfg.DERPNode{{
			Name:             "test",
			RegionID:         1,
			HostName:         "127.0.0.1",
			IPv4:             "127.0.0.1",
			IPv6:             "none",
			STUNPort:         stunAddr.Port,
			DERPPort:         ln.Addr().(*net.TCPAddr).Port,
			InsecureForTests: true,
			STUNTestIP:       "127.0.0.1",
		}},
	}
}
