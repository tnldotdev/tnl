package workercontrol

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/tailtransport"
	"github.com/tnldotdev/tnl/internal/worker"
	"github.com/tnldotdev/tnl/pkg/protocol/workerv1"
	"tailscale.com/types/key"
)

func TestRemoteOwnerMatchesLocalSemantics(t *testing.T) {
	token, verifier, err := credentials.NewWorkerToken()
	if err != nil {
		t.Fatal(err)
	}
	registry := newTestRegistry()
	hub, err := NewHub(HubConfig{Tokens: []credentials.WorkerVerifier{verifier}, Registry: registry})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(hub)
	defer server.Close()
	url := "wss" + strings.TrimPrefix(server.URL, "https")

	wrongHeader := make(http.Header)
	wrongHeader.Set("Authorization", "Bearer wrong")
	if connection, response, err := websocket.Dial(context.Background(), url, &websocket.DialOptions{
		HTTPClient: server.Client(), HTTPHeader: wrongHeader, Subprotocols: []string{"tnl-worker-v1"},
	}); err == nil || response == nil || response.StatusCode != http.StatusUnauthorized {
		if connection != nil {
			_ = connection.CloseNow()
		}
		t.Fatalf("wrong-token dial = %v, %#v", err, response)
	}

	local := &echoWorker{limit: 2}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	workerDone := make(chan error, 1)
	go func() {
		workerDone <- RunWorker(ctx, WorkerConfig{
			URL: url, Token: token, Worker: local, HTTPClient: server.Client(), DrainTime: 2 * time.Second,
		})
	}()
	var remote worker.RouteWorker
	select {
	case remote = <-registry.added:
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not register")
	}

	assignment := worker.Assignment{
		RouteRef: worker.RouteRef{RouteID: "route", RouteVersion: 1},
		Endpoint: tailtransport.TransportDescriptor{Version: 1, PublisherPublicKey: key.NewNode().Public().String(), RelayRegion: "test"},
		Key:      key.NewNode(),
	}
	backend, err := remote.Attach(context.Background(), assignment)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := backend.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := connection.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(connection)
	if err != nil {
		t.Fatal(err)
	}
	if string(response) != "goodbye: hello" {
		t.Fatalf("response = %q", response)
	}
	_ = connection.Close()
	if err := backend.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.Open(context.Background()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("open after drain error = %v", err)
	}

	if err := hub.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-workerDone:
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not drain")
	}
	if local.closed.Load() != 0 {
		t.Fatal("RunWorker closed its caller-owned worker")
	}
	if err := local.Close(); err != nil || local.closed.Load() != 1 {
		t.Fatalf("caller close = %v, count = %d", err, local.closed.Load())
	}
}

func TestSessionObservers(t *testing.T) {
	tests := []struct {
		name   string
		abrupt bool
	}{
		{name: "clean shutdown"},
		{name: "abnormal disconnect", abrupt: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			token, verifier, err := credentials.NewWorkerToken()
			if err != nil {
				t.Fatal(err)
			}
			established := make(chan SessionRole, 4)
			disconnected := make(chan struct {
				role   SessionRole
				reason DisconnectReason
			}, 4)
			onEstablished := func(role SessionRole) { established <- role }
			onDisconnected := func(role SessionRole, reason DisconnectReason) {
				disconnected <- struct {
					role   SessionRole
					reason DisconnectReason
				}{role: role, reason: reason}
			}
			registry := newTestRegistry()
			hub, err := NewHub(HubConfig{
				Tokens: []credentials.WorkerVerifier{verifier}, Registry: registry,
				OnSessionEstablished: onEstablished, OnSessionDisconnected: onDisconnected,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = hub.Shutdown(context.Background()) }()
			server := httptest.NewServer(hub)
			defer server.Close()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			workerDone := make(chan error, 1)
			go func() {
				workerDone <- RunWorker(ctx, WorkerConfig{
					URL: "ws" + strings.TrimPrefix(server.URL, "http"), Token: token,
					Worker: &echoWorker{limit: 1}, OnSessionEstablished: onEstablished,
					OnSessionDisconnected: onDisconnected,
				})
			}()
			select {
			case <-registry.added:
			case <-time.After(5 * time.Second):
				t.Fatal("worker did not establish")
			}
			roles := make(map[SessionRole]int)
			for range 2 {
				select {
				case role := <-established:
					roles[role]++
				case <-time.After(5 * time.Second):
					t.Fatal("missing establishment callback")
				}
			}
			if roles[RoleEdge] != 1 || roles[RoleWorker] != 1 {
				t.Fatalf("established roles = %v", roles)
			}

			if test.abrupt {
				hub.mu.Lock()
				var connection *websocket.Conn
				for current := range hub.connections {
					connection = current
					break
				}
				hub.mu.Unlock()
				if connection == nil {
					t.Fatal("hub did not track worker connection")
				}
				_ = connection.CloseNow()
			} else {
				cancel()
			}
			select {
			case err := <-workerDone:
				if !test.abrupt && err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("worker did not exit")
			}

			exits := make(map[SessionRole]int)
			for range 2 {
				select {
				case event := <-disconnected:
					if !validDisconnectReason(event.reason) {
						t.Errorf("%s disconnect reason = %q", event.role, event.reason)
					}
					if !test.abrupt && event.role == RoleWorker && event.reason != DisconnectShutdown {
						t.Errorf("worker disconnect reason = %q, want %q", event.reason, DisconnectShutdown)
					}
					exits[event.role]++
				case <-time.After(5 * time.Second):
					t.Fatal("missing disconnect callback")
				}
			}
			if exits[RoleEdge] != 1 || exits[RoleWorker] != 1 {
				t.Fatalf("disconnected roles = %v", exits)
			}
			select {
			case event := <-disconnected:
				t.Fatalf("extra disconnect callback = %#v", event)
			case <-time.After(20 * time.Millisecond):
			}
		})
	}
}

func validDisconnectReason(reason DisconnectReason) bool {
	switch reason {
	case DisconnectShutdown, DisconnectNetwork, DisconnectProtocol, DisconnectTimeout, DisconnectInternal:
		return true
	default:
		return false
	}
}

func TestRemoteOwnerDetachesLateAttachResponse(t *testing.T) {
	edge, remote := net.Pipe()
	worker := newRemoteWorker(nil, edge, 1)
	loopDone := make(chan error, 1)
	go func() { loopDone <- worker.readLoop() }()

	ctx, cancel := context.WithCancel(context.Background())
	requestDone := make(chan error, 1)
	ref := &workerv1.RouteRef{RouteID: "route", RouteVersion: 1}
	go func() {
		_, err := worker.request(ctx, workerv1.Message{
			Type: workerv1.AttachRoute, Route: ref,
			PublisherTransport: &tailtransport.TransportDescriptor{}, TailcatDialerPrivateKey: "private",
		})
		requestDone <- err
	}()
	if message, err := workerv1.ReadControl(remote); err != nil || message.Type != workerv1.AttachRoute {
		t.Fatalf("attach request = %#v, %v", message, err)
	}
	cancel()
	if err := <-requestDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("request error = %v", err)
	}
	if err := workerv1.WriteControl(remote, workerv1.Message{Type: workerv1.RouteReady, Route: ref}); err != nil {
		t.Fatal(err)
	}
	if message, err := workerv1.ReadControl(remote); err != nil || message.Type != workerv1.DetachRoute {
		t.Fatalf("late-response cleanup = %#v, %v", message, err)
	}
	if err := workerv1.WriteControl(remote, workerv1.Message{Type: workerv1.RouteDrained, Route: ref}); err != nil {
		t.Fatal(err)
	}
	_ = remote.Close()
	if err := <-loopDone; err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("read loop error = %v", err)
	}
}

type testRegistry struct {
	mu      sync.Mutex
	workers map[string]worker.RouteWorker
	added   chan worker.RouteWorker
}

func newTestRegistry() *testRegistry {
	return &testRegistry{workers: make(map[string]worker.RouteWorker), added: make(chan worker.RouteWorker, 1)}
}

func (r *testRegistry) AddWorker(id string, worker worker.RouteWorker) error {
	r.mu.Lock()
	r.workers[id] = worker
	r.mu.Unlock()
	r.added <- worker
	return nil
}

func (r *testRegistry) DrainWorker(ctx context.Context, id string) error {
	r.mu.Lock()
	worker := r.workers[id]
	r.mu.Unlock()
	if worker == nil {
		return nil
	}
	return worker.Drain(ctx)
}

func (r *testRegistry) RemoveWorker(id string) {
	r.mu.Lock()
	delete(r.workers, id)
	r.mu.Unlock()
}

type echoWorker struct {
	limit    int
	draining atomic.Bool
	closed   atomic.Int32
}

func (o *echoWorker) Attach(context.Context, worker.Assignment) (worker.WorkerRoute, error) {
	if o.draining.Load() {
		return nil, worker.ErrDraining
	}
	return new(echoRoute), nil
}

func (o *echoWorker) Capacity() worker.Capacity {
	return worker.Capacity{Limit: o.limit, Draining: o.draining.Load()}
}

func (o *echoWorker) Drain(context.Context) error {
	o.draining.Store(true)
	return nil
}

func (o *echoWorker) Close() error {
	o.closed.Add(1)
	return nil
}

type echoRoute struct {
	closed atomic.Bool
}

func (r *echoRoute) Open(context.Context) (net.Conn, error) {
	if r.closed.Load() {
		return nil, net.ErrClosed
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	server, err := listener.Accept()
	_ = listener.Close()
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	go func() {
		defer server.Close()
		request, _ := io.ReadAll(server)
		_, _ = server.Write([]byte("goodbye: " + string(request)))
		_ = server.(*net.TCPConn).CloseWrite()
	}()
	return client, nil
}

func (r *echoRoute) Drain(context.Context) error {
	r.closed.Store(true)
	return nil
}

func (r *echoRoute) Close() error {
	r.closed.Store(true)
	return nil
}
