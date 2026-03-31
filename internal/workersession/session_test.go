package workersession

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

	"github.com/0xcadams/tnl/internal/credentials"
	"github.com/0xcadams/tnl/internal/tailtransport"
	"github.com/0xcadams/tnl/internal/worker"
	"github.com/0xcadams/tnl/pkg/protocol/workerv1"
	"github.com/coder/websocket"
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

	local := &echoOwner{limit: 2}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	workerDone := make(chan error, 1)
	go func() {
		workerDone <- RunWorker(ctx, WorkerConfig{
			URL: url, Token: token, Owner: local, HTTPClient: server.Client(), DrainTime: 2 * time.Second,
		})
	}()
	var remote worker.RouteOwner
	select {
	case remote = <-registry.added:
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not register")
	}

	assignment := worker.Assignment{
		RouteRef: worker.RouteRef{RouteID: "route", Generation: 1},
		Endpoint: tailtransport.Endpoint{Version: 1, ServerPublicKey: key.NewNode().Public().String(), RelayProfile: "test"},
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

	hub.Close()
	select {
	case <-workerDone:
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not drain")
	}
}

func TestRemoteOwnerDetachesLateAttachResponse(t *testing.T) {
	edge, remote := net.Pipe()
	owner := newRemoteOwner(nil, edge, 1)
	loopDone := make(chan error, 1)
	go func() { loopDone <- owner.readLoop() }()

	ctx, cancel := context.WithCancel(context.Background())
	requestDone := make(chan error, 1)
	ref := &workerv1.RouteRef{RouteID: "route", Generation: 1}
	go func() {
		_, err := owner.request(ctx, workerv1.Message{
			Type: workerv1.AttachRoute, Route: ref,
			Endpoint: &tailtransport.Endpoint{}, ClientPrivateKey: "private",
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
	mu     sync.Mutex
	owners map[string]worker.RouteOwner
	added  chan worker.RouteOwner
}

func newTestRegistry() *testRegistry {
	return &testRegistry{owners: make(map[string]worker.RouteOwner), added: make(chan worker.RouteOwner, 1)}
}

func (r *testRegistry) AddOwner(id string, owner worker.RouteOwner) error {
	r.mu.Lock()
	r.owners[id] = owner
	r.mu.Unlock()
	r.added <- owner
	return nil
}

func (r *testRegistry) DrainOwner(ctx context.Context, id string) error {
	r.mu.Lock()
	owner := r.owners[id]
	r.mu.Unlock()
	if owner == nil {
		return nil
	}
	return owner.Drain(ctx)
}

func (r *testRegistry) RemoveOwner(id string) {
	r.mu.Lock()
	delete(r.owners, id)
	r.mu.Unlock()
}

type echoOwner struct {
	limit    int
	draining atomic.Bool
}

func (o *echoOwner) Attach(context.Context, worker.Assignment) (worker.OwnedRoute, error) {
	if o.draining.Load() {
		return nil, worker.ErrDraining
	}
	return new(echoRoute), nil
}

func (o *echoOwner) Capacity() worker.Capacity {
	return worker.Capacity{Limit: o.limit, Draining: o.draining.Load()}
}

func (o *echoOwner) Drain(context.Context) error {
	o.draining.Store(true)
	return nil
}

func (o *echoOwner) Close() error { return nil }

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
