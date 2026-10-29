package daemon

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"golang.org/x/net/websocket"
)

func TestIntegrationPublicForwardingConnectionLossDoesNotReplayHTTP2OrWebSocket(t *testing.T) {
	f := newSplitPublishFixture(t, "public-failure")
	var targetRequests [3]atomic.Int32
	var freshRequests atomic.Int32
	closed := make(chan int, 3)
	mux := http.NewServeMux()
	for index, path := range []string{"/first", "/second"} {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			targetRequests[index].Add(1)
			defer func() { closed <- index }()
			_, _ = io.WriteString(w, "initial\n")
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		})
	}
	mux.Handle("/websocket", websocket.Handler(func(connection *websocket.Conn) {
		targetRequests[2].Add(1)
		defer func() { closed <- 2 }()
		defer connection.Close()
		if err := websocket.Message.Send(connection, "initial"); err != nil {
			return
		}
		for {
			var message string
			if err := websocket.Message.Receive(connection, &message); err != nil {
				return
			}
			if err := websocket.Message.Send(connection, "echo:"+message); err != nil {
				return
			}
		}
	}))
	mux.HandleFunc("/fresh", func(w http.ResponseWriter, _ *http.Request) {
		freshRequests.Add(1)
		_, _ = io.WriteString(w, "surviving slot")
	})
	target := httptest.NewServer(mux)
	cleanupIntegrationHTTPServer(t, target, f.owner)
	quic, _ := disabledIntegrationConnector("public failure proof uses TLS/TCP publisher slots")
	_, tcp := f.connectors()
	tcpBase := tcp
	var mu sync.Mutex
	sessions := make(map[string]muxsession.Session)
	failed := make(map[string]bool)
	tcp = muxsession.ConnectorFunc(func(ctx context.Context, endpoint muxsession.Endpoint) (muxsession.Session, error) {
		mu.Lock()
		offline := failed[endpoint.Address]
		mu.Unlock()
		if offline {
			return nil, errors.New("fixture publisher carrier is unavailable")
		}
		session, err := tcpBase.Connect(ctx, endpoint)
		if err == nil {
			mu.Lock()
			sessions[endpoint.Address] = session
			mu.Unlock()
		}
		return session, err
	})
	publisher := f.startPublisher(t, target.URL, quic, tcp)
	ready := f.waitReady(t, publisher)
	defer func() {
		if t.Failed() {
			logIntegrationPublishRunAuthority(t, f.inspect, ready.PublicURLID, ready.PublishRunNumber, "public-connection-loss")
		}
	}()
	relays := [2]splitRelayFixture{f.relayA, f.relayB}
	before := [2]splitConnectionState{
		readSplitConnectionState(t, f.inspect, ready.PublicURLID, ready.PublishRunNumber, relays[0].config.RelayServiceID),
		readSplitConnectionState(t, f.inspect, ready.PublicURLID, ready.PublishRunNumber, relays[1].config.RelayServiceID),
	}
	streams := func(total int64) [2]int64 {
		t.Helper()
		var counts [2]int64
		waitForIntegrationCondition(t, 5*time.Second, func(ctx context.Context) (bool, error) {
			err := f.inspect.QueryRowContext(ctx, `SELECT
				COALESCE(sum(reported_streams) FILTER (WHERE relay_id=$1),0),
				COALESCE(sum(reported_streams) FILTER (WHERE relay_id=$2),0)
				FROM control.relay_leases WHERE NOT draining AND lease_expires_at>now()`,
				relays[0].config.RelayID, relays[1].config.RelayID).Scan(&counts[0], &counts[1])
			return err == nil && counts[0]+counts[1] == total, err
		})
		return counts
	}
	// readiness TLS probes must retire before stream counts identify this
	// test's exact carrier. each HTTP/2 connection is one relay visitor stream.
	streams(0)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	dial := func(protocols []string) *tls.Conn {
		t.Helper()
		connection, err := (&tls.Dialer{Config: &tls.Config{
			RootCAs: f.pebble.roots, ServerName: ready.Hostname, MinVersion: tls.VersionTLS13, NextProtos: protocols,
		}}).DialContext(ctx, "tcp", f.ingressConfig.IngressListen)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = connection.Close() })
		if err := connection.SetDeadline(deadline); err != nil {
			t.Fatal(err)
		}
		return connection.(*tls.Conn)
	}
	secured := dial([]string{"h2"})
	if secured.ConnectionState().NegotiatedProtocol != "h2" {
		t.Fatal("public visitor did not negotiate HTTP/2")
	}
	// ClientConn pins both requests to one visitor connection. it cannot
	// silently redial after the fault as an ordinary HTTP pool might.
	var used atomic.Bool
	h2Transport := &http.Transport{Protocols: new(http.Protocols), DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
		if !used.CompareAndSwap(false, true) {
			return nil, errors.New("fixture HTTP/2 connection cannot redial")
		}
		return secured, nil
	}}
	h2Transport.Protocols.SetHTTP2(true)
	h2, err := h2Transport.NewClientConn(ctx, "https", net.JoinHostPort(ready.Hostname, "443"))
	if err != nil {
		t.Fatal(err)
	}
	defer h2.Close()
	var responses [2]*bufio.Reader
	for index, path := range []string{"/first", "/second"} {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, ready.PublicURL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := h2.RoundTrip(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK || response.ProtoMajor != 2 {
			t.Fatalf("HTTP/2 response: %s %s", response.Proto, response.Status)
		}
		responses[index] = bufio.NewReader(response.Body)
		if line, err := responses[index].ReadString('\n'); err != nil || line != "initial\n" {
			t.Fatalf("initial HTTP/2 stream %d: %q, %v", index, line, err)
		}
	}
	h2Relay := 0
	if counts := streams(1); counts[1] == 1 {
		h2Relay = 1
	}
	config, err := websocket.NewConfig("wss://"+ready.Hostname+"/websocket", ready.PublicURL)
	if err != nil {
		t.Fatal(err)
	}
	ws, err := websocket.NewClient(config, dial(nil))
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	var message string
	if err := websocket.Message.Receive(ws, &message); err != nil || message != "initial" {
		t.Fatalf("initial WebSocket message: %q, %v", message, err)
	}
	wsRelay := h2Relay
	if counts := streams(2); counts[h2Relay] == 1 {
		wsRelay = 1 - h2Relay
	}
	closeCarrier := func(index int) {
		t.Helper()
		address := relays[index].config.RelayAddress
		mu.Lock()
		// keep this carrier unavailable during the fresh-connection assertion.
		// publisher reconnect is not evidence that the other slot survived.
		failed[address] = true
		session := sessions[address]
		mu.Unlock()
		if session == nil {
			t.Fatal("selected publisher session was not captured")
		}
		if err := session.Close(); err != nil {
			t.Fatal(err)
		}
	}
	faultAt := time.Now()
	closeCarrier(h2Relay)
	for index, response := range responses {
		remainder, err := io.ReadAll(response)
		t.Logf("HTTP/2 stream %d after selected publisher loss: elapsed=%s bytes=%d error=%v", index, time.Since(faultAt), len(remainder), err)
		if err == nil || len(remainder) != 0 {
			t.Fatalf("HTTP/2 stream %d survived or replayed after connection loss: bytes=%d error=%v", index, len(remainder), err)
		}
	}
	survivor := 1 - h2Relay
	waitForReadyPublisherConnections(t, f.inspect, ready.PublicURLID, ready.PublishRunNumber, 1)
	waitForIngressRoutingCurrent(t, f.inspect, 1)
	response, body, err := f.visitor.requestURLContext(ctx, http.MethodGet, ready.PublicURL+"/fresh", nil)
	if err != nil {
		t.Fatal("fresh visitor did not reach the surviving slot", err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "surviving slot" || freshRequests.Load() != 1 {
		t.Fatalf("fresh visitor: status=%d bytes=%d target_opens=%d", response.StatusCode, len(body), freshRequests.Load())
	}
	assertIntegrationPublicURLCertificate(t, response, ready.Hostname)
	if after := readSplitConnectionState(t, f.inspect, ready.PublicURLID, ready.PublishRunNumber, relays[survivor].config.RelayServiceID); after != before[survivor] {
		t.Fatalf("surviving publisher slot changed: before=%+v after=%+v", before[survivor], after)
	}
	assertPublishRunNumber(t, f.inspect, ready.PublicURLID, ready.PublishRunNumber)
	if wsRelay != h2Relay {
		if err := websocket.Message.Send(ws, "sibling-carrier-live"); err != nil {
			t.Fatal(err)
		}
		if err := websocket.Message.Receive(ws, &message); err != nil || message != "echo:sibling-carrier-live" {
			t.Fatalf("unrelated carrier loss interrupted WebSocket: %q, %v", message, err)
		}
		closeCarrier(wsRelay)
	}
	err = websocket.Message.Receive(ws, &message)
	t.Logf("WebSocket after selected publisher loss: elapsed=%s error=%v", time.Since(faultAt), err)
	if err == nil {
		t.Fatal("WebSocket survived publisher connection loss")
	}
	var stopped [3]bool
	for range 3 {
		select {
		case index := <-closed:
			if stopped[index] {
				t.Fatalf("target %d was reopened and stopped twice", index)
			}
			stopped[index] = true
		case <-ctx.Done():
			t.Fatal("connection loss retained target work", ctx.Err())
		}
	}
	for index := range targetRequests {
		if got := targetRequests[index].Load(); got != 1 {
			t.Fatalf("target %d opened %d times; committed requests must not replay", index, got)
		}
	}
	if !time.Now().Before(deadline) {
		t.Fatal("visitor deadline, not publisher connection loss, ended the proof")
	}
	select {
	case <-publisher.done:
		t.Fatalf("carrier failure stopped publisher: %v", publisher.result())
	default:
	}
	t.Logf("selected carrier loss closed committed HTTP/2 and WebSocket visitors without replay; a fresh visitor used the unchanged surviving publisher slot (HTTP/2 relay=%d WebSocket relay=%d)", h2Relay, wsRelay)
}
