package publisher

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
	"golang.org/x/net/websocket"
)

func TestPublicURLHighPortHTTPAuthorityAcrossPublisherConnections(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(map[bool]string{false: "http1", true: "http2"}[h2], func(t *testing.T) {
			var forwarded atomic.Int32
			release := make(chan struct{})
			unblock := sync.OnceFunc(func() { close(release) })
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				forwarded.Add(1)
				if r.Host != "route.example:25443" || r.Header.Get("X-Forwarded-Host") != r.Host {
					t.Error("proxy lost the public HTTP port", r.Host, r.Header.Get("X-Forwarded-Host"))
				}
				_, _ = io.WriteString(w, "first\n")
				w.(http.Flusher).Flush()
				select {
				case <-release:
				case <-r.Context().Done():
					return
				}
				_, _ = io.WriteString(w, "second\n")
			}))
			t.Cleanup(target.Close)
			t.Cleanup(unblock)
			f := newPublicCapacityFixture(t, 4, nil, func(c *PublicURLServerConfig) {
				c.Port, c.Target = 25443, target.URL
			})
			if !f.route.visitorPolicyPrepared() {
				t.Fatal("a high-port public URL could not become ready")
			}
			transport := &http.Transport{ForceAttemptHTTP2: h2, DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
				stream, err := f.open(0, false)
				if err != nil {
					return nil, err
				}
				protocols := []string{"http/1.1"}
				if h2 {
					protocols = []string{"h2", "http/1.1"}
				}
				return f.secure(stream, protocols...)
			}}
			t.Cleanup(transport.CloseIdleConnections)
			client := &http.Client{Transport: transport}
			for _, authority := range []string{"route.example:25443", "route.example", "route.example:443", "route.example:25444"} {
				request, err := http.NewRequestWithContext(f.ctx, http.MethodGet, "https://route.example:25443/", nil)
				if err != nil {
					t.Fatal(err)
				}
				request.Host = authority
				response, err := client.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				if authority == "route.example:25443" {
					first := make([]byte, len("first\n"))
					if _, err := io.ReadFull(response.Body, first); err != nil || string(first) != "first\n" {
						_ = response.Body.Close()
						t.Fatal("high-port response did not stream before target completion", string(first), err)
					}
					unblock()
				}
				body, err := io.ReadAll(response.Body)
				_ = response.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				want := http.StatusBadRequest
				if h2 {
					want = http.StatusMisdirectedRequest
				}
				if authority == "route.example:25443" {
					want = http.StatusOK
					if string(body) != "second\n" {
						t.Fatal("high-port response was not forwarded", string(body))
					}
				}
				if response.StatusCode != want || h2 && response.ProtoMajor != 2 || !h2 && response.ProtoMajor != 1 {
					t.Fatal("public URL authority crossed a port boundary", authority, response.StatusCode, want, response.Proto)
				}
			}
			if forwarded.Load() != 1 {
				t.Fatal("a mismatched authority reached the target", forwarded.Load())
			}
		})
	}
}

func TestPublicURLHighPortWebSocketKeepsAuthorityAndBytes(t *testing.T) {
	finished := make(chan error, 1)
	target := httptest.NewServer(websocket.Handler(func(connection *websocket.Conn) {
		defer connection.Close()
		var message string
		err := websocket.Message.Receive(connection, &message)
		if err == nil {
			err = websocket.Message.Send(connection, "echo: "+message)
		}
		finished <- err
	}))
	t.Cleanup(target.Close)
	f := newPublicCapacityFixture(t, 2, nil, func(c *PublicURLServerConfig) {
		c.Port, c.Target = 25443, target.URL
	})
	stream, err := f.open(1, false)
	if err != nil {
		t.Fatal(err)
	}
	secured, err := f.secure(stream, "http/1.1")
	if err != nil {
		t.Fatal(err)
	}
	config, err := websocket.NewConfig("wss://route.example:25443/socket", "https://route.example:25443")
	if err != nil {
		t.Fatal(err)
	}
	connection, err := websocket.NewClient(config, secured)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	if err := websocket.Message.Send(connection, "retained application bytes"); err != nil {
		t.Fatal(err)
	}
	var response string
	if err := websocket.Message.Receive(connection, &response); err != nil || response != "echo: retained application bytes" {
		t.Fatal("high-port upgrade lost application bytes", response, err)
	}
	if err := awaitPublisherTest(t, finished); err != nil {
		t.Fatal(err)
	}
}

func TestPublicURLVisitorSourceRequiresTheApprovedDestinationPort(t *testing.T) {
	route, err := newTestPublicURLServer(t, PublicURLServerConfig{Hostname: "route.example", Port: 25443, Handler: http.NotFoundHandler()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = route.Close() })
	header := testPublicStreamHeader(route, tunnelv1.VisitorStreamHeader{})
	for _, port := range []uint16{443, 25444, 25443} {
		// even an authentic ingress proof cannot replace this run's endpoint.
		wire, err := encodeTestPublicMetadata(route, header, proxyproto.Header{
			Source:      netip.MustParseAddrPort("192.0.2.1:1234"),
			Destination: netip.AddrPortFrom(netip.MustParseAddr("203.0.113.1"), port),
		})
		if err != nil {
			t.Fatal(err)
		}
		metadata, _, err := proxyproto.Decode(bytes.NewReader(wire))
		if err != nil {
			t.Fatal(err)
		}
		err = route.authenticateVisitorSource(header, metadata)
		if port == 25443 {
			if err != nil {
				t.Fatal("approved high-port visitor proof was rejected", err)
			}
		} else if !errors.Is(err, visitortoken.ErrVisitorSource) || len(route.sourceHistory) != 0 {
			t.Fatal("another destination port supplied authority or consumed replay evidence", port, err)
		}
	}
}

func TestPublicURLReadyPolicyCannotReplaceTheRunEndpoint(t *testing.T) {
	policy, update, _ := visitorfixture.ScopePolicy(t, visitorscope.Scope{Kind: visitorscope.PublicURL, ID: certificateTestPublicURLID}, "route.example", 25443, true)
	route, err := newTestPublicURLServer(t, PublicURLServerConfig{Hostname: "route.example", Port: 25443, VisitorPolicy: policy, Handler: http.NotFoundHandler()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = route.Close() })
	if !route.visitorPolicyPrepared() {
		t.Fatal("matching high-port policy was not prepared")
	}
	update.View.Port = 25444
	if err := policy.Apply(policy.Begin(), update); err != nil {
		t.Fatal(err)
	}
	if route.visitorPolicyPrepared() {
		t.Fatal("policy renewal silently replaced the run's endpoint")
	}
}

func TestPublicURLServerRequiresAnExplicitNetworkPort(t *testing.T) {
	for _, port := range []int{-1, 0, 65536} {
		if _, err := NewPublicURLServer(PublicURLServerConfig{Hostname: "route.example", Port: port, Handler: http.NotFoundHandler()}); err == nil {
			t.Fatal("public URL server accepted an unspecified or invalid endpoint", port)
		}
	}
}
