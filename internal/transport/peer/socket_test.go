package peer

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/stun/v4"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// this fixture supplies mapping replies only. relay discovery policy and metrics
// stay with the relay owner; the socket test checks shared transport mechanics.
func serveSocketMappingFixture(t *testing.T, ctx context.Context, listener *muxsession.QUICListener) {
	t.Helper()
	ctx, cancel := context.WithCancel(ctx)
	packets := listener.NonQUICPackets(ctx)
	done := make(chan error, 1)
	go func() {
		var buffer [2048]byte
		for {
			n, remote, err := packets.ReadFrom(buffer[:])
			if err != nil {
				if ctx.Err() != nil {
					err = nil
				}
				done <- err
				return
			}
			request := &stun.Message{Raw: buffer[:n]}
			if err := request.Decode(); err != nil || request.Type != stun.BindingRequest {
				continue
			}
			address := remote.(*net.UDPAddr)
			response, err := stun.Build(stun.NewTransactionIDSetter(request.TransactionID), stun.BindingSuccess,
				&stun.XORMappedAddress{IP: address.IP, Port: address.Port})
			if err == nil {
				_, err = packets.WriteTo(response.Raw, remote)
			}
			if err != nil {
				done <- err
				return
			}
		}
	}()
	t.Cleanup(func() {
		cancel()
		_ = packets.Close()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
}

func TestPeerSocketSharesQUICSTUNAndICE(t *testing.T) {
	for _, address := range []string{"127.0.0.1:0", "[::1]:0"} {
		t.Run(address, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			serverTLS, clientTLS := peerTLS(t)
			clientTLS.NextProtos = []string{muxsession.ALPN}
			listener, err := muxsession.ListenQUIC(address, serverTLS, muxsession.QUICConfig{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			serveSocketMappingFixture(t, ctx, listener)
			makeSocket := func() *Socket {
				s, err := ListenSocket(ctx, "udp", address)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := s.Close(); err != nil {
						t.Error(err)
					}
				})
				return s
			}
			left, right := makeSocket(), makeSocket()
			client, err := left.DialQUIC(ctx, listener.Addr(), clientTLS, nil)
			if err != nil {
				t.Fatal(err)
			}
			server, err := listener.Accept(ctx)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.CloseWithError(0, ""); _ = server.Close() })
			roundTripQUIC := func() {
				t.Helper()
				stream, err := client.OpenStreamSync(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := stream.Write([]byte("quic")); err != nil {
					t.Fatal(err)
				}
				incoming, err := server.AcceptStream(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer incoming.Close()
				var data [4]byte
				if _, err := io.ReadFull(incoming, data[:]); err != nil || string(data[:]) != "quic" {
					t.Fatal("STUN/ICE interfered with QUIC", err)
				}
				stream.CancelRead(0)
				_ = stream.Close()
			}
			roundTripQUIC()
			url, err := stun.ParseURI("stun:" + listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			makeAgent := func(socket *Socket) (*ice.Agent, []ice.Candidate) {
				agent, err := socket.NewICE([]*stun.URI{url}, true)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = agent.Close() })
				var mu sync.Mutex
				var candidates []ice.Candidate
				complete := make(chan struct{})
				if err := agent.OnCandidate(func(c ice.Candidate) {
					mu.Lock()
					defer mu.Unlock()
					if c == nil {
						close(complete)
					} else {
						candidates = append(candidates, c)
					}
				}); err != nil {
					t.Fatal(err)
				}
				if err := agent.GatherCandidates(); err != nil {
					t.Fatal(err)
				}
				select {
				case <-complete:
				case <-ctx.Done():
					t.Fatal("shared-socket gathering failed", ctx.Err())
				}
				mu.Lock()
				defer mu.Unlock()
				found := false
				for _, c := range candidates {
					if c.Port() != socket.LocalAddr().(*net.UDPAddr).Port {
						t.Fatal("ICE opened another socket", c.Marshal())
					}
					if c.Type() == ice.CandidateTypeServerReflexive {
						found = true
					}
				}
				if !found {
					t.Fatal("STUN did not discover the shared socket mapping")
				}
				return agent, candidates
			}
			leftAgent, leftCandidates := makeAgent(left)
			rightAgent, rightCandidates := makeAgent(right)
			for _, c := range rightCandidates {
				if err := leftAgent.AddRemoteCandidate(c); err != nil {
					t.Fatal(err)
				}
			}
			for _, c := range leftCandidates {
				if err := rightAgent.AddRemoteCandidate(c); err != nil {
					t.Fatal(err)
				}
			}
			leftUfrag, leftPwd, err := leftAgent.GetLocalUserCredentials()
			if err != nil {
				t.Fatal(err)
			}
			rightUfrag, rightPwd, err := rightAgent.GetLocalUserCredentials()
			if err != nil {
				t.Fatal(err)
			}
			type result struct {
				conn *ice.Conn
				err  error
			}
			accepted := make(chan result, 1)
			go func() { conn, err := rightAgent.Accept(ctx, leftUfrag, leftPwd); accepted <- result{conn, err} }()
			leftConn, err := leftAgent.Dial(ctx, rightUfrag, rightPwd)
			if err != nil {
				t.Fatal(err)
			}
			other := <-accepted
			if other.err != nil {
				t.Fatal(other.err)
			}
			if leftConn.LocalAddr().(*net.UDPAddr).Port != client.LocalAddr().(*net.UDPAddr).Port {
				t.Fatal("direct ICE and relay QUIC use different UDP sockets")
			}
			carrier := ICECarrier{Conn: leftConn}
			otherCarrier := ICECarrier{Conn: other.conn}
			frame, err := (tunnelv1.PeerPacket{Kind: tunnelv1.PeerData, Sequence: 1, Path: Direct, Total: 3, Payload: []byte("abc")}).MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			if err := carrier.Send(ctx, frame); err != nil {
				t.Fatal(err)
			}
			got, err := otherCarrier.Receive(ctx)
			if err != nil || string(got) != string(frame) {
				t.Fatal("ICE did not preserve direct packet bytes", err)
			}
			roundTripQUIC()
			if err := leftAgent.Close(); err != nil {
				t.Fatal(err)
			}
			if err := rightAgent.Close(); err != nil {
				t.Fatal(err)
			}
			roundTripQUIC()
		})
	}
}
