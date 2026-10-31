package publisher

import (
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestPublicCapacityRetainsSidebandAuthorization(t *testing.T) {
	for _, accepted := range []bool{false, true} {
		name := "denied"
		if accepted {
			name = "accepted"
		}
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int32
			policy, _, token := httpPermissionScopeFixture(t, visitorscope.Scope{Kind: visitorscope.PublicURL, ID: certificateTestPublicURLID}, "route.example", 443, false)
			f := newPublicCapacityFixture(t, 1, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(204) }), func(c *PublicURLServerConfig) {
				c.AccessMode, c.VisitorPolicy = "restricted", policy
			})
			entered, ack := make(chan struct{}), make(chan struct{})
			release := sync.OnceFunc(func() { close(ack) })
			defer release()
			ctx, cancel := context.WithCancel(f.ctx)
			done := make(chan error, 1)
			go func() {
				done <- f.relays[0].ServeAdmissions(ctx, tunnelv1.PublisherAdmissionStream, func(ctx context.Context, h tunnelv1.AdmissionHeader) tunnelv1.AdmissionResult {
					if h.PublisherConnectionID != f.refs[0].PublisherConnectionID || h.RelayServiceID != f.refs[0].RelayServiceID || h.PublishRunID != f.refs[0].PublishRunID {
						t.Error("sideband identity changed")
					}
					close(entered)
					select {
					case <-ack:
					case <-ctx.Done():
					}
					if !accepted {
						return tunnelv1.AdmissionResult{Type: tunnelv1.StreamRejected, Code: tunnelv1.CapacityExceeded}
					}
					return tunnelv1.AdmissionResult{Type: tunnelv1.StreamAccepted}
				})
			}()
			t.Cleanup(func() { release(); cancel(); _ = f.relays[0].Close(); _ = awaitPublisherTest(t, done) })
			stream, err := f.open(0, true)
			if err != nil {
				t.Fatal(err)
			}
			requested := make(chan error, 1)
			go func() {
				response, err := f.request(stream, "/", token.Reveal())
				if err == nil {
					_, err = io.Copy(io.Discard, response.Body)
					_ = response.Body.Close()
				}
				requested <- err
				close(requested)
			}()
			t.Cleanup(func() { release(); _ = stream.Close(); _ = awaitPublisherTest(t, requested) })
			awaitPublisherTest(t, entered)
			f.wait(0, 1)
			if calls.Load() != 0 {
				t.Fatal("target work preceded sideband acknowledgement")
			}
			// drain rejects pending setup but retains this already committed slot.
			f.route.stopAdmissions()
			release()
			err = awaitPublisherTest(t, requested)
			f.wait(0, 0)
			want := int32(0)
			if accepted {
				want = 1
				if err != nil {
					t.Fatal("drain interrupted admitted promotion", err)
				}
			}
			if calls.Load() != want {
				t.Fatal("sideband denial bypassed or admitted socket evicted", calls.Load())
			}
		})
	}
}

func TestPublicCapacityPendingDeadlineRetainsPermitUntilRetirement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		route, err := newTestPublicURLServer(t, PublicURLServerConfig{Hostname: "route.example", StreamCapacity: 1, Handler: http.NotFoundHandler()})
		if err != nil {
			t.Fatal(err)
		}
		defer route.Close()
		live := &livePublisherSession{ctx: ctx, ref: tunnelv1.PublisherConnectionRef{RelayServiceID: "relay-a"}}
		route.sessions[0] = live
		connection, peer := net.Pipe()
		defer peer.Close()
		a, code := route.reservePublicSetup(live, connection)
		if code != "" {
			t.Fatal(code)
		}
		defer a.retire()
		header, metadata := sourceMetadataFixture(t, route)
		if err := a.authenticateSource(header, metadata); err != nil {
			t.Fatal(err)
		}
		time.Sleep(visitorPromotionTimeout)
		<-a.connection.done
		if err := a.commit(); err == nil {
			t.Fatal("expired setup committed authorization")
		}
		if route.pendingStreams != 1 || route.authorizedStreams != 0 || route.pendingSources[a.source] != 1 {
			t.Fatal("deadline released a permit before worker retirement")
		}
		a.retire()
		if route.pendingStreams != 0 || len(route.pendingRelays) != 0 || len(route.pendingSources) != 0 {
			t.Fatal("retired setup retained capacity")
		}
	})
}

func TestPublicCapacityRejectedPromotionKeepsOriginalDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		route, err := newTestPublicURLServer(t, PublicURLServerConfig{Hostname: "route.example", Handler: http.NotFoundHandler()})
		if err != nil {
			t.Fatal(err)
		}
		defer route.Close()
		var calls int
		v := &visitorSession{promote: func(context.Context, Visitor) error {
			calls++
			return &tunnel.ProtocolError{Code: tunnelv1.CapacityExceeded}
		}}
		defer ownTestVisitorSession(t, route, v)()
		for range 2 {
			if err := v.admit(t.Context()); err == nil {
				t.Fatal("rejected promotion admitted a request")
			}
		}
		if calls != 1 {
			t.Fatal("rejected sideband decision replayed", calls)
		}
		time.Sleep(visitorPromotionTimeout)
		<-v.capacity.connection.done
		if route.authorizedStreams != 1 {
			t.Fatal("setup deadline released capacity before joined retirement")
		}
		v.close()
		v.capacity.retire()
		if route.authorizedStreams != 0 {
			t.Fatal("closed rejected connection retained capacity")
		}
	})
}
