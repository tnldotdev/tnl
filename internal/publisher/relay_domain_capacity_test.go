package publisher

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// this regression deliberately uses exactly the run's allocation capacity, not
// testPublicAllocations' larger allowance. the attacker has an observed ingress
// reservation, but never supplies a visitor permission or reaches the handler.
func TestPublicURLStreamCapacityRelayDomainIsolation(t *testing.T) {
	for _, capacity := range []int{1, 2, 4, 5} {
		for _, stage := range []string{"control", "metadata", "tls", "permission"} {
			t.Run(fmt.Sprintf("capacity=%d/%s", capacity, stage), func(t *testing.T) {
				var reached atomic.Int32
				release := make(chan struct{})
				unblock := sync.OnceFunc(func() { close(release) })
				defer unblock()
				fixture := newPublicCapacityFixture(t, capacity, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					reached.Add(1)
					if r.Header.Get(visitorTokenHeader) != "" {
						t.Error("visitor credential reached application handler")
					}
					if r.URL.Path == "/live" {
						_, _ = io.WriteString(w, "prefix")
						w.(http.Flusher).Flush()
						select {
						case <-release:
							_, _ = io.WriteString(w, "finished")
						case <-r.Context().Done():
						}
						return
					}
					_, _ = io.WriteString(w, "authorized")
				}))
				ctx, route := fixture.ctx, fixture.route
				open, secure, request, metadata := fixture.open, fixture.secure, fixture.request, fixture.metadata
				var live *http.Response
				existing := 0
				if capacity == 2 || capacity == 5 {
					existing = 1
					stream, err := open(1, 0, 1)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = stream.Close() })
					live, err = request(stream, "/live")
					if err != nil || live.StatusCode != http.StatusOK {
						t.Fatal("existing authorized visitor did not start", err)
					}
					prefix := make([]byte, len("prefix"))
					if _, err := io.ReadFull(live.Body, prefix); err != nil || string(prefix) != "prefix" {
						t.Fatal("existing authorized response did not stream", err)
					}
				}
				if stage != "control" {
					for slot := existing; slot < capacity; slot++ {
						attack, err := open(0, uint32(slot), 1)
						if err != nil {
							t.Fatal(err)
						}
						t.Cleanup(func() { _ = attack.Close() })
						if stage == "tls" {
							if _, err := attack.Write(metadata); err != nil {
								t.Fatal(err)
							}
						} else if stage == "permission" {
							if _, err := secure(attack); err != nil {
								t.Fatal("attacker did not reach unproven HTTP stage", err)
							}
						}
					}
					ticker := time.NewTicker(time.Millisecond)
					defer ticker.Stop()
					for {
						route.mu.Lock()
						held := len(route.streams)
						route.mu.Unlock()
						if held == capacity {
							break
						}
						select {
						case <-ctx.Done():
							t.Fatal("attacker did not establish full shared setup pressure")
						case <-ticker.C:
						}
					}
					if capacity-existing == 4 {
						extra, err := open(0, uint32(capacity-1), 9)
						if err != nil {
							t.Fatal(err)
						}
						_, err = extra.Read(make([]byte, 1))
						_ = extra.Close()
						var rejected *tunnel.ProtocolError
						if !errors.As(err, &rejected) || rejected.Code != tunnelv1.CapacityExceeded {
							t.Fatal("fifth setup borrowed capacity outside its relay domain", err)
						}
						spoofed, err := open(0, uint32(capacity-1), 9, 1)
						if err != nil {
							t.Fatal(err)
						}
						_, err = spoofed.Read(make([]byte, 1))
						_ = spoofed.Close()
						if !errors.As(err, &rejected) || rejected.Code != tunnelv1.StaleConnectionAssignment {
							t.Fatal("opening header selected the healthy domain", err)
						}
					}
				}
				// ingress has released the attacker's previous local connection and
				// issued a newer, correctly MACed use of the same bounded slot.
				// the relay still holds the old publisher setup, without permission.
				stream, err := open(1, uint32(capacity-1), 2)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = stream.Close() })
				response, requestErr := request(stream, "/healthy")
				if requestErr != nil {
					var denied *tunnel.ProtocolError
					if errors.As(requestErr, &denied) {
						t.Errorf("healthy signed visitor rejected under %s pressure at capacity %d: %s", stage, capacity, denied.Code)
					} else {
						t.Errorf("healthy signed visitor failed: %v", requestErr)
					}
				} else {
					body, err := io.ReadAll(response.Body)
					_ = response.Body.Close()
					if err != nil || response.StatusCode != http.StatusOK || string(body) != "authorized" {
						t.Errorf("healthy signed visitor response=%d %q err=%v", response.StatusCode, body, err)
					}
				}
				unblock()
				if live != nil {
					body, err := io.ReadAll(live.Body)
					_ = live.Body.Close()
					if err != nil || string(body) != "finished" {
						t.Error("attack evicted existing authorized visitor", err)
					}
				}
				want := int32(existing)
				if requestErr == nil {
					want++
				}
				if reached.Load() != want {
					t.Errorf("unproven setup reached target: got %d want %d", reached.Load(), want)
				}
			})
		}
	}
}
