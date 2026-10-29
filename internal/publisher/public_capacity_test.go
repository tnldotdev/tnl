package publisher

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestPublicCapacitySharedAcrossRelaysIndependentAcrossRuns(t *testing.T) {
	const capacity = 10
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	var reached, active atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		active.Add(1)
		defer active.Add(-1)
		_, _ = io.WriteString(w, "prefix")
		w.(http.Flusher).Flush()
		select {
		case <-release:
			_, _ = io.WriteString(w, "finished")
		case <-r.Context().Done():
		}
	})
	// two runs for the same URL own independent capacity, as group members do.
	first := newPublicCapacityFixture(t, capacity, handler)
	second := newPublicCapacityFixture(t, capacity, handler, func(c *PublicURLServerConfig) {
		c.PublishRunID, c.PublishRunNumber = "run-2", 2
	})
	var held []*http.Response
	for _, f := range []*publicCapacityFixture{first, second} {
		for n := range capacity {
			index := n % 2
			if f == second {
				// one surviving relay can use all of its run's capacity.
				index = 1
			}
			stream, err := f.open(index, false)
			if err != nil {
				t.Fatal(err)
			}
			response, err := f.request(stream, "/hold")
			if err != nil || response.StatusCode != http.StatusOK {
				t.Fatal("authorized capacity unavailable", err)
			}
			prefix := make([]byte, 6)
			if _, err := io.ReadFull(response.Body, prefix); err != nil || string(prefix) != "prefix" {
				t.Fatal("target did not stream", err)
			}
			held = append(held, response)
		}
		f.wait(0, capacity)
		for index := range 2 {
			stream, err := f.open(index, false)
			if err != nil {
				t.Fatal(err)
			}
			response, err := f.request(stream, "/overflow")
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if response.StatusCode != http.StatusServiceUnavailable {
				t.Fatal("relay multiplied run capacity", response.StatusCode)
			}
		}
	}
	var pending []net.Conn
	for range PendingSetupsPerRelay {
		stream, err := second.open(0, false)
		if err != nil {
			t.Fatal(err)
		}
		pending = append(pending, stream)
	}
	second.wait(PendingSetupsPerRelay, capacity)
	if active.Load() != 2*capacity || reached.Load() != 2*capacity {
		t.Fatalf("two cap-10 runs: active=%d reached=%d", active.Load(), reached.Load())
	}
	for _, stream := range pending {
		_ = stream.Close()
	}
	second.wait(0, capacity)
	unblock()
	for _, response := range held {
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil || string(body) != "finished" {
			t.Fatal("overflow evicted an admitted connection", err)
		}
	}
	first.wait(0, 0)
	second.wait(0, 0)
}

func TestPublicCapacityPendingRelayFairnessAndIdentity(t *testing.T) {
	for _, stage := range []string{"metadata", "tls", "http"} {
		t.Run(stage, func(t *testing.T) {
			var calls atomic.Int32
			f := newPublicCapacityFixture(t, 1, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(204) }))
			for range PendingSetupsPerRelay {
				stream, err := f.open(0, false)
				if err != nil {
					t.Fatal(err)
				}
				if stage == "tls" {
					if _, err := stream.Write(f.metadataFor(stream)); err != nil {
						t.Fatal(err)
					}
				} else if stage == "http" {
					if _, err := f.secure(stream); err != nil {
						t.Fatal(err)
					}
				}
			}
			f.wait(PendingSetupsPerRelay, 0)
			for _, spoof := range []bool{false, true} {
				claimed, code := 0, tunnelv1.CapacityExceeded
				if spoof {
					claimed, code = 1, tunnelv1.StaleConnectionAssignment
				}
				_, err := f.open(0, false, claimed)
				var rejected *tunnel.ProtocolError
				if !errors.As(err, &rejected) || rejected.Code != code {
					t.Fatalf("spoof=%v: %v", spoof, err)
				}
			}
			stream, err := f.open(1, false)
			if err != nil {
				t.Fatal(err)
			}
			response, err := f.request(stream, "/healthy")
			if err != nil {
				t.Fatal("pending relay starved healthy relay", err)
			}
			_ = response.Body.Close()
			if response.StatusCode != 204 || calls.Load() != 1 {
				t.Fatal("unproven setup reached target or healthy visitor denied", calls.Load())
			}
		})
	}
}

func TestPublicCapacityDeniedSetupDoesNoTargetWork(t *testing.T) {
	var calls atomic.Int32
	f := newPublicCapacityFixture(t, 1, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(204) }), func(c *PublicURLServerConfig) {
		c.AccessMode = "restricted"
	})
	stream, err := f.open(0, true)
	if err != nil {
		t.Fatal(err)
	}
	response, err := f.request(stream, "/denied")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden || calls.Load() != 0 {
		t.Fatal("denied setup performed target work")
	}
	f.wait(0, 0)
}

func TestPublicCapacityHTTPConnectionChargedOnce(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(fmt.Sprint(h2), func(t *testing.T) {
			var checks atomic.Int32
			f := newPublicCapacityFixture(t, 1, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }), func(c *PublicURLServerConfig) {
				c.AdmitVisitor = func(context.Context, Visitor) error { checks.Add(1); return nil }
			})
			stream, err := f.open(0, false)
			if err != nil {
				t.Fatal(err)
			}
			protocols := []string{"http/1.1"}
			if h2 {
				protocols = []string{"h2"}
			}
			client, err := f.secure(stream, protocols...)
			if err != nil {
				t.Fatal(err)
			}
			var roundTrip func(*http.Request) (*http.Response, error)
			if h2 {
				transport := &http.Transport{
					DialTLSContext: func(context.Context, string, string) (net.Conn, error) { return client, nil },
					Protocols:      new(http.Protocols),
				}
				transport.Protocols.SetHTTP2(true)
				connection, err := transport.NewClientConn(f.ctx, "https", "route.example:443")
				if err != nil {
					t.Fatal(err)
				}
				defer connection.Close()
				roundTrip = connection.RoundTrip
			} else {
				roundTrip = func(r *http.Request) (*http.Response, error) { return capacityRequest(client, r.URL.Path, false) }
			}
			var workers sync.WaitGroup
			for n := range 8 {
				request := func() {
					r, _ := http.NewRequestWithContext(f.ctx, "GET", fmt.Sprintf("https://route.example/%d", n), nil)
					response, err := roundTrip(r)
					if err != nil {
						t.Error(err)
						return
					}
					_ = response.Body.Close()
					if response.StatusCode != 204 {
						t.Error("connection charged per request", response.StatusCode)
					}
				}
				if h2 {
					workers.Go(request)
				} else {
					request()
				}
			}
			workers.Wait()
			f.wait(0, 1)
			if checks.Load() != 8 {
				t.Fatal("connection capacity cached request authorization", checks.Load())
			}
			extra, err := f.open(1, false)
			if err != nil {
				t.Fatal(err)
			}
			response, err := f.request(extra, "/overflow")
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if response.StatusCode != 503 {
				t.Fatal("idle authorized connection did not retain capacity")
			}
			_ = client.Close()
			f.wait(0, 0)
		})
	}
}

func TestPublicCapacityRequiresOwnedVisitorSession(t *testing.T) {
	var calls int
	route, err := newTestPublicURLServer(t, PublicURLServerConfig{Hostname: "route.example", Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ })})
	if err != nil {
		t.Fatal(err)
	}
	defer route.Close()
	request := httptest.NewRequest("GET", "https://route.example/", nil)
	request.TLS = &tls.ConnectionState{ServerName: "route.example"}
	response := httptest.NewRecorder()
	route.http.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || calls != 0 {
		t.Fatal("request without a visitor owner reached the target", response.Code, calls)
	}
}
