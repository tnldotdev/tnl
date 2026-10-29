package publisher

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestPublicURLStreamCapacityOneLegUsesAllAuthorizedCapacityAndReturningLegCannotEvict(t *testing.T) {
	for _, capacity := range []int{1, 2} {
		t.Run(fmt.Sprint(capacity), func(t *testing.T) {
			release := make(chan struct{})
			unblock := sync.OnceFunc(func() { close(release) })
			defer unblock()
			var calls atomic.Int32
			f := newPublicCapacityFixture(t, capacity, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.URL.Path == "/hold" {
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
			_ = f.relays[0].Close()
			awaitPublisherTest(t, f.finished[0])
			var responses []*http.Response
			for slot := 0; slot < capacity; slot++ {
				stream, err := f.open(1, uint32(slot), 1)
				if err != nil {
					t.Fatal(err)
				}
				response, err := f.request(stream, "/hold")
				if err != nil || response.StatusCode != 200 {
					t.Fatal("surviving relay could not use all C", err)
				}
				prefix := make([]byte, 6)
				if _, err := io.ReadFull(response.Body, prefix); err != nil || string(prefix) != "prefix" {
					t.Fatal(err)
				}
				responses = append(responses, response)
			}
			f.wait(0, capacity)
			f.refs[0].PublisherConnectionID = "domain-a-returned"
			f.refs[0].ConnectionAssignmentRevision++
			f.connect(0)
			for _, index := range []int{0, 1} {
				extra, err := f.open(index, 0, uint64(index+2))
				if err != nil {
					t.Fatal(err)
				}
				_, err = extra.Read(make([]byte, 1))
				_ = extra.Close()
				var denied *tunnel.ProtocolError
				if !errors.As(err, &denied) || denied.Code != tunnelv1.Unauthenticated {
					t.Fatal("newer reservation preempted an authorized visitor", err)
				}
			}
			f.wait(0, capacity)
			unblock()
			for _, response := range responses {
				body, err := io.ReadAll(response.Body)
				_ = response.Body.Close()
				if err != nil || string(body) != "finished" {
					t.Fatal("returning relay evicted an authorized response", err)
				}
			}
			f.wait(0, 0)
			stream, err := f.open(0, 0, 4)
			if err != nil {
				t.Fatal(err)
			}
			response, err := f.request(stream, "/fresh")
			if err != nil {
				t.Fatal("returning relay could not use released capacity", err)
			}
			body, err := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if err != nil || response.StatusCode != 200 || string(body) != "authorized" {
				t.Fatal("fresh target response", err)
			}
			if calls.Load() != int32(capacity+1) {
				t.Fatal("overflow reached target or response was replayed", calls.Load())
			}
		})
	}
}

func TestPublicURLStreamCapacityPendingCancellationExpiryReplacementDrainAndCloseJoin(t *testing.T) {
	for _, action := range []string{"cancel", "policy expiry", "replacement", "drain", "close"} {
		t.Run(action, func(t *testing.T) {
			var calls atomic.Int32
			f := newPublicCapacityFixture(t, 4, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(204) }))
			var streams []muxsession.Stream
			for slot := range uint32(4) {
				stream, err := f.open(0, slot, 1)
				if err != nil {
					t.Fatal(err)
				}
				streams = append(streams, stream)
			}
			f.wait(4, 0)
			f.route.mu.Lock()
			var old []*publicVisitorAdmission
			for _, admission := range f.route.streams {
				old = append(old, admission)
			}
			f.route.mu.Unlock()
			switch action {
			case "cancel":
				for _, stream := range streams {
					_ = stream.Close()
				}
			case "policy expiry":
				now := time.Now()
				f.update.View.ControlTime = time.Time{}
				f.update.View.ObservedAt, f.update.View.ValidUntil = now, now.Add(100*time.Millisecond)
				if err := f.policy.Apply(f.policy.Begin(), f.update); err != nil {
					t.Fatal(err)
				}
			case "replacement":
				finished := f.finished[0]
				f.refs[0].PublisherConnectionID = "replacement-a"
				f.refs[0].ConnectionAssignmentRevision++
				f.connect(0)
				awaitPublisherTest(t, finished)
			case "drain":
				ctx, cancel := context.WithTimeout(f.ctx, time.Second)
				defer cancel()
				if err := f.route.Drain(ctx); err != nil {
					t.Fatal("drain did not join unproven workers", err)
				}
			case "close":
				if err := f.route.Close(); err != nil {
					t.Fatal(err)
				}
			}
			f.wait(0, 0)
			for _, admission := range old {
				select {
				case <-admission.done:
				case <-f.ctx.Done():
					t.Fatal("old setup worker did not join")
				}
			}
			if calls.Load() != 0 {
				t.Fatal("pending setup reached target")
			}
			if action == "cancel" || action == "replacement" {
				current, err := f.open(0, 0, 2)
				if err != nil {
					t.Fatal(err)
				}
				f.wait(1, 0)
				for _, admission := range old {
					admission.close()
					admission.close()
				}
				f.wait(1, 0)
				response, err := f.request(current, "/fresh")
				if err != nil {
					t.Fatal("old release damaged replacement", err)
				}
				_, _ = io.Copy(io.Discard, response.Body)
				_ = response.Body.Close()
				if response.StatusCode != 204 || calls.Load() != 1 {
					t.Fatal("replacement authorization failed")
				}
			}
		})
	}
}

func TestPublicURLStreamCapacityMalformedSetupNeverReachesTarget(t *testing.T) {
	for _, stage := range []string{"metadata", "tls", "request"} {
		t.Run(stage, func(t *testing.T) {
			var calls atomic.Int32
			f := newPublicCapacityFixture(t, 1, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(204) }))
			stream, err := f.open(0, 0, 1)
			if err != nil {
				t.Fatal(err)
			}
			switch stage {
			case "metadata":
				_, _ = stream.Write([]byte("not a PROXY header"))
			case "tls":
				_, _ = stream.Write(append(append([]byte(nil), f.metadata...), []byte("not a TLS record")...))
			case "request":
				client, err := f.secure(stream)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = fmt.Fprint(client, "GET / HTTP/1.1\r\nHost: unrelated.example\r\n\r\n")
				response, err := http.ReadResponse(bufio.NewReader(client), nil)
				if err != nil {
					t.Fatal(err)
				}
				_ = response.Body.Close()
			}
			_ = stream.Close()
			f.wait(0, 0)
			if calls.Load() != 0 {
				t.Fatal("invalid setup dialed target")
			}
			healthy, err := f.open(1, 0, 2)
			if err != nil {
				t.Fatal(err)
			}
			response, err := f.request(healthy, "/valid")
			if err != nil {
				t.Fatal("invalid setup retained capacity", err)
			}
			_ = response.Body.Close()
			if response.StatusCode != 204 || calls.Load() != 1 {
				t.Fatal("healthy request did not reach target")
			}
		})
	}
}
