package httpstream_test

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/applicationlimits"
	"github.com/tnldotdev/tnl/internal/transport/httpstream"
)

func TestRequestBodyIdleBoundsUnreadHTTP1Cleanup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		incoming, visitor := net.Pipe()
		defer visitor.Close()
		done := make(chan error, 1)
		go func() {
			done <- httpstream.ServeHandler(t.Context(), incoming, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusRequestEntityTooLarge)
			}), httpstream.Drain{}, 100*time.Millisecond)
		}()
		if _, err := io.WriteString(visitor, "POST / HTTP/1.1\r\nHost: service.example.test\r\nContent-Length: 2\r\n\r\na"); err != nil {
			t.Fatal(err)
		}
		response, err := http.ReadResponse(bufio.NewReader(visitor), &http.Request{Method: http.MethodPost})
		if err != nil || response.StatusCode != http.StatusRequestEntityTooLarge {
			t.Fatal("unread upload delayed the early final response", response, err)
		}
		response.Body.Close()
		if err := boundaryAwait(t, done); err != nil {
			t.Fatal("unread-body cleanup did not join within its idle bound", err)
		}
	})
}

func TestRequestBodyIdleCompletedUploadDoesNotLimitUpgrade(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		incoming, visitor := net.Pipe()
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan error, 1)
		go func() {
			done <- httpstream.ServeHandler(ctx, incoming, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if body, err := io.ReadAll(r.Body); err != nil || string(body) != "a" {
					t.Error("upgrade lost its completed upload", string(body), err)
					return
				}
				connection, buffered, err := http.NewResponseController(w).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				defer connection.Close()
				_, _ = buffered.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: test\r\n\r\n")
				_ = buffered.Flush()
				_, _ = io.Copy(connection, buffered)
			}), httpstream.Drain{}, 100*time.Millisecond)
		}()
		defer func() {
			cancel()
			_ = visitor.Close()
			if err := boundaryAwait(t, done); err != nil {
				t.Error("upgraded body owner did not join", err)
			}
		}()
		_, err := io.WriteString(visitor, "POST / HTTP/1.1\r\nHost: service.example.test\r\nConnection: Upgrade\r\nUpgrade: test\r\nContent-Length: 1\r\n\r\na")
		if err != nil {
			t.Fatal(err)
		}
		reader := bufio.NewReader(visitor)
		response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodPost})
		if err != nil || response.StatusCode != http.StatusSwitchingProtocols {
			t.Fatal("completed upload did not upgrade", response, err)
		}
		time.Sleep(time.Minute)
		if _, err := io.WriteString(visitor, "ping"); err != nil {
			t.Fatal("body timeout limited the upgrade lifetime", err)
		}
		echo := make([]byte, 4)
		if _, err := io.ReadFull(reader, echo); err != nil || string(echo) != "ping" {
			t.Fatal("long-lived upgrade did not return application bytes", string(echo), err)
		}
	})
}

func TestRequestBodyIdleProgressExceedsThirtySeconds(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("http2=%t", h2), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				progress := make(chan struct{})
				frontend, finished := deadlineFrontend(t, 0, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					for range 5 {
						if _, err := io.ReadFull(r.Body, make([]byte, 1)); err != nil {
							t.Error("progressing upload was interrupted", err)
							return
						}
						progress <- struct{}{}
					}
					if rest, err := io.ReadAll(r.Body); err != nil || len(rest) != 0 || r.Trailer.Get("X-Upload-Digest") != "complete" {
						t.Error("progressing upload lost EOF or trailers", string(rest), err, r.Trailer)
						return
					}
					_, _ = io.WriteString(w, "complete")
				}))
				client := deadlineClient(t, frontend, h2)
				client.Timeout = 0
				reader, writer := io.Pipe()
				defer writer.Close()
				request, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://service.example.test/", reader)
				request.Trailer = http.Header{"X-Upload-Digest": nil}
				done := make(chan deadlineResponse, 1)
				go func() { done <- deadlineDo(client, request) }()
				start := time.Now()
				for index := range 5 {
					if index > 0 {
						time.Sleep(10 * time.Second)
					}
					if _, err := io.WriteString(writer, "a"); err != nil {
						t.Fatal(err)
					}
					boundaryAwait(t, progress)
				}
				if time.Since(start) <= applicationlimits.DefaultRequestBodyIdleTimeout {
					t.Fatal("upload did not exceed the production default")
				}
				request.Trailer.Set("X-Upload-Digest", "complete")
				_ = writer.Close()
				if response := boundaryAwait(t, done); response.err != nil || response.status != http.StatusOK {
					t.Fatal("progressing upload failed after thirty seconds", response)
				}
				boundaryAwait(t, finished)
			})
		})
	}
}

func TestRequestBodyIdleTimeoutKeepsActiveHTTP2Sibling(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		unblock := sync.OnceFunc(func() { close(release) })
		defer unblock()
		entered := make(chan struct{})
		uploadEntered := make(chan struct{})
		frontend, _ := deadlineFrontendConcurrency(t, 100*time.Millisecond, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/upload" {
				close(uploadEntered)
				_, _ = io.Copy(io.Discard, r.Body)
				return
			}
			w.Header().Set("Trailer", "X-Sibling")
			_, _ = io.WriteString(w, "first\n")
			_ = http.NewResponseController(w).Flush()
			close(entered)
			<-release
			if err := r.Context().Err(); err != nil {
				t.Error("upload timeout canceled its active sibling", err)
			}
			_, _ = io.WriteString(w, "last\n")
			w.Header().Set("X-Sibling", "complete")
		}), 2)
		client := deadlineClient(t, frontend, true)
		reader, writer := io.Pipe()
		defer writer.Close()
		request, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://service.example.test/upload", reader)
		done := make(chan deadlineResponse, 1)
		go func() { done <- deadlineDo(client, request) }()
		_, _ = io.WriteString(writer, "a")
		boundaryAwait(t, uploadEntered)
		sibling, err := client.Get("https://service.example.test/sibling")
		if err != nil {
			t.Fatal(err)
		}
		defer sibling.Body.Close()
		boundaryAwait(t, entered)
		if response := boundaryAwait(t, done); response.err == nil && response.status < 400 {
			t.Fatal("stalled HTTP/2 upload succeeded", response)
		}
		time.Sleep(200 * time.Millisecond)
		unblock()
		if body, err := io.ReadAll(sibling.Body); err != nil || string(body) != "first\nlast\n" || sibling.Trailer.Get("X-Sibling") != "complete" {
			t.Fatal("timed-out upload damaged the sibling response or trailers", string(body), err, sibling.Trailer)
		}
	})
}

func TestRequestBodyIdleExcludesTargetBackpressure(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("http2=%t", h2), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				paused, resume := make(chan struct{}), make(chan struct{})
				unblock := sync.OnceFunc(func() { close(resume) })
				defer unblock()
				const size = 4 << 20
				handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_ = http.NewResponseController(w).EnableFullDuplex()
					if _, err := io.ReadFull(r.Body, make([]byte, 1)); err != nil {
						t.Error(err)
						return
					}
					close(paused)
					<-resume
					read, err := io.Copy(io.Discard, r.Body)
					if err != nil || read != size-1 {
						t.Error("target backpressure consumed the incoming-body timeout", read, err)
						return
					}
					_, _ = io.WriteString(w, "complete")
				})
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				incoming, target := net.Pipe()
				wire := &idleTargetConn{Conn: incoming}
				served := make(chan error, 1)
				go func() { served <- httpstream.ServeHandler(ctx, target, handler, httpstream.Drain{}, 0) }()
				defer func() {
					cancel()
					_ = incoming.Close()
					_ = target.Close()
					if err := <-served; err != nil {
						t.Error("backpressured target did not join", err)
					}
				}()
				frontend, finished := deadlineFrontendDial(t, 100*time.Millisecond, 1, func(context.Context) (net.Conn, error) { return wire, nil })
				client := deadlineClient(t, frontend, h2)
				reader, writer := io.Pipe()
				defer writer.Close()
				request, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://service.example.test/", reader)
				done, written := make(chan deadlineResponse, 1), make(chan error, 1)
				go func() { done <- deadlineDo(client, request) }()
				go func() {
					_, err := io.Copy(writer, bytes.NewReader(bytes.Repeat([]byte("a"), size)))
					_ = writer.CloseWithError(err)
					written <- err
				}()
				boundaryAwait(t, paused)
				synctest.Wait()
				if !wire.writing.Load() {
					t.Fatal("fixture did not block the publisher on a target write")
				}
				time.Sleep(time.Second)
				unblock()
				if err := boundaryAwait(t, written); err != nil {
					t.Fatal("paused target broke the upload", err)
				}
				if response := boundaryAwait(t, done); response.err != nil || response.status != http.StatusOK {
					t.Fatal("paused target was mistaken for an idle client", response)
				}
				boundaryAwait(t, finished)
			})
		})
	}
}

type idleTargetConn struct {
	net.Conn
	writing atomic.Bool
}

func (c *idleTargetConn) Write(p []byte) (int, error) {
	c.writing.Store(true)
	defer c.writing.Store(false)
	return c.Conn.Write(p)
}
