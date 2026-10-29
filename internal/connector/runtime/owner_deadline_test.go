package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"
)

type deadlineBackend struct {
	fixtureBackend
	renew func(context.Context) (time.Time, error)
}

func (b *deadlineBackend) Renew(ctx context.Context) (time.Time, error) {
	return b.renew(ctx)
}

func TestConnectionOwnerRenewalUsesOriginalDeadline(t *testing.T) {
	for _, late := range []bool{false, true} {
		name := "shortened"
		if late {
			name = "late"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			scope := fixtureScope(t)
			directory, err := NewDirectory(scope.Directory)
			if err != nil {
				t.Fatal(err)
			}
			life, cancel := context.WithCancel(t.Context())
			defer cancel()
			release := make(chan struct{})
			unblock := sync.OnceFunc(func() { close(release) })
			defer unblock()
			renewed := make(chan time.Time, 1)
			expired := make(chan struct{})
			b := &deadlineBackend{fixtureBackend: fixtureBackend{deadline: time.Now().Add(32 * time.Second)}}
			b.renew = func(ctx context.Context) (time.Time, error) {
				until, ok := ctx.Deadline()
				if !ok || until.After(b.deadline) {
					t.Error("renewal was not clipped to the original owner deadline")
				}
				if !late {
					next := time.Now().Add(100 * time.Millisecond)
					renewed <- next
					return next, nil
				}
				renewed <- b.deadline
				<-ctx.Done()
				close(expired)
				// hold a backend's late success after cancellation. IPC must deny
				// new work without waiting for the renewal branch to return.
				select {
				case <-release:
				case <-life.Done():
				}
				return b.deadline, nil
			}
			reader, writer := io.Pipe()
			defer reader.Close()
			done := make(chan error, 1)
			stopped := make(chan struct{})
			go func() {
				defer close(stopped)
				done <- Serve(life, scope, directory, "/test/tnl", b, writer)
			}()
			t.Cleanup(func() {
				cancel()
				unblock()
				_ = writer.Close()
				select {
				case <-stopped:
				case <-time.After(5 * time.Second):
					t.Error("failed assertion left owner cleanup running")
				}
			})
			var state Status
			if err := json.NewDecoder(reader).Decode(&state); err != nil {
				t.Fatal(err)
			}
			handle, err := ReadHandle(state.ConnectionHandle)
			if err != nil {
				t.Fatal(err)
			}
			var renewedUntil time.Time
			select {
			case renewedUntil = <-renewed:
			case err := <-done:
				t.Fatal("owner ended without entering renewal", err)
			case <-time.After(33 * time.Second):
				t.Fatal("owner did not enter renewal")
			}
			if late {
				select {
				case <-expired:
				case err := <-done:
					t.Fatal("owner ended before exercising a late renewal", err)
				case <-time.After(35 * time.Second):
					t.Fatal("renewal did not observe its clipped deadline")
				}
				request, err := json.Marshal(Request{Schema: Schema, Directory: scope.Directory, ConfigDigest: scope.ConfigDigest, Service: "database"})
				if err != nil {
					t.Fatal(err)
				}
				client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, Timeout: time.Second}
				defer client.CloseIdleConnections()
				for _, operation := range []string{"status", "connect"} {
					req, err := http.NewRequestWithContext(life, http.MethodPost, handle.URL+"/v1/connections/"+operation, bytes.NewReader(request))
					if err != nil {
						t.Fatal(err)
					}
					req.Header.Set("Authorization", "Bearer "+handle.Key)
					response, err := client.Do(req)
					if err != nil {
						t.Fatal(err)
					}
					_, _ = io.Copy(io.Discard, response.Body)
					_ = response.Body.Close()
					if response.StatusCode != http.StatusGone {
						t.Fatal("expired IPC succeeded while renewal was pending", operation, response.StatusCode)
					}
				}
				if b.credential.Load() != 0 {
					t.Fatal("late renewal allowed a new connection")
				}
				unblock()
			}
			cleanupWait := time.Second
			if !late {
				cleanupWait = max(0, time.Until(renewedUntil.Add(time.Second)))
			}
			select {
			case err := <-done:
				if !errors.Is(err, ErrExpired) {
					t.Fatal("renewal revived the owner", err)
				}
			case <-time.After(cleanupWait):
				t.Fatal("owner did not stop after renewal")
			}
			if !b.closed.Load() {
				t.Fatal("owner returned without closing its backend")
			}
			if err := ReadStopResult(state.ConnectionHandle); err != nil {
				t.Fatal("owner returned before publishing joined cleanup", err)
			}
		})
	}
}
