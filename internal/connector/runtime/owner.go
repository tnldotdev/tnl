package runtime

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/client/project/meta"
	"github.com/tnldotdev/tnl/internal/observability"
	credentialv1 "k8s.io/client-go/pkg/apis/clientauthentication/v1"
)

// Serve owns private IPC and joins cleanup. process-owned adapters distinguish
// their process lifetime from bounded session and per-service authorization.
func Serve(ctx context.Context, scope Context, directory, executable string, backend Backend, output io.Writer) (result error) {
	startup, finishStartup := observability.ClientOperation(ctx, "connector.connections.startup")
	defer func() { finishStartup(result) }()
	if scope.Validate() != nil || backend == nil {
		return ErrInvalid
	}
	lifetime, cancel := context.WithCancel(observability.Independent(ctx))
	defer cancel()
	var closeOnce sync.Once
	var closeError error
	closeBackend := func() {
		closeOnce.Do(func() {
			cleanup, done := context.WithTimeout(observability.Independent(context.WithoutCancel(ctx)), 15*time.Second)
			defer done()
			cleanup, finish := observability.ClientOperation(cleanup, "connector.connections.shutdown")
			closeError = backend.Close(cleanup)
			finish(closeError)
			result = errors.Join(result, closeError)
		})
	}
	defer closeBackend()
	lock, err := ownerLock(directory)
	if err != nil {
		return err
	}
	defer lock.Close()
	setup, finish := context.WithTimeout(startup, 30*time.Second)
	metadata, expires, err := backend.Start(setup)
	finish()
	if err != nil {
		return err
	}
	observed := time.Now()
	if !expires.After(observed) || expires.After(observed.Add(6*time.Hour+time.Second)) {
		return ErrExpired
	}
	// attach the received fixed expiry to this process's monotonic clock once.
	// renewals may shorten this deadline, never re-anchor it to a changed wall clock.
	localDeadline := observed.Add(expires.Sub(observed))
	persistent := false
	if provider, ok := backend.(interface{ Persistent() bool }); ok {
		persistent = provider.Persistent()
	}
	if persistent {
		expires = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
		localDeadline = expires
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	key, err := randomKey()
	if err != nil {
		return err
	}
	path := filepath.Join(directory, "handle.json")
	handle := Handle{Schema: Schema, URL: "http://" + listener.Addr().String(), Key: key, Directory: scope.Directory, ConfigDigest: scope.ConfigDigest, ExpiresAt: expires, Executable: executable}
	if scope.Workload != "" {
		handle.Workload, handle.TeamID = scope.Workload, scope.TeamID
	}
	if err := WriteHandle(path, handle); err != nil {
		return err
	}
	defer func() {
		closeBackend()
		terminal, _ := json.Marshal(struct {
			Schema int  `json:"schema"`
			Clean  bool `json:"clean"`
		}{Schema: 1, Clean: closeError == nil})
		result = errors.Join(result, os.WriteFile(filepath.Join(directory, "stopped.json"), terminal, 0o600))
		_ = os.Remove(path)
	}()
	state := Status{Schema: Schema, State: "ready", PID: os.Getpid(), ExpiresAt: expires, ProjectRuntime: metadata, ConnectionHandle: path, Executable: executable}
	if provider, ok := backend.(interface{ Kubeconfig() string }); ok {
		state.Kubeconfig = provider.Kubeconfig()
	}
	var failed <-chan error
	if provider, ok := backend.(interface{ Done() <-chan error }); ok {
		failed = provider.Done()
	}
	var stateMu sync.Mutex
	server := &http.Server{BaseContext: func(net.Listener) context.Context { return observability.Independent(lifetime) }, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 35 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 4096}
	server.Handler = observability.LocalRequests(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		if r.Method != "POST" || r.Host != listener.Addr().String() || r.Header.Get("Origin") != "" || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+key)) != 1 {
			w.WriteHeader(401)
			_, _ = io.WriteString(w, `{"code":"connections.unauthorized"}`)
			return
		}
		request := Request{}
		if ReadJSON(r.Body, &request) != nil || request.Schema != Schema || request.Directory != scope.Directory || request.ConfigDigest != scope.ConfigDigest {
			w.WriteHeader(401)
			_, _ = io.WriteString(w, `{"code":"connections.unauthorized"}`)
			return
		}
		operation := strings.TrimPrefix(r.URL.Path, "/v1/connections/")
		if operation == "stop" {
			defer cancel()
			_ = json.NewEncoder(w).Encode(map[string]any{"schema": Schema, "state": "stopping"})
			return
		}
		stateMu.Lock()
		current := state
		expired := !persistent && !time.Now().Before(localDeadline)
		stateMu.Unlock()
		if lifetime.Err() != nil || expired {
			w.WriteHeader(410)
			_, _ = io.WriteString(w, `{"code":"connections.expired"}`)
			return
		}
		switch operation {
		case "attach":
			provider, ok := backend.(interface {
				Attach(context.Context, string) error
			})
			if !ok {
				w.WriteHeader(400)
				_, _ = io.WriteString(w, `{"code":"connections.invalid"}`)
				return
			}
			bounded, done := context.WithTimeout(r.Context(), 10*time.Second)
			defer done()
			if err := provider.Attach(bounded, request.Assertion); err != nil {
				w.WriteHeader(403)
				_, _ = io.WriteString(w, `{"code":"connections.unauthorized"}`)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"schema": Schema, "state": "attached"})
		case "status":
			if provider, ok := backend.(interface {
				ProjectRuntime() meta.PublicMetadata
			}); ok {
				current.ProjectRuntime = provider.ProjectRuntime()
			}
			_ = json.NewEncoder(w).Encode(current)
		case "connect", "prepare", "prepared":
			bounded, done := context.WithTimeout(r.Context(), 25*time.Second)
			defer done()
			stop := context.AfterFunc(lifetime, done)
			defer stop()
			var connection Connection
			var err error
			if operation == "prepared" {
				connection, err = backend.Prepared(request.Service)
			} else {
				if request.Assertion != "" || request.AcquireAssertion {
					if provider, ok := backend.(interface {
						UseAssertion(context.Context, string) error
					}); ok {
						err = provider.UseAssertion(bounded, request.Assertion)
					} else {
						provider, ok := backend.(interface {
							Attach(context.Context, string) error
						})
						if !ok {
							err = ErrInvalid
						} else {
							err = provider.Attach(bounded, request.Assertion)
						}
					}
				}
				if err == nil {
					connection, err = backend.Connect(bounded, request.Service)
				}
			}
			if err != nil {
				writeConnectionFailure(w, err)
				return
			}
			if operation != "connect" {
				if provider, ok := backend.(interface {
					SnapshotFor(string, string) (Prepared, error)
				}); ok {
					// pair metadata, transport identity and assertion proof from one
					// immutable publication, even if another request replaces a session.
					prepared, err := provider.SnapshotFor(request.Service, request.Assertion)
					if err != nil {
						writeConnectionFailure(w, err)
						return
					}
					_ = json.NewEncoder(w).Encode(prepared)
					return
				}
				if provider, ok := backend.(interface {
					ProjectRuntime() meta.PublicMetadata
				}); ok {
					current.ProjectRuntime = provider.ProjectRuntime()
				}
				result := Prepared{Schema: Schema, ProjectRuntime: current.ProjectRuntime, Connection: connection}
				if provider, ok := backend.(interface{ Verification() *AssertionVerification }); ok {
					result.Verification = provider.Verification()
				}
				_ = json.NewEncoder(w).Encode(result)
			} else {
				_ = json.NewEncoder(w).Encode(connection)
			}
		case "kube-credential":
			provider, ok := backend.(interface {
				Credential(context.Context, string) (credentialv1.ExecCredential, error)
			})
			if !ok {
				w.WriteHeader(503)
				_, _ = io.WriteString(w, `{"code":"connections.unavailable"}`)
				return
			}
			bounded, done := context.WithTimeout(r.Context(), 25*time.Second)
			defer done()
			stop := context.AfterFunc(lifetime, done)
			defer stop()
			credential, err := provider.Credential(bounded, request.Service)
			if err != nil {
				w.WriteHeader(503)
				_, _ = io.WriteString(w, `{"code":"connections.unavailable"}`)
				return
			}
			_ = json.NewEncoder(w).Encode(credential)
		default:
			w.WriteHeader(404)
			_, _ = io.WriteString(w, `{"code":"connections.invalid"}`)
		}
	}))
	serverDone := make(chan struct{})
	var serveError error
	go func() { serveError = server.Serve(listener); close(serverDone) }()
	defer func() {
		cancel()
		shutdown, done := context.WithTimeout(context.Background(), 5*time.Second)
		_ = server.Shutdown(shutdown)
		done()
		_ = server.Close()
		closeBackend()
		<-serverDone
		if !errors.Is(serveError, http.ErrServerClosed) {
			result = errors.Join(result, serveError)
		}
	}()
	if err := json.NewEncoder(output).Encode(state); err != nil {
		return err
	}
	finishStartup(nil)
	// the parent receives EOF immediately; the detached child retains no pipe to
	// the action's terminal and keeps RUNNER_TRACKING_ID for runner crash cleanup.
	if closer, ok := output.(io.Closer); ok {
		_ = closer.Close()
	}
	renew := time.NewTicker(30 * time.Second)
	defer renew.Stop()
	deadline := time.NewTimer(time.Until(localDeadline))
	defer deadline.Stop()
	for {
		select {
		case <-lifetime.Done():
			return nil
		case <-serverDone:
			return ErrUnavailable
		case err := <-failed:
			return errors.Join(ErrUnavailable, err)
		case <-deadline.C:
			return ErrExpired
		case <-renew.C:
			until := time.Now().Add(10 * time.Second)
			if !persistent && localDeadline.Before(until) {
				until = localDeadline
			}
			bounded, done := context.WithDeadline(lifetime, until)
			bounded, finish := observability.ClientOperation(bounded, "connector.connections.renew")
			next, err := backend.Renew(bounded)
			finish(err)
			done()
			if persistent {
				if provider, ok := backend.(interface{ OwnerAlive() bool }); ok && !provider.OwnerAlive() {
					return nil
				}
				continue
			}
			if err != nil {
				return err
			}
			stateMu.Lock()
			narrowed, err := renewedOwnerDeadline(time.Now(), localDeadline, expires, next)
			if err != nil {
				stateMu.Unlock()
				return err
			}
			localDeadline = narrowed
			expires = next
			state.ExpiresAt = next
			deadline.Reset(time.Until(localDeadline))
			stateMu.Unlock()
		}
	}
}

func renewedOwnerDeadline(now, deadline, previous, next time.Time) (time.Time, error) {
	if !now.Before(deadline) || !next.After(now) || next.After(previous) {
		return time.Time{}, ErrExpired
	}
	// subtract only the authority's reduction. rebuilding from next-now would
	// extend the running owner after a backward wall-clock adjustment.
	deadline = deadline.Add(next.Sub(previous))
	if !now.Before(deadline) {
		return time.Time{}, ErrExpired
	}
	return deadline, nil
}

func writeConnectionFailure(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrUnprepared):
		w.WriteHeader(425)
		_, _ = io.WriteString(w, `{"code":"connections.unprepared"}`)
	case errors.Is(err, ErrExpired):
		w.WriteHeader(410)
		_, _ = io.WriteString(w, `{"code":"connections.expired"}`)
	default:
		w.WriteHeader(503)
		_, _ = io.WriteString(w, `{"code":"connections.unavailable"}`)
	}
}
