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

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability"
)

// Serve owns private IPC and joins cleanup. process-owned adapters distinguish
// their process lifetime from bounded session and per-service authorization.
func Serve(ctx context.Context, scope Context, directory, executable string, config OwnerConfig, output io.Writer) (result error) {
	startup, finishStartup := observability.ClientOperation(ctx, "connector.connections.startup")
	defer func() { finishStartup(result) }()
	backend := config.Backend
	if scope.Validate() != nil || backend == nil || config.Persistent && config.OwnerAlive == nil {
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
	renewable := config.AuthorizationDeadline != nil
	var deadlineChanged <-chan struct{}
	if renewable {
		expires, deadlineChanged = config.AuthorizationDeadline()
	}
	observed := time.Now()
	if !expires.After(observed) || expires.After(observed.Add(12*time.Hour+time.Minute)) {
		return ErrExpired
	}
	// attach the accepted horizon to this process's monotonic clock once. later
	// updates shift it by the authority's delta, never a changed local wall clock.
	localDeadline := observed.Add(expires.Sub(observed))
	persistent := config.Persistent
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
	if config.Kubernetes != nil {
		state.Kubeconfig = config.Kubernetes.Kubeconfig()
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
		case "sdk-workload":
			if config.SDKWorkload == nil {
				writeConnectionFailure(w, ErrInvalid)
				return
			}
			selected, err := config.SDKWorkload(r.Context(), request)
			if err != nil {
				reason, known := failure.ReasonOf(err)
				if !known {
					reason = failure.ConnectionUnavailable
				}
				w.WriteHeader(http.StatusServiceUnavailable)
				_ = json.NewEncoder(w).Encode(map[string]any{"schema": 1, "reason": reason})
				return
			}
			_ = json.NewEncoder(w).Encode(selected)
		case "sdk-prepare":
			if config.SDKPrepare == nil {
				writeConnectionFailure(w, ErrInvalid)
				return
			}
			bounded, done := context.WithTimeout(r.Context(), 25*time.Second)
			defer done()
			prepared, err := config.SDKPrepare(bounded, request)
			if err != nil {
				reason, known := failure.ReasonOf(err)
				if !known {
					reason = failure.ConnectionUnavailable
				}
				w.WriteHeader(http.StatusServiceUnavailable)
				var retained interface{ RetainSDKFailure() bool }
				sticky := errors.As(err, &retained) && retained.RetainSDKFailure()
				var handle interface{ SDKFailureHandle() string }
				var failureHandle string
				if sticky && errors.As(err, &handle) {
					failureHandle = handle.SDKFailureHandle()
				}
				var owner interface{ SDKOwnerHandle() string }
				var ownerHandle string
				if errors.As(err, &owner) {
					ownerHandle = owner.SDKOwnerHandle()
				}
				_ = json.NewEncoder(w).Encode(struct {
					Schema        int            `json:"schema"`
					Reason        failure.Reason `json:"reason"`
					Retained      bool           `json:"sdk_retained_start_failure,omitempty"`
					FailureHandle string         `json:"sdk_failure_handle,omitempty"`
					OwnerHandle   string         `json:"sdk_owner_handle,omitempty"`
				}{Schema: 1, Reason: reason, Retained: sticky, FailureHandle: failureHandle, OwnerHandle: ownerHandle})
				return
			}
			_ = json.NewEncoder(w).Encode(prepared)
		case "attach":
			bounded, done := context.WithTimeout(r.Context(), 10*time.Second)
			defer done()
			if err := backend.Attach(bounded, request.Assertion); err != nil {
				w.WriteHeader(403)
				_, _ = io.WriteString(w, `{"code":"connections.unauthorized"}`)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"schema": Schema, "state": "attached"})
		case "status":
			current.ProjectRuntime = backend.ProjectRuntime()
			if config.Kubernetes != nil {
				current.Kubeconfig = config.Kubernetes.Kubeconfig()
			}
			_ = json.NewEncoder(w).Encode(current)
		case "connect", "prepare", "prepared":
			bounded, done := context.WithTimeout(r.Context(), 25*time.Second)
			defer done()
			stop := context.AfterFunc(lifetime, done)
			defer stop()
			var prepared Prepared
			var err error
			if operation == "prepared" {
				prepared, err = backend.SnapshotFor(request.Service, request.Assertion)
			} else {
				prepared, err = PrepareSnapshot(bounded, backend, request)
			}
			if err != nil {
				writeConnectionFailure(w, err)
				return
			}
			if err := prepared.Validate(); err != nil {
				writeConnectionFailure(w, err)
				return
			}
			if operation != "connect" {
				_ = json.NewEncoder(w).Encode(prepared)
			} else {
				_ = json.NewEncoder(w).Encode(prepared.Connection)
			}
		case "kube-credential":
			if config.Kubernetes == nil {
				w.WriteHeader(503)
				_, _ = io.WriteString(w, `{"code":"connections.unavailable"}`)
				return
			}
			bounded, done := context.WithTimeout(r.Context(), 25*time.Second)
			defer done()
			stop := context.AfterFunc(lifetime, done)
			defer stop()
			credential, err := config.Kubernetes.Credential(bounded, request.Service)
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
	updateDeadline := func(next time.Time) error {
		stateMu.Lock()
		defer stateMu.Unlock()
		shifted, err := renewedOwnerDeadline(time.Now(), localDeadline, expires, next, renewable)
		if err != nil {
			return err
		}
		if !expires.Equal(next) {
			nextHandle := handle
			nextHandle.ExpiresAt = next
			if err := updateHandle(path, handle, nextHandle); err != nil {
				return err
			}
			handle = nextHandle
		}
		localDeadline, expires, state.ExpiresAt = shifted, next, next
		deadline.Reset(time.Until(localDeadline))
		return nil
	}
	for {
		select {
		case <-lifetime.Done():
			return nil
		case <-serverDone:
			return ErrUnavailable
		case err := <-config.Done:
			return errors.Join(ErrUnavailable, err)
		case <-deadline.C:
			return ErrExpired
		case <-deadlineChanged:
			if !persistent {
				next, _ := config.AuthorizationDeadline()
				if err := updateDeadline(next); err != nil {
					return err
				}
			}
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
				if !config.OwnerAlive() {
					return nil
				}
				continue
			}
			if err != nil {
				return err
			}
			if err := updateDeadline(next); err != nil {
				return err
			}
		}
	}
}

func renewedOwnerDeadline(now, deadline, previous, next time.Time, renewable bool) (time.Time, error) {
	if !now.Before(deadline) || !next.After(now) || !renewable && next.After(previous) || next.After(now.Add(12*time.Hour+time.Minute)) {
		return time.Time{}, ErrExpired
	}
	// shift only by the authority's change. rebuilding from next-now would
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
