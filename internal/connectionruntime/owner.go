package connectionruntime

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

	credentialv1 "k8s.io/client-go/pkg/apis/clientauthentication/v1"
)

// Serve reports readiness once, after every service has bound and verified TLS.
// any service/renewal failure cancels the entire owner; cleanup is always joined.
func Serve(ctx context.Context, scope Context, directory, executable string, backend Backend, output io.Writer) (result error) {
	if scope.Validate() != nil || backend == nil {
		return ErrInvalid
	}
	lifetime, cancel := context.WithCancel(ctx)
	defer cancel()
	var closeOnce sync.Once
	var closeError error
	closeBackend := func() {
		closeOnce.Do(func() {
			cleanup, done := context.WithTimeout(context.Background(), 15*time.Second)
			defer done()
			closeError = backend.Close(cleanup)
			result = errors.Join(result, closeError)
		})
	}
	defer closeBackend()
	setup, finish := context.WithTimeout(lifetime, 30*time.Second)
	metadata, expires, err := backend.Start(setup)
	finish()
	if err != nil {
		return err
	}
	if !expires.After(time.Now()) || expires.After(time.Now().Add(6*time.Hour+time.Second)) {
		return ErrExpired
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
	if scope.CI != "" {
		handle.CI, handle.TeamID = scope.CI, scope.TeamID
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
	state := Status{Schema: Schema, State: "ready", PID: os.Getpid(), ExpiresAt: expires, PublicRuntime: metadata, PrivateHandle: path, Executable: executable}
	if provider, ok := backend.(interface{ Kubeconfig() string }); ok {
		state.Kubeconfig = provider.Kubeconfig()
	}
	var failed <-chan error
	if provider, ok := backend.(interface{ Done() <-chan error }); ok {
		failed = provider.Done()
	}
	var operationMu sync.Mutex
	server := &http.Server{ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 35 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 4096}
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		operationMu.Lock()
		defer operationMu.Unlock()
		if lifetime.Err() != nil || !expires.After(time.Now()) {
			w.WriteHeader(410)
			_, _ = io.WriteString(w, `{"code":"connections.expired"}`)
			return
		}
		switch operation {
		case "status":
			_ = json.NewEncoder(w).Encode(state)
		case "connect", "prepared":
			bounded, done := context.WithTimeout(r.Context(), 25*time.Second)
			defer done()
			stop := context.AfterFunc(lifetime, done)
			defer stop()
			connection, err := backend.Connect(bounded, request.Service)
			if err != nil {
				if errors.Is(err, ErrExpired) {
					w.WriteHeader(410)
					_, _ = io.WriteString(w, `{"code":"connections.expired"}`)
					return
				}
				w.WriteHeader(503)
				_, _ = io.WriteString(w, `{"code":"connections.unavailable"}`)
				return
			}
			if operation == "prepared" {
				_ = json.NewEncoder(w).Encode(Prepared{Schema: Schema, PublicRuntime: state.PublicRuntime, Connection: connection})
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
	})
	serverDone := make(chan struct{})
	var serveError error
	go func() { serveError = server.Serve(listener); close(serverDone) }()
	defer func() {
		cancel()
		shutdown, done := context.WithTimeout(context.Background(), 5*time.Second)
		_ = server.Shutdown(shutdown)
		done()
		_ = server.Close()
		operationMu.Lock()
		closeBackend()
		operationMu.Unlock()
		<-serverDone
		if !errors.Is(serveError, http.ErrServerClosed) {
			result = errors.Join(result, serveError)
		}
	}()
	if err := json.NewEncoder(output).Encode(state); err != nil {
		return err
	}
	// the parent receives EOF immediately; the detached child retains no pipe to
	// the action's terminal and keeps RUNNER_TRACKING_ID for runner crash cleanup.
	if closer, ok := output.(io.Closer); ok {
		_ = closer.Close()
	}
	renew := time.NewTicker(30 * time.Second)
	defer renew.Stop()
	deadline := time.NewTimer(time.Until(expires))
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
			bounded, done := context.WithTimeout(lifetime, 10*time.Second)
			next, err := backend.Renew(bounded)
			done()
			if err != nil {
				return err
			}
			if !next.After(time.Now()) || next.After(expires) {
				return ErrExpired
			}
		}
	}
}
