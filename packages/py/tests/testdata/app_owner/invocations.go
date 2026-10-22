package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"sync"
	"syscall"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	clientruntime "github.com/tnldotdev/tnl/internal/publisher/app"
	localpublisher "github.com/tnldotdev/tnl/internal/publisher/localapi"
	privateprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
)

func gate(ctx context.Context, root, name string) error {
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		if _, err := os.Stat(filepath.Join(root, name)); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return errors.New("fixture gate timed out")
		case <-tick.C:
		}
	}
}

func serveInvocations() error {
	if flag.NArg() != 1 {
		return errors.New("pass the private fixture directory")
	}
	root, err := filepath.EvalSymlinks(flag.Arg(0))
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	database, err := clientstate.OpenWithOptions(ctx, filepath.Join(root, "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		return err
	}
	defer database.Close()
	manager, err := clientruntime.New(ctx, root, database, nil, func(worker context.Context, service clientruntime.Service, publish func(uint64, bool) error) error {
		if err := os.WriteFile(filepath.Join(root, "worker-"+service.RegistrationID), nil, 0600); err != nil {
			return err
		}
		if err := publish(1, true); err != nil {
			return err
		}
		<-worker.Done()
		if err := os.WriteFile(filepath.Join(root, "drain-started"), nil, 0600); err != nil {
			return err
		}
		// the native unregister response must join this worker, even after the
		// client's registration reply was lost outside the handler boundary.
		return gate(ctx, root, "release-drain")
	})
	if err != nil {
		return err
	}
	defer manager.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	caps, err := privateprotocol.NewCapabilities("http://" + listener.Addr().String())
	if err != nil {
		return err
	}
	endpoint := caps.Owner()
	var preparation sync.Mutex
	requests := map[string]privateprotocol.Invocation{}
	boundary := (&localpublisher.Server{Capabilities: caps, Manager: manager, Database: database, Project: root, Invocation: func(requestContext context.Context, request privateprotocol.Invocation) (privateprotocol.Registration, error) {
		preparation.Lock()
		defer preparation.Unlock()
		for _, service := range manager.Snapshot().Services {
			if service.Name == request.InvocationId && service.RegistrationID != "" {
				if !reflect.DeepEqual(requests[service.Name], request) {
					return privateprotocol.Registration{}, clientruntime.ErrOwnerConflict
				}
				err := manager.RenewTarget(service.RegistrationID, request.Owner, request.Target)
				return privateprotocol.Registration{Version: 1, RegistrationID: service.RegistrationID, Owner: request.Owner, Target: request.Target}, err
			}
		}
		if err := manager.AddService(clientruntime.Service{Name: request.InvocationId, Directory: root, ServiceProtocol: "http"}); err != nil {
			return privateprotocol.Registration{}, err
		}
		id, err := manager.Reserve(request.InvocationId, request.Owner, request.Pid, "https://ephemeral.member.example.test")
		if err != nil {
			return privateprotocol.Registration{}, err
		}
		err = manager.RegisterContext(requestContext, id, request.Owner, request.Target, "python")
		requests[request.InvocationId] = request
		return privateprotocol.Registration{Version: 1, RegistrationID: id, Owner: request.Owner, Target: request.Target}, err
	}}).Handler()
	var first sync.Once
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/ad-hoc/register" {
			boundary.ServeHTTP(w, r)
			return
		}
		// capture after the actual handler commits and writes a successful reply;
		// drop only the outer transport so native cannot detect the lost ack.
		reply := httptest.NewRecorder()
		boundary.ServeHTTP(reply, r)
		drop := false
		first.Do(func() { drop = true })
		if drop && reply.Code == 200 {
			_ = os.WriteFile(filepath.Join(root, "committed.json"), reply.Body.Bytes(), 0600)
			_ = gate(ctx, root, "release-register")
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
			return
		}
		for key, values := range reply.Header() {
			w.Header()[key] = values
		}
		w.WriteHeader(reply.Code)
		_, _ = io.Copy(w, reply.Body)
	})}
	defer server.Close()
	if err := json.NewEncoder(os.Stdout).Encode(endpoint); err != nil {
		return err
	}
	go func() { _ = server.Serve(listener) }()
	<-ctx.Done()
	return nil
}
