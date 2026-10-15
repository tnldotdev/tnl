// this fixture runs the real private owner API and target resolver in separate
// containers. it does not replace public URL publication or public probes.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/tnldotdev/tnl/internal/clientruntime"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/localpublisher"
	"github.com/tnldotdev/tnl/internal/privateprotocol"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/internal/publishertarget"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 {
		return errors.New("select owner, app, query, or exec-query")
	}
	switch os.Args[1] {
	case "app":
		name, _ := os.Hostname()
		return http.ListenAndServe(":3000", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, name) }))
	case "app-register":
		return registeredApp()
	case "query":
		flags := flag.NewFlagSet("query", flag.ContinueOnError)
		path := flags.String("descriptor", os.Getenv("TNL_APP_ENDPOINT"), "private endpoint")
		urlPath := flags.String("path", "/v1/status", "request path")
		method := flags.String("method", "GET", "request method")
		body := flags.String("body", "", "request JSON")
		save := flags.String("save", "", "save the current app endpoint for a stale-capability check")
		if err := flags.Parse(os.Args[2:]); err != nil {
			return err
		}
		data, err := os.ReadFile(*path)
		if err != nil {
			return err
		}
		if *save != "" {
			if err := os.WriteFile(*save, data, 0600); err != nil {
				return err
			}
		}
		var endpoint privateprotocol.Endpoint
		if err := json.Unmarshal(data, &endpoint); err != nil {
			return err
		}
		if err := privateprotocol.ValidateComposeAppEndpoint(endpoint, os.Getenv("TNL_APP_AUTHORITY")); err != nil {
			return err
		}
		req, err := http.NewRequest(*method, endpoint.Url+*urlPath, strings.NewReader(*body))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+endpoint.Capability)
		req.Header.Set("Content-Type", "application/json")
		client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		response, err := client.Do(req)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		bodyData, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		if err != nil {
			return err
		}
		if len(bodyData) == 0 {
			bodyData = []byte("null")
		}
		return json.NewEncoder(os.Stdout).Encode(localpublisher.ComposeReply{Status: response.StatusCode, Body: bodyData})
	case "exec-query":
		path, err := privateprotocol.DescriptorPath("/state/private", "/project")
		if err != nil {
			return err
		}
		endpoint, err := privateprotocol.ReadEndpoint(path)
		if err != nil {
			return err
		}
		return localpublisher.ServeComposeQuery(context.Background(), endpoint, os.Stdin, os.Stdout)
	case "owner":
		return owner()
	}
	return errors.New("unknown fixture command")
}

// registeredApp runs a real app listener and renews its scoped registration.
// after owner replacement it reads the rotated descriptor and prepares again.
func registeredApp() error {
	endpointPath := os.Getenv("TNL_APP_ENDPOINT")
	authority := os.Getenv("TNL_APP_AUTHORITY")
	if endpointPath == "" || authority == "" {
		return errors.New("the scoped app endpoint or publisher authority is missing")
	}
	listener, err := net.Listen("tcp", ":3000")
	if err != nil {
		return err
	}
	name, err := os.Hostname()
	if err != nil {
		_ = listener.Close()
		return err
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, name) }), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = server.Serve(listener) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return err
	}
	owner := hex.EncodeToString(bytes[:])
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	var endpoint privateprotocol.Endpoint
	var registration privateprotocol.Registration
	registered := false
	lastError := ""
	for {
		if !registered {
			current, err := privateprotocol.ReadComposeAppEndpoint(endpointPath, authority)
			if err == nil {
				callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
				var assignment privateprotocol.Assignment
				err = privateprotocol.CallComposeApp(callCtx, current, authority, "POST", "/v1/prepare", privateprotocol.Prepare{Version: 1, Directory: "/workspace", Service: "web", Framework: "node", Owner: owner, PID: os.Getpid()}, &assignment)
				if err == nil {
					registration = privateprotocol.Registration{Version: 1, RegistrationID: assignment.RegistrationID, Owner: owner, Target: "http://0.0.0.0:3000"}
					err = privateprotocol.CallComposeApp(callCtx, current, authority, "POST", "/v1/register", registration, nil)
				}
				cancel()
				if err == nil {
					endpoint, registered = current, true
				}
			}
			if err != nil && err.Error() != lastError {
				fmt.Fprintln(os.Stderr, "app registration:", err)
				lastError = err.Error()
			} else if err == nil {
				lastError = ""
			}
		}
		interval := 250 * time.Millisecond
		if registered {
			interval = 3 * time.Second
		}
		select {
		case <-ctx.Done():
			if registered {
				cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				_ = privateprotocol.CallComposeApp(cleanup, endpoint, authority, "POST", "/v1/unregister", registration, nil)
				cancel()
			}
			return nil
		case <-time.After(interval):
		}
		if registered {
			callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			err := privateprotocol.CallComposeApp(callCtx, endpoint, authority, "POST", "/v1/renew", registration, nil)
			cancel()
			registered = err == nil
		}
	}
}

func owner() error {
	ctx := context.Background()
	var setup localpublisher.ComposeSetup
	deadline := time.Now().Add(time.Minute)
	for {
		file, err := os.Open("/setup/placement.json")
		if err == nil {
			setup, err = localpublisher.DecodeComposeSetup(file)
			file.Close()
			if err != nil {
				return err
			}
			break
		}
		if time.Now().After(deadline) {
			return errors.New("host placement metadata was not supplied")
		}
		time.Sleep(50 * time.Millisecond)
	}
	docker := publishertarget.Socket{}
	if err := setup.Validate(ctx, docker); err != nil {
		return err
	}
	root := "/state/private"
	db, err := clientstate.OpenWithOptions(ctx, root, clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		return err
	}
	defer db.Close()
	if err := os.MkdirAll("/project", 0755); err != nil {
		return err
	}
	manager, err := clientruntime.New(ctx, "/project", db, []clientruntime.Service{{Name: "web"}, {Name: "api"}, {Name: "db", ServiceProtocol: "redis"}}, func(ctx context.Context, _ clientruntime.Service, _ func(uint64, bool) error) error {
		<-ctx.Done()
		return ctx.Err()
	})
	if err != nil {
		return err
	}
	defer manager.Close()
	boundary := setup.Boundary(docker, root)
	address, err := boundary.ListenAddress()
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp4", address)
	if err != nil {
		return err
	}
	caps, err := privateprotocol.NewCapabilities(fmt.Sprintf("http://127.0.0.1:%d", setup.Port))
	if err != nil {
		return err
	}
	if err := setup.WriteApps(ctx, docker, root, caps); err != nil {
		return err
	}
	path, err := privateprotocol.DescriptorPath(root, "/project")
	if err != nil {
		return err
	}
	if err := privateprotocol.WriteEndpoint(path, caps.Owner()); err != nil {
		return err
	}
	defer privateprotocol.RemoveEndpoint(path, caps.Owner().OwnerId)
	port, project, file, service, protocol := 3000, setup.Project, filepath.Base(setup.File), "web", "http"
	resolvedProject := projectconfig.Project{Root: "/project", Worktree: setup.Placement.Worktree, Config: config.TNL{Services: config.Services{"web": {Protocol: &protocol, Target: &config.ServiceTarget{Type: "compose", Project: &project, File: &file, Service: &service, Port: &port}}}}}
	dbPort, dbService, dbProtocol := 6379, "db", "redis"
	resolvedProject.Config.Services["db"] = config.Service{Protocol: &dbProtocol, Target: &config.ServiceTarget{Type: "compose", Project: &project, File: &file, Service: &dbService, Port: &dbPort}}
	resolver := publishertarget.Resolver{Docker: docker, Placement: &setup.Placement}
	server := &localpublisher.Server{Capabilities: caps, Manager: manager, Database: db, Project: "/project", AppService: func(name string) bool { return name == "web" || name == "api" }, Acquire: func(ctx context.Context, request privateprotocol.Lease) (privateprotocol.Registration, error) {
		target, err := resolver.ResolveTarget(ctx, resolvedProject, request.Service)
		if err != nil {
			return privateprotocol.Registration{}, err
		}
		id, err := manager.Reserve(request.Service, request.Owner, request.Pid, "https://fixture.invalid")
		if err != nil {
			return privateprotocol.Registration{}, err
		}
		if request.Service == "web" {
			target = "http://" + target
		}
		registration := privateprotocol.Registration{Version: 1, RegistrationID: id, Owner: request.Owner, Target: target}
		return registration, manager.Register(id, request.Owner, registration.Target, "")
	}}
	return (&http.Server{Handler: boundary.Handler(caps, server.Handler()), ReadHeaderTimeout: 5 * time.Second}).Serve(listener)
}
