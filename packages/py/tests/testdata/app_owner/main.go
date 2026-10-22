// this fixture uses native metadata and registration without control or relays.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	projectmeta "github.com/tnldotdev/tnl/internal/client/project/meta"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	clientruntime "github.com/tnldotdev/tnl/internal/publisher/app"
	localpublisher "github.com/tnldotdev/tnl/internal/publisher/localapi"
	privateprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	metadataOnly := flag.Bool("tnl-metadata", false, "emit the native assignment and exit")
	invocations := flag.Bool("tnl-invocations", false, "serve invocation reply-loss and drain gates")
	port := flag.Int("tnl-port", 25443, "allocated HTTP port")
	public := flag.Bool("tnl-public", true, "HTTP endpoint exposure")
	omit := flag.Bool("tnl-omit-service", false, "omit the selected service's metadata")
	flag.Parse()
	if *invocations {
		return serveInvocations()
	}
	metadata := projectmeta.Metadata{Version: projectmeta.Version, Namespace: "member.example", Services: map[string]projectmeta.Service{}}
	for _, entry := range []struct {
		name, protocol string
		port           int
		public         bool
	}{
		{"web", "http", *port, *public},
		{"api", "http", 443, false},
		{"database", "postgres", 15443, false},
		{"mysql", "mysql", 15444, true},
		{"stream", "tcp", 15445, false},
		{"cluster", "kubernetes", 16443, true},
	} {
		if *omit && entry.name == "web" {
			continue
		}
		service, err := projectmeta.NewEndpoint(metadata.Namespace, entry.name+"."+metadata.Namespace, entry.protocol, entry.port, entry.public)
		if err != nil {
			return err
		}
		metadata.Services[entry.name] = service
	}
	if service, found := metadata.Services["web"]; found {
		service.Paths = map[string]projectmeta.Path{"/api": {Service: "api", URL: service.URL + "/api", StripPrefix: true}}
		metadata.Services["web"] = service
	}
	if err := metadata.Validate(); err != nil {
		return err
	}
	selected := metadata.Services["web"]
	assignment := privateprotocol.Assignment{Version: 1, RegistrationID: "reg_0123456789abcdef0123456789abcdef", Service: "web", Hostname: selected.Hostname, PublicURL: selected.URL, Project: metadata.Public(true)}
	if *metadataOnly {
		return json.NewEncoder(os.Stdout).Encode(assignment)
	}
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
	manager, err := clientruntime.New(ctx, root, database, []clientruntime.Service{{Name: "web", Directory: root, ServiceProtocol: "http"}}, func(ctx context.Context, _ clientruntime.Service, _ func(uint64, bool) error) error {
		<-ctx.Done()
		return ctx.Err()
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
	capabilities, err := privateprotocol.NewCapabilities("http://" + listener.Addr().String())
	if err != nil {
		return err
	}
	name := "web"
	endpoint, err := capabilities.Issue(privateprotocol.CapabilityRequest{Scope: "app", Service: &name})
	if err != nil {
		return err
	}
	boundary := &localpublisher.Server{Capabilities: capabilities, Manager: manager, Database: database, Project: root, Prepare: func(_ context.Context, request privateprotocol.Prepare) (privateprotocol.Assignment, error) {
		if request.Directory != root || request.Service != name || request.Framework != privateprotocol.FrameworkPython {
			return privateprotocol.Assignment{}, errors.New("unexpected fixture preparation")
		}
		value := assignment
		id, err := manager.Reserve(name, request.Owner, request.PID, selected.URL)
		value.RegistrationID = id
		return value, err
	}}
	server := &http.Server{Handler: boundary.Handler(), ReadHeaderTimeout: 5 * time.Second}
	defer server.Close()
	if err := json.NewEncoder(os.Stdout).Encode(endpoint); err != nil {
		return err
	}
	go func() { _ = server.Serve(listener) }()
	<-ctx.Done()
	return nil
}
