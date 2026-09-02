package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/dnsready"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/serverclient"
	"github.com/tnldotdev/tnl/internal/state"
	"github.com/tnldotdev/tnl/internal/testutil/integrationtest"
	"github.com/tnldotdev/tnl/internal/worker"
	"github.com/tnldotdev/tnl/internal/workercontrol"
	"github.com/tnldotdev/tnl/pkg/protocol/serverv1"
	"github.com/tnldotdev/tnl/pkg/protocol/workerv1"
	"tailscale.com/tailcfg"
)

func TestVersionCommand(t *testing.T) {
	var output bytes.Buffer
	if err := run(context.Background(), []string{"version"}, &output); err != nil {
		t.Fatal(err)
	}
	if output.String() != "tnld devel\n" {
		t.Fatalf("output = %q", output.String())
	}
}

func TestTokenCommands(t *testing.T) {
	for _, tokenType := range []string{"worker", "service"} {
		t.Run(tokenType, func(t *testing.T) {
			var output bytes.Buffer
			if err := run(context.Background(), []string{"token", tokenType}, &output); err != nil {
				t.Fatal(err)
			}
			value := strings.TrimSpace(output.String())
			var err error
			if tokenType == "worker" {
				_, err = credentials.ParseWorkerToken(credentials.WorkerToken(value))
			} else {
				_, err = credentials.ParseServiceToken(credentials.ServiceToken(value))
			}
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCommandTreeIncludesServeAndAdministration(t *testing.T) {
	var flags tnldCLI
	parser, err := newTNLDParser(&flags, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	commands := map[string]bool{}
	for _, command := range parser.Model.Leaves(true) {
		commands[command.Path()] = true
	}
	for _, command := range []string{"serve", "version", "login-token", "token worker", "token service", "relay refresh"} {
		if !commands[command] {
			t.Fatalf("command %q missing from help model: %#v", command, commands)
		}
	}

	for name, test := range map[string]struct {
		args []string
		want string
	}{
		"default serve":  {args: []string{"--public-listen", ""}, want: "serve"},
		"explicit serve": {args: []string{"serve", "--public-listen", ""}, want: "serve"},
		"login token":    {args: []string{"login-token", "--state-dir", "/state"}, want: "login-token"},
		"relay refresh":  {args: []string{"relay", "refresh", "--state-dir", "/state"}, want: "relay refresh"},
	} {
		t.Run(name, func(t *testing.T) {
			var flags tnldCLI
			parser, err := newTNLDParser(&flags, &bytes.Buffer{})
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := parser.Parse(test.args)
			if err != nil {
				t.Fatal(err)
			}
			if parsed.Command() != test.want {
				t.Fatalf("command = %q, want %q", parsed.Command(), test.want)
			}
		})
	}
}

func TestLoginTokenCommand(t *testing.T) {
	directory := t.TempDir()
	db, err := state.Open(t.Context(), directory)
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := state.EnsureLoginToken(t.Context(), db)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := run(context.Background(), []string{"login-token", "--state-dir", directory}, &output); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(output.String()); got != token.String() {
		t.Fatalf("login token = %q", got)
	}
}

func TestIntegrationStandaloneControlLifecycle(t *testing.T) {
	pebblePath := integrationtest.RequirePebble(t)
	directory := t.TempDir()
	relayFile := filepath.Join(directory, "relay.json")
	relayData, err := json.Marshal(tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{1: {
		RegionID: 1, RegionCode: "test", Nodes: []*tailcfg.DERPNode{{
			Name: "test", RegionID: 1, HostName: "derp.invalid", DERPPort: 443,
		}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(relayFile, relayData, 0o600); err != nil {
		t.Fatal(err)
	}
	login, err := credentials.NewLoginToken()
	if err != nil {
		t.Fatal(err)
	}
	publicListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	publicAddress := publicListener.Addr().String()
	publicPort := publicListener.Addr().(*net.TCPAddr).Port
	if err := publicListener.Close(); err != nil {
		t.Fatal(err)
	}
	dnsAddress := integrationtest.StartChallengeDNS(t)
	dnsDialer := new(net.Dialer)
	testResolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dnsDialer.DialContext(ctx, "udp", dnsAddress)
		},
	}
	pebble := integrationtest.StartPebble(t, pebblePath, publicPort, dnsAddress)
	previousTransport := http.DefaultTransport
	http.DefaultTransport = pebble.HTTPClient().Transport
	t.Cleanup(func() { http.DefaultTransport = previousTransport })
	cfg := config.TNLD{
		Mode: config.TNLDModeStandalone, StateDir: filepath.Join(directory, "state"),
		PublicListen: publicAddress, Domain: "example",
		ACMEDirectoryURL: pebble.DirectoryURL(), ACMEEmail: "operator@example.com", ACMEAcceptTerms: true,
		ACMEProfile: "tlsserver", RelayMapFile: relayFile, RelayRegion: "test",
		WorkerCapacity: 10, WorkerStreamLimit: 10, PublicConnLimit: 10, RouteConnLimit: 5, DrainTimeout: time.Second,
		MaxActiveHostnames: 128, MaxHostnameRequests: 1024,
		AccessTokenLifetime: time.Hour,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	db, err := state.Open(context.Background(), cfg.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	running := &daemon{db: db, login: login, dns: dnsready.NewWithResolver("tnl.example", "example", testResolver)}
	t.Cleanup(func() { _ = running.shutdown(time.Second) })
	serverContext, cancelServer := context.WithCancel(context.Background())
	t.Cleanup(cancelServer)
	controlDone, ingressDone, err := running.startServer(serverContext, cfg, observability.New("standalone"))
	if err != nil {
		t.Fatal(err)
	}
	httpClient := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pebble.IssuerRoots(t), MinVersion: tls.VersionTLS13},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return new(net.Dialer).DialContext(ctx, network, running.controlListener.Addr().String())
		},
	}, Timeout: 5 * time.Second}
	baseURL := "https://tnl.example"
	for _, path := range []string{"/v1/health", "/v1/ready"} {
		response, err := httpClient.Get(baseURL + path)
		if err != nil {
			t.Fatal(err)
		}
		var body map[string]any
		decodeErr := json.NewDecoder(response.Body).Decode(&body)
		closeErr := response.Body.Close()
		if response.StatusCode != http.StatusOK || decodeErr != nil || closeErr != nil || body["status"] == nil {
			t.Fatalf("probe %s: status = %d, body = %#v, decode = %v, close = %v", path, response.StatusCode, body, decodeErr, closeErr)
		}
	}
	anonymous, err := serverclient.New(baseURL, httpClient, "")
	if err != nil {
		t.Fatal(err)
	}
	issued, err := anonymous.Exchange(context.Background(), login)
	if err != nil {
		t.Fatal(err)
	}
	if lifetime := time.Until(issued.ExpiresAt); lifetime < 59*time.Minute || lifetime > time.Hour {
		t.Fatalf("issued access token lifetime = %s, want 1h", lifetime)
	}
	client, err := serverclient.New(baseURL, httpClient, credentials.AccessToken(issued.AccessToken))
	if err != nil {
		t.Fatal(err)
	}
	capabilities, err := client.Capabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if capabilities.Transport.RelayRegion != "test" || capabilities.Transport.Type != serverv1.Tailcat {
		t.Fatalf("capabilities = %#v", capabilities)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !capabilities.DnsReady && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
		capabilities, err = client.Capabilities(context.Background())
		if err != nil {
			t.Fatal(err)
		}
	}
	if !capabilities.DnsReady || len(capabilities.IngressIpv4) != 1 || capabilities.IngressIpv4[0] != "127.0.0.1" || len(capabilities.IngressIpv6) != 0 {
		t.Fatalf("DNS capabilities = %#v", capabilities)
	}
	hostname, err := client.AddHostname(
		context.Background(), serverv1.AddHostnameRequestKindManaged, "route", "standalone-test",
	)
	if err != nil {
		t.Fatal(err)
	}
	if hostnames, err := client.ListHostnames(context.Background()); err != nil || len(hostnames) != 1 || hostnames[0].Id != hostname.Id {
		t.Fatalf("hostnames = %#v, %v", hostnames, err)
	}
	routeToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	setup, err := client.CreateRoute(context.Background(), serverv1.CreateRouteRequest{
		Hostname: "route.example", LocalTarget: "http://127.0.0.1:3000", RouteToken: routeToken.String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if setup.Route.Version != 1 || setup.SessionToken == "" {
		t.Fatalf("setup = %#v", setup)
	}
	if err := client.DeleteRoute(context.Background(), setup.Route.Id); err != nil {
		t.Fatal(err)
	}
	if err := client.RemoveHostname(context.Background(), hostname.Id); err != nil {
		t.Fatal(err)
	}
	if hostnames, err := client.ListHostnames(context.Background()); err != nil || len(hostnames) != 1 ||
		hostnames[0].Id != hostname.Id || hostnames[0].Status != serverv1.HostnameStatusInactive {
		t.Fatalf("hostnames after release = %#v, %v", hostnames, err)
	}
	if err := running.shutdown(time.Second); err != nil {
		t.Fatal(err)
	}
	if err := <-controlDone; err != nil {
		t.Fatal(err)
	}
	if err := <-ingressDone; err != nil {
		t.Fatal(err)
	}
	running = new(daemon)
}

func TestWorkerReconnectsWithFreshOwner(t *testing.T) {
	previousMin, previousMax := workerReconnectMin, workerReconnectMax
	workerReconnectMin, workerReconnectMax = time.Millisecond, 2*time.Millisecond
	t.Cleanup(func() { workerReconnectMin, workerReconnectMax = previousMin, previousMax })

	token, verifier, err := credentials.NewWorkerToken()
	if err != nil {
		t.Fatal(err)
	}
	registry := &workerRegistry{added: make(chan struct{}, 2)}
	hub, err := workercontrol.NewHub(workercontrol.HubConfig{
		Tokens: []credentials.WorkerVerifier{verifier}, Registry: registry,
	})
	if err != nil {
		t.Fatal(err)
	}
	relayData, err := json.Marshal(tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{1: {
		RegionID: 1, RegionCode: "test", Nodes: []*tailcfg.DERPNode{{
			Name: "test", RegionID: 1, HostName: "derp.invalid", DERPPort: 443,
		}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle(workerv1.Endpoint, hub)
	var relayRequests atomic.Int32
	mux.HandleFunc("/v1/transport/relay-map", func(response http.ResponseWriter, _ *http.Request) {
		if relayRequests.Add(1) == 1 {
			response.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write(relayData)
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()
	defer hub.Close()
	previousTransport := http.DefaultTransport
	http.DefaultTransport = server.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = previousTransport })

	ctx, cancel := context.WithCancel(context.Background())
	done, err := startWorker(ctx, config.TNLD{
		Mode: config.TNLDModeWorker, WorkerURL: "wss" + strings.TrimPrefix(server.URL, "https") + workerv1.Endpoint,
		WorkerToken: token.String(), WorkerCapacity: 2, WorkerStreamLimit: 10,
		DrainTimeout: time.Second,
	}, observability.New("worker"))
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	for range 2 {
		select {
		case <-registry.added:
		case <-time.After(5 * time.Second):
			cancel()
			t.Fatal("worker did not reconnect")
		}
	}
	if relayRequests.Load() < 3 {
		t.Fatalf("relay map requests = %d, want at least 3", relayRequests.Load())
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not stop")
	}
}

type workerRegistry struct {
	connections atomic.Int32
	added       chan struct{}
}

func (r *workerRegistry) AddWorker(_ string, worker worker.RouteWorker) error {
	connection := r.connections.Add(1)
	r.added <- struct{}{}
	if connection == 1 {
		go worker.Close()
	}
	return nil
}

func (*workerRegistry) DrainWorker(context.Context, string) error { return nil }

func (*workerRegistry) RemoveWorker(string) {}
