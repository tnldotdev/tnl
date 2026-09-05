package tnldruntime

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/routeclient"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestIntegrationStandalonePublishAndVisit(t *testing.T) {
	directURL := os.Getenv("TNL_TEST_POSTGRES_URL")
	if directURL == "" {
		t.Skip("TNL_TEST_POSTGRES_URL is not set")
	}
	databaseURL, inspect := standaloneTestDatabase(t, directURL)
	publicAddress := unusedTCPAddress(t)
	relayUDPAddress := unusedUDPAddress(t)
	dnsAddress := startStandalonePublishDNS(t)
	pebble := startStandalonePublishPebble(t, integrationPort(t, publicAddress), dnsAddress)

	const serverDomain = "integration.test"
	const managedDomain = "routes.integration.test"
	controlHostname := "control." + serverDomain
	cfg := config.TNLD{
		Mode: config.TNLDModeStandalone, DatabaseURL: databaseURL, MetricsListen: unusedTCPAddress(t),
		ControlListen: unusedTCPAddress(t), PrivateControlListen: unusedTCPAddress(t), IngressListen: publicAddress,
		RelayTCPListen: unusedTCPAddress(t), RelayUDPListen: relayUDPAddress, InternalRelayListen: unusedTCPAddress(t),
		ServerDomain: serverDomain, ManagedDeploymentDomain: managedDomain,
		ACMEDirectoryURL: pebble.directoryURL, ACMEEmail: "integration@example.test",
		ACMEAcceptTerms: true, ACMEProfile: "tlsserver", LoginToken: testLoginToken,
		StorageKey:          testStorageKey,
		AccessTokenLifetime: 5 * time.Minute, RefreshTokenLifetime: time.Hour,
		PublicConnectionLimit: 100, RouteConnectionLimit: 10, PublisherConnectionLimit: 10,
		RelayStreamCapacity: 100, QUICMaxIncomingStreams: 100, QUICIdleTimeout: time.Minute,
		TunnelFallbackDelay: 10 * time.Millisecond, IngressLeaseDuration: 5 * time.Second,
		RelayLeaseDuration: 5 * time.Second, LeaseRenewalInterval: time.Second,
		ControlRetryInterval: 10 * time.Millisecond, RoutingTableWait: time.Second, DrainTimeout: 3 * time.Second,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	process := startStandalonePublishProcess(t, cfg, pebble)
	waitForProcessReady(t, process.done, cfg.MetricsListen)

	controlTransport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pebble.roots, MinVersion: tls.VersionTLS13},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return new(net.Dialer).DialContext(ctx, network, publicAddress)
		},
	}
	t.Cleanup(controlTransport.CloseIdleConnections)
	controlHTTP := &http.Client{Transport: controlTransport, Timeout: 10 * time.Second}
	controlOrigin := "https://" + controlHostname
	state, err := clientstate.Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	authenticated, err := clientauth.Authenticate(t.Context(), clientauth.Config{
		ServerEndpoint: controlOrigin, State: state, HTTPClient: controlHTTP, Diagnostics: io.Discard,
		ForceLoginToken: true,
		LoginToken: func() (credentials.LoginToken, error) {
			return credentials.LoginToken(testLoginToken), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := authenticated.Authority.IdentityContext(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	team, err := authenticated.Authority.GetTeam(t.Context(), identity.PersonalTeamId)
	if err != nil {
		t.Fatal(err)
	}
	domainPage, err := authenticated.Authority.ListTeamDomains(t.Context(), team.Id)
	if err != nil {
		t.Fatal(err)
	}
	var membership authorityv1.Membership
	for _, candidate := range identity.Memberships {
		if candidate.TeamId == team.Id {
			membership = candidate
			break
		}
	}
	if membership.Id == "" {
		t.Fatal("personal team membership is missing")
	}
	var domain authorityv1.Domain
	for _, candidate := range domainPage.Domains {
		if candidate.Id == team.DefaultDomainId {
			domain = candidate
			break
		}
	}
	if domain.Id == "" || domain.State != authorityv1.DomainStateReady {
		t.Fatalf("default domain is not ready: %#v", domain)
	}
	routeHostname := "visit." + membership.ManagedLabel + "." + domain.CanonicalDomain

	type targetRequest struct {
		host string
		path string
	}
	targetRequests := make(chan targetRequest, 1)
	target := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		select {
		case targetRequests <- targetRequest{host: request.Host, path: request.URL.RequestURI()}:
		default:
		}
		response.Header().Set("X-Tnl-Integration", "publisher")
		_, _ = io.WriteString(response, "visitor reached local service")
	}))
	t.Cleanup(target.Close)

	routes, err := routeclient.New(authenticated.Control)
	if err != nil {
		t.Fatal(err)
	}
	publisherState, err := state.Server(t.Context(), controlOrigin)
	if err != nil {
		t.Fatal(err)
	}
	relayTLS := &tls.Config{RootCAs: pebble.roots, MinVersion: tls.VersionTLS13}
	quicConnector := redirectIntegrationConnector(
		relayUDPAddress,
		muxsession.QUICConnector{TLSConfig: relayTLS},
	)
	tcpConnector := redirectIntegrationConnector(
		publicAddress,
		muxsession.TLSYamuxConnector{TLSConfig: relayTLS},
	)
	publisherEvents := make(chan publisher.Event, 8)
	publisherContext, cancelPublisher := context.WithCancel(t.Context())
	publisherDone := make(chan error, 1)
	go func() {
		publisherDone <- publisher.Run(publisherContext, publisher.Config{
			Control: routes, TeamID: team.Id, DomainID: domain.Id, MembershipID: membership.Id,
			PolicyRevision: uint64(team.PolicyRevision), RouteScope: controlv1.Member,
			CertificatePlan: controlv1.CertificatePlan{
				CacheKey: routeHostname, Scope: routeHostname, Identifiers: []string{routeHostname},
				ChallengeMethod: controlv1.TlsAlpn01,
			},
			Hostname: routeHostname, Target: target.URL, AllowedIPPrefixes: []string{"127.0.0.1/32"},
			State: publisherState, QUICConnector: quicConnector, TCPConnector: tcpConnector,
			FallbackDelay: 10 * time.Millisecond, DrainTime: time.Second, Logf: t.Logf,
			Observe: func(event publisher.Event) error {
				publisherEvents <- event
				return nil
			},
		})
	}()
	publisherStopped := false
	t.Cleanup(func() {
		cancelPublisher()
		if !publisherStopped {
			select {
			case <-publisherDone:
			case <-time.After(10 * time.Second):
			}
		}
	})

	readyDeadline := time.After(30 * time.Second)
	for {
		select {
		case event := <-publisherEvents:
			if event.Type == publisher.EventReady {
				if event.Hostname != routeHostname || event.PublicURL != "https://"+routeHostname {
					t.Fatalf("publisher ready event = %#v", event)
				}
				goto publisherReady
			}
		case err := <-publisherDone:
			publisherStopped = true
			var issuanceState, issuanceError string
			queryErr := inspect.QueryRowContext(t.Context(), `
				SELECT state, coalesce(last_error, '')
				FROM control.acme_orders
				ORDER BY created_at DESC
				LIMIT 1
			`).Scan(&issuanceState, &issuanceError)
			pebbleLog, _ := os.ReadFile(pebble.logPath)
			t.Fatalf(
				"publisher stopped before becoming ready: %v; latest certificate order = %q, %q, %v\n%s",
				err, issuanceState, issuanceError, queryErr, pebbleLog,
			)
		case <-readyDeadline:
			t.Fatal("publisher did not become ready")
		}
	}

publisherReady:
	visitorTransport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pebble.roots, MinVersion: tls.VersionTLS13},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return new(net.Dialer).DialContext(ctx, network, publicAddress)
		},
	}
	t.Cleanup(visitorTransport.CloseIdleConnections)
	visitor := &http.Client{Transport: visitorTransport, Timeout: 3 * time.Second}
	visitorURL := "https://" + routeHostname + "/through-tnl?source=integration"
	var visitorErr error
	visitorDeadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(visitorDeadline) {
		response, err := visitor.Get(visitorURL)
		if err != nil {
			visitorErr = err
			time.Sleep(50 * time.Millisecond)
			continue
		}
		body, readErr := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if readErr != nil {
			visitorErr = readErr
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if response.StatusCode != http.StatusOK || string(body) != "visitor reached local service" ||
			response.Header.Get("X-Tnl-Integration") != "publisher" {
			t.Fatalf("visitor response = %s, headers %#v, body %q", response.Status, response.Header, body)
		}
		if response.TLS == nil || len(response.TLS.PeerCertificates) == 0 {
			t.Fatal("visitor response has no verified route TLS certificate")
		}
		if err := response.TLS.PeerCertificates[0].VerifyHostname(routeHostname); err != nil {
			t.Fatalf("route TLS certificate hostname: %v", err)
		}
		visitorErr = nil
		break
	}
	if visitorErr != nil {
		t.Fatalf("visit published route: %v", visitorErr)
	}
	select {
	case request := <-targetRequests:
		if request.host != routeHostname || request.path != "/through-tnl?source=integration" {
			t.Fatalf("local service request = %#v", request)
		}
	case <-time.After(time.Second):
		t.Fatal("local service did not observe the visitor request")
	}

	cancelPublisher()
	select {
	case err := <-publisherDone:
		publisherStopped = true
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("stop publisher: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("publisher did not stop")
	}
	visitorTransport.CloseIdleConnections()
	controlTransport.CloseIdleConnections()
	stopIntegrationProcess(t, process)
}

type standalonePublishPebble struct {
	directoryURL string
	httpClient   *http.Client
	roots        *x509.CertPool
	logPath      string
}

func startStandalonePublishPebble(
	t *testing.T,
	validationPort int,
	dnsAddress string,
) standalonePublishPebble {
	t.Helper()
	pebblePath, err := exec.LookPath("pebble")
	if err != nil {
		t.Fatal("Pebble is required; run mise install")
	}
	apiAddress := unusedTCPAddress(t)
	managementAddress := unusedTCPAddress(t)
	certificateFile, privateKeyFile, apiRoots := standaloneTestCertificate(t, "localhost")
	configuration := map[string]any{"pebble": map[string]any{
		"listenAddress": apiAddress, "managementListenAddress": managementAddress,
		"certificate": certificateFile, "privateKey": privateKeyFile,
		"httpPort": integrationPort(t, unusedTCPAddress(t)), "tlsPort": validationPort,
		"ocspResponderURL": "", "externalAccountBindingRequired": false,
		"domainBlocklist": []string{}, "retryAfter": map[string]int{"authz": 0, "order": 0},
		"keyAlgorithm": "ecdsa", "profiles": map[string]any{
			"default":   map[string]any{"description": "integration", "validityPeriod": 3600},
			"tlsserver": map[string]any{"description": "tnl route TLS", "validityPeriod": 3600},
		},
	}}
	encoded, err := json.Marshal(configuration)
	if err != nil {
		t.Fatal(err)
	}
	configurationFile := filepath.Join(t.TempDir(), "pebble.json")
	if err := os.WriteFile(configurationFile, encoded, 0o600); err != nil {
		t.Fatal(err)
	}

	logPath := filepath.Join(t.TempDir(), "pebble.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	processContext, cancelProcess := context.WithCancel(context.Background())
	command := exec.CommandContext(
		processContext, pebblePath, "-config", configurationFile, "-strict=false", "-dnsserver", dnsAddress,
	)
	command.Env = append(os.Environ(),
		"PEBBLE_AUTHZREUSE=0",
		"PEBBLE_VA_ALWAYS_VALID=0",
		"PEBBLE_VA_NOSLEEP=1",
		"PEBBLE_WFE_NONCEREJECT=0",
	)
	command.Stdout, command.Stderr = logFile, logFile
	if err := command.Start(); err != nil {
		cancelProcess()
		_ = logFile.Close()
		t.Fatal(err)
	}
	processDone := make(chan error, 1)
	go func() { processDone <- command.Wait() }()
	processStopped := false
	stop := func() {
		if processStopped {
			return
		}
		cancelProcess()
		select {
		case <-processDone:
		case <-time.After(5 * time.Second):
			_ = command.Process.Kill()
			<-processDone
		}
		_ = logFile.Close()
		processStopped = true
	}
	t.Cleanup(stop)

	_, apiPort, err := net.SplitHostPort(apiAddress)
	if err != nil {
		stop()
		t.Fatal(err)
	}
	_, managementPort, err := net.SplitHostPort(managementAddress)
	if err != nil {
		stop()
		t.Fatal(err)
	}
	directoryURL := "https://localhost:" + apiPort + "/dir"
	rootURL := "https://localhost:" + managementPort + "/roots/0"
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: apiRoots, MinVersion: tls.VersionTLS12}}
	httpClient := &http.Client{Transport: transport, Timeout: time.Second}
	t.Cleanup(transport.CloseIdleConnections)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-processDone:
			processStopped = true
			cancelProcess()
			_ = logFile.Close()
			output, _ := os.ReadFile(logPath)
			t.Fatalf("Pebble exited during startup: %v\n%s", err, output)
		default:
		}
		roots, ready := standalonePublishPebbleRoots(httpClient, directoryURL, rootURL)
		if ready {
			return standalonePublishPebble{
				directoryURL: directoryURL, httpClient: httpClient, roots: roots, logPath: logPath,
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	stop()
	output, _ := os.ReadFile(logPath)
	t.Fatalf("Pebble did not become ready\n%s", output)
	return standalonePublishPebble{}
}

func standalonePublishPebbleRoots(client *http.Client, directoryURL, rootURL string) (*x509.CertPool, bool) {
	directory, err := client.Get(directoryURL)
	if err != nil {
		return nil, false
	}
	_, readErr := io.Copy(io.Discard, io.LimitReader(directory.Body, 64<<10))
	_ = directory.Body.Close()
	if readErr != nil || directory.StatusCode != http.StatusOK {
		return nil, false
	}
	response, err := client.Get(rootURL)
	if err != nil {
		return nil, false
	}
	rootPEM, readErr := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	_ = response.Body.Close()
	if readErr != nil || response.StatusCode != http.StatusOK {
		return nil, false
	}
	roots := x509.NewCertPool()
	return roots, roots.AppendCertsFromPEM(rootPEM)
}

func startStandalonePublishDNS(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	handler := dns.HandlerFunc(func(response dns.ResponseWriter, request *dns.Msg) {
		message := new(dns.Msg)
		message.SetReply(request)
		message.Authoritative = true
		for _, question := range request.Question {
			if question.Qtype == dns.TypeA {
				message.Answer = append(message.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1},
					A:   net.IPv4(127, 0, 0, 1),
				})
			}
		}
		_ = response.WriteMsg(message)
	})
	server := &dns.Server{Listener: listener, Handler: handler}
	done := make(chan error, 1)
	go func() { done <- server.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = server.Shutdown()
		select {
		case <-done:
		case <-time.After(time.Second):
		}
	})
	return listener.Addr().String()
}

func integrationPort(t *testing.T, address string) int {
	t.Helper()
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	value, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func redirectIntegrationConnector(address string, connector muxsession.Connector) muxsession.Connector {
	return muxsession.ConnectorFunc(func(ctx context.Context, endpoint muxsession.Endpoint) (muxsession.Session, error) {
		if address == "" {
			return nil, fmt.Errorf("integration connector address is empty")
		}
		endpoint.Address = address
		return connector.Connect(ctx, endpoint)
	})
}

func startStandalonePublishProcess(
	t *testing.T,
	cfg config.TNLD,
	pebble standalonePublishPebble,
) *integrationProcess {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	process := &integrationProcess{cancel: cancel, done: make(chan error, 1), metricsAddress: cfg.MetricsListen}
	go func() {
		process.done <- serveWithRelayClientTLS(
			ctx,
			cfg,
			pebble.httpClient,
			&http.Client{Timeout: 10 * time.Second},
			&tls.Config{RootCAs: pebble.roots, MinVersion: tls.VersionTLS13},
		)
	}()
	t.Cleanup(cancel)
	return process
}
