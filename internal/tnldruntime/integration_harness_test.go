package tnldruntime

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/miekg/dns"
	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/routeclient"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/tnldconfig"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

const testLoginToken = "tnl_login_AAECAwQFBgcICQoLDA0ODw.EBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8"
const testClusterSecret = "0123456789abcdef0123456789abcdef"
const testStorageKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

var issuedIntegrationTCPAddresses = struct {
	sync.Mutex
	addresses map[string]struct{}
}{addresses: make(map[string]struct{})}

type integrationProcessOptions struct {
	acmeHTTPClient    *http.Client
	serviceHTTPClient *http.Client
	relayClientTLS    *tls.Config
}

type integrationProcess struct {
	cancel         context.CancelFunc
	done           chan struct{}
	metricsAddress string
	name           string

	mu  sync.Mutex
	err error
}

func startIntegrationProcess(
	t *testing.T,
	cfg tnldconfig.Config,
	acmeHTTPClient, serviceHTTPClient *http.Client,
) *integrationProcess {
	t.Helper()
	return startIntegrationProcessWithOptions(t, cfg, integrationProcessOptions{
		acmeHTTPClient: acmeHTTPClient, serviceHTTPClient: serviceHTTPClient,
	})
}

func startIntegrationProcessWithOptions(
	t *testing.T,
	cfg tnldconfig.Config,
	options integrationProcessOptions,
) *integrationProcess {
	t.Helper()
	if options.acmeHTTPClient == nil {
		options.acmeHTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if options.serviceHTTPClient == nil {
		options.serviceHTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	ctx, cancel := context.WithCancel(context.Background())
	name := string(cfg.Mode)
	if cfg.IngressID != "" {
		name += " " + cfg.IngressID
	}
	if cfg.RelayID != "" {
		name += " " + cfg.RelayID
	}
	process := &integrationProcess{
		cancel: cancel, done: make(chan struct{}), metricsAddress: cfg.MetricsListen, name: name,
	}
	go func() {
		err := serveWithRelayClientTLS(
			ctx, cfg, options.acmeHTTPClient, options.serviceHTTPClient, options.relayClientTLS,
		)
		process.mu.Lock()
		process.err = err
		process.mu.Unlock()
		close(process.done)
	}()
	t.Cleanup(func() {
		process.cancel()
		select {
		case <-process.done:
			if err := process.result(); err != nil {
				t.Errorf("tnld %s process cleanup: %v", process.name, err)
			}
		case <-time.After(10 * time.Second):
			t.Errorf("tnld %s process did not shut down during cleanup", process.name)
		}
	})
	return process
}

func (p *integrationProcess) result() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}

func stopIntegrationProcess(t *testing.T, process *integrationProcess) {
	t.Helper()
	process.cancel()
	waitForIntegrationProcess(t, process)
}

func waitForIntegrationProcess(t *testing.T, process *integrationProcess) {
	t.Helper()
	select {
	case <-process.done:
		if err := process.result(); err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("tnld process did not shut down within its drain deadline")
	}
}

func waitForProcessReady(t *testing.T, process *integrationProcess) {
	t.Helper()
	client := &http.Client{Timeout: time.Second}
	waitForIntegrationCondition(t, 10*time.Second, func() (bool, error) {
		select {
		case <-process.done:
			t.Fatalf("tnld %s process exited before readiness: %v", process.name, process.result())
		default:
		}
		response, err := client.Get("http://" + process.metricsAddress + "/ready")
		if err != nil {
			return false, fmt.Errorf("tnld %s process still running; metrics listener probe: %w", process.name, err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			return false, fmt.Errorf("tnld %s process still running; metrics listener reachable, /ready returned %s", process.name, response.Status)
		}
		return true, nil
	})
}

func waitForIntegrationCondition(t *testing.T, timeout time.Duration, check func() (bool, error)) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		ready, err := check()
		if ready {
			return
		}
		if err != nil {
			lastErr = err
		}
		if time.Now().After(deadline) {
			if lastErr != nil {
				t.Fatalf("integration condition did not become ready: %v", lastErr)
			}
			t.Fatal("integration condition did not become ready")
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func waitForIngressRoutingCurrent(t *testing.T, database *sql.DB, expected int) {
	t.Helper()
	waitForIntegrationCondition(t, 10*time.Second, func() (bool, error) {
		var current, applied int
		err := database.QueryRowContext(t.Context(), `
			SELECT
				count(*),
				count(*) FILTER (WHERE leases.routing_table_revision >= clock.current_revision)
			FROM control.ingress_leases AS leases
			CROSS JOIN control.ingress_routing_table_clock AS clock
			WHERE NOT leases.draining AND leases.lease_expires_at > now()
		`).Scan(&current, &applied)
		return err == nil && current == expected && applied == expected, err
	})
}

func waitForReadyPublisherConnections(
	t *testing.T,
	database *sql.DB,
	routeID string,
	routeVersion uint64,
	expected int,
) {
	t.Helper()
	waitForIntegrationCondition(t, 25*time.Second, func() (bool, error) {
		var ready int
		err := database.QueryRowContext(t.Context(), `
			SELECT count(*)
			FROM control.route_session_connections AS connections
			JOIN control.relay_leases AS leases
			  ON leases.relay_id = connections.connected_relay_id
			 AND leases.relay_run_id = connections.connected_relay_run_id
			 AND leases.relay_lease_revision = connections.connected_relay_lease_revision
			WHERE connections.route_id = $1
			  AND connections.route_version = $2
			  AND connections.state = 'ready'
			  AND NOT leases.draining
			  AND leases.lease_expires_at > now()
		`, routeID, routeVersion).Scan(&ready)
		return err == nil && ready == expected, err
	})
}

func standaloneTestDatabase(t *testing.T) (string, *sql.DB) {
	t.Helper()
	databaseURL := testutil.NewDisposablePostgresDatabaseURL(t, "standalone")
	if err := controlstate.Migrate(t.Context(), databaseURL); err != nil {
		t.Fatal(err)
	}
	return databaseURL, inspectStandaloneTestDatabase(t, databaseURL)
}

func inspectStandaloneTestDatabase(t *testing.T, databaseURL string) *sql.DB {
	t.Helper()
	inspectConfig, err := pgx.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	inspect := stdlib.OpenDB(*inspectConfig)
	t.Cleanup(func() { _ = inspect.Close() })
	return inspect
}

type integrationTestCA struct {
	certificate    *x509.Certificate
	privateKey     *ecdsa.PrivateKey
	certificatePEM []byte
	roots          *x509.CertPool

	mu     sync.Mutex
	serial int64
}

type integrationCertificate struct {
	certificateFile string
	privateKeyFile  string
}

func newIntegrationTestCA(t *testing.T) *integrationTestCA {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "tnl integration root"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:     true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, privateKey.Public(), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	return &integrationTestCA{
		certificate: certificate, privateKey: privateKey, certificatePEM: certificatePEM, roots: roots, serial: 1,
	}
}

func (c *integrationTestCA) issueServer(t *testing.T, hostname string) integrationCertificate {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.serial++
	serial := c.serial
	c.mu.Unlock()
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: hostname}, DNSNames: []string{hostname},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(12 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, c.certificate, privateKey.Public(), c.privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	certificateFile := filepath.Join(directory, "certificate.pem")
	privateKeyFile := filepath.Join(directory, "private-key.pem")
	certificatePEM := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		c.certificatePEM...,
	)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := errors.Join(
		os.WriteFile(certificateFile, certificatePEM, 0o600),
		os.WriteFile(privateKeyFile, privateKeyPEM, 0o600),
	); err != nil {
		t.Fatal(err)
	}
	return integrationCertificate{certificateFile: certificateFile, privateKeyFile: privateKeyFile}
}

type integrationPebble struct {
	directoryURL string
	httpClient   *http.Client
	roots        *x509.CertPool
	apiRootPEM   []byte
	rootPEM      []byte
	logPath      string
}

func startIntegrationPebble(t *testing.T, validationPort int, dnsAddress string) integrationPebble {
	t.Helper()
	pebblePath, err := exec.LookPath("pebble")
	if err != nil {
		t.Fatal("Pebble is required; run mise install")
	}
	apiAddress := unusedTCPAddress(t)
	managementAddress := unusedTCPAddress(t)
	apiCA := newIntegrationTestCA(t)
	apiCertificate := apiCA.issueServer(t, "localhost")
	configuration := map[string]any{"pebble": map[string]any{
		"listenAddress": apiAddress, "managementListenAddress": managementAddress,
		"certificate": apiCertificate.certificateFile, "privateKey": apiCertificate.privateKeyFile,
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
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: apiCA.roots, MinVersion: tls.VersionTLS12}}
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
		roots, rootPEM, ready := integrationPebbleRoots(httpClient, directoryURL, rootURL)
		if ready {
			return integrationPebble{
				directoryURL: directoryURL, httpClient: httpClient, roots: roots,
				apiRootPEM: append([]byte(nil), apiCA.certificatePEM...), rootPEM: rootPEM, logPath: logPath,
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	stop()
	output, _ := os.ReadFile(logPath)
	t.Fatalf("Pebble did not become ready\n%s", output)
	return integrationPebble{}
}

func integrationPebbleRoots(
	client *http.Client,
	directoryURL, rootURL string,
) (*x509.CertPool, []byte, bool) {
	directory, err := client.Get(directoryURL)
	if err != nil {
		return nil, nil, false
	}
	_, readErr := io.Copy(io.Discard, io.LimitReader(directory.Body, 64<<10))
	_ = directory.Body.Close()
	if readErr != nil || directory.StatusCode != http.StatusOK {
		return nil, nil, false
	}
	response, err := client.Get(rootURL)
	if err != nil {
		return nil, nil, false
	}
	rootPEM, readErr := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	_ = response.Body.Close()
	if readErr != nil || response.StatusCode != http.StatusOK {
		return nil, nil, false
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		return nil, nil, false
	}
	return roots, rootPEM, true
}

func startIntegrationDNS(t *testing.T) string {
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

func unusedTCPAddress(t *testing.T) string {
	t.Helper()
	for {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		address := listener.Addr().String()
		issuedIntegrationTCPAddresses.Lock()
		_, issued := issuedIntegrationTCPAddresses.addresses[address]
		if !issued {
			issuedIntegrationTCPAddresses.addresses[address] = struct{}{}
		}
		issuedIntegrationTCPAddresses.Unlock()
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}
		if !issued {
			return address
		}
	}
}

func unusedUDPAddress(t *testing.T) string {
	t.Helper()
	connection, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := connection.LocalAddr().String()
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func redirectIntegrationConnector(address string, connector muxsession.Connector) muxsession.Connector {
	return muxsession.ConnectorFunc(func(ctx context.Context, endpoint muxsession.Endpoint) (muxsession.Session, error) {
		if address == "" {
			return nil, errors.New("integration connector address is empty")
		}
		endpoint.Address = address
		return connector.Connect(ctx, endpoint)
	})
}

func routeIntegrationConnector(addresses map[string]string, connector muxsession.Connector) muxsession.Connector {
	return muxsession.ConnectorFunc(func(ctx context.Context, endpoint muxsession.Endpoint) (muxsession.Session, error) {
		address := addresses[endpoint.Address]
		if address == "" {
			return nil, fmt.Errorf("integration connector has no destination for %q", endpoint.Address)
		}
		endpoint.Address = address
		return connector.Connect(ctx, endpoint)
	})
}

type integrationConnectorStats struct {
	attempts   atomic.Int64
	successful atomic.Int64
}

func observeIntegrationConnector(
	connector muxsession.Connector,
) (muxsession.Connector, *integrationConnectorStats) {
	stats := new(integrationConnectorStats)
	return muxsession.ConnectorFunc(func(ctx context.Context, endpoint muxsession.Endpoint) (muxsession.Session, error) {
		stats.attempts.Add(1)
		session, err := connector.Connect(ctx, endpoint)
		if err == nil {
			stats.successful.Add(1)
		}
		return session, err
	}), stats
}

func disabledIntegrationConnector(message string) (muxsession.Connector, *integrationConnectorStats) {
	return observeIntegrationConnector(muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) {
		return nil, errors.New(message)
	}))
}

func newIntegrationHTTPSClient(
	t *testing.T,
	roots *x509.CertPool,
	address string,
	disableKeepAlives bool,
) (*http.Client, *http.Transport) {
	t.Helper()
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13},
		DisableKeepAlives: disableKeepAlives,
	}
	if address != "" {
		transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return new(net.Dialer).DialContext(ctx, network, address)
		}
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 10 * time.Second}, transport
}

type integrationVisitor struct {
	client    *http.Client
	transport *http.Transport
}

func newIntegrationVisitor(t *testing.T, roots *x509.CertPool, address string) *integrationVisitor {
	t.Helper()
	client, transport := newIntegrationHTTPSClient(t, roots, address, true)
	return &integrationVisitor{client: client, transport: transport}
}

func (v *integrationVisitor) request(request *http.Request) (*http.Response, []byte, error) {
	response, err := v.client.Do(request)
	if err != nil {
		return nil, nil, err
	}
	body, readErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	return response, body, errors.Join(readErr, closeErr)
}

func (v *integrationVisitor) requestURL(method, target string, body io.Reader) (*http.Response, []byte, error) {
	request, err := http.NewRequest(method, target, body)
	if err != nil {
		return nil, nil, err
	}
	return v.request(request)
}

func assertIntegrationRouteCertificate(t *testing.T, response *http.Response, hostname string) {
	t.Helper()
	if response.TLS == nil || len(response.TLS.PeerCertificates) == 0 {
		t.Fatal("visitor response has no verified route TLS certificate")
	}
	if err := response.TLS.PeerCertificates[0].VerifyHostname(hostname); err != nil {
		t.Fatalf("route TLS certificate hostname: %v", err)
	}
}

func integrationPublisherDiagnostics(database *sql.DB, pebbleLogPath string) string {
	var state, message string
	queryErr := database.QueryRow(`
		SELECT state, coalesce(last_error, '')
		FROM control.acme_orders
		ORDER BY created_at DESC
		LIMIT 1
	`).Scan(&state, &message)
	pebbleLog, _ := os.ReadFile(pebbleLogPath)
	return fmt.Sprintf("; latest certificate order = %q, %q, %v\n%s", state, message, queryErr, pebbleLog)
}

type integrationPublishingIdentity struct {
	controlOrigin   string
	hostname        string
	teamID          string
	domainID        string
	membershipID    string
	policyRevision  uint64
	state           *clientstate.Store
	routes          *routeclient.Client
	certificatePlan controlv1.CertificatePlan
	routeScope      controlv1.RouteScope
}

func newIntegrationPublishingIdentity(
	t *testing.T,
	controlOrigin string,
	controlHTTP *http.Client,
	hostnameLabel string,
) *integrationPublishingIdentity {
	t.Helper()
	stateDatabase, err := clientstate.Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stateDatabase.Close() })
	authenticated, err := clientauth.Authenticate(t.Context(), clientauth.Config{
		ServerEndpoint: controlOrigin, State: stateDatabase, HTTPClient: controlHTTP, Diagnostics: io.Discard,
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
	routes, err := routeclient.New(authenticated.Control)
	if err != nil {
		t.Fatal(err)
	}
	publisherState, err := stateDatabase.Server(t.Context(), controlOrigin)
	if err != nil {
		t.Fatal(err)
	}
	hostname := hostnameLabel + "." + membership.ManagedLabel + "." + domain.CanonicalDomain
	return &integrationPublishingIdentity{
		controlOrigin: controlOrigin,
		hostname:      hostname,
		teamID:        team.Id, domainID: domain.Id, membershipID: membership.Id,
		policyRevision: uint64(team.PolicyRevision), state: publisherState, routes: routes,
		routeScope: controlv1.Member,
		certificatePlan: controlv1.CertificatePlan{
			CacheKey: hostname, Scope: hostname, Identifiers: []string{hostname}, ChallengeMethod: controlv1.TlsAlpn01,
		},
	}
}

func (i *integrationPublishingIdentity) publisherConfig(
	target string,
	quicConnector, tcpConnector muxsession.Connector,
) publisher.Config {
	return publisher.Config{
		Control: i.routes, TeamID: i.teamID, DomainID: i.domainID, MembershipID: i.membershipID,
		PolicyRevision: i.policyRevision, RouteScope: i.routeScope,
		Hostname: i.hostname, Target: target, AllowedIPPrefixes: []string{"127.0.0.1/32"},
		State: i.state, QUICConnector: quicConnector, TCPConnector: tcpConnector,
		FallbackDelay: 10 * time.Millisecond, DrainTime: time.Second,
	}
}

type integrationPublisher struct {
	cancel context.CancelFunc
	done   chan struct{}
	events chan publisher.Event

	mu          sync.Mutex
	err         error
	diagnostics func() string
}

func startIntegrationPublisher(
	t *testing.T,
	config publisher.Config,
	diagnostics func() string,
) *integrationPublisher {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	handle := &integrationPublisher{
		cancel: cancel, done: make(chan struct{}), events: make(chan publisher.Event, 32), diagnostics: diagnostics,
	}
	config.Logf = t.Logf
	config.Observe = func(event publisher.Event) error {
		select {
		case handle.events <- event:
			return nil
		case <-ctx.Done():
			return context.Cause(ctx)
		}
	}
	go func() {
		err := publisher.Run(ctx, config)
		handle.mu.Lock()
		handle.err = err
		handle.mu.Unlock()
		close(handle.done)
	}()
	t.Cleanup(func() {
		handle.cancel()
		select {
		case <-handle.done:
			if err := handle.result(); err != nil && !errors.Is(err, context.Canceled) {
				t.Errorf("publisher cleanup: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("publisher did not stop during cleanup")
		}
	})
	return handle
}

func (p *integrationPublisher) result() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}

func waitForPublisherReady(t *testing.T, handle *integrationPublisher) publisher.Event {
	t.Helper()
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()
	for {
		select {
		case event := <-handle.events:
			if event.Type == publisher.EventReady {
				return event
			}
		case <-handle.done:
			diagnostics := ""
			if handle.diagnostics != nil {
				diagnostics = handle.diagnostics()
			}
			t.Fatalf("publisher stopped before becoming ready: %v%s", handle.result(), diagnostics)
		case <-timer.C:
			t.Fatal("publisher did not become ready")
		}
	}
}

func stopIntegrationPublisher(t *testing.T, handle *integrationPublisher) {
	t.Helper()
	handle.cancel()
	select {
	case <-handle.done:
		if err := handle.result(); err != nil && !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("publisher did not stop")
	}
}
