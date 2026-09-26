package tnldruntime

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/tnldconfig"
)

const testLoginToken = "tnl_login_AAECAwQFBgcICQoLDA0ODw.EBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8"
const testClusterSecret = "0123456789abcdef0123456789abcdef"
const testStorageKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

type integrationProcessOptions struct {
	acmeHTTPClient    *http.Client
	serviceHTTPClient *http.Client
	relayClientTLS    *tls.Config
	owner             *runtimeTopology
}

type integrationProcess struct {
	cancel         context.CancelFunc
	done           chan struct{}
	metricsAddress string
	name           string
	mu             sync.Mutex
	err            error
}

// runtimeTopology owns all incarnations, including retired and replacement
// processes. Cleanup order follows dependencies rather than start chronology.
type runtimeTopology struct {
	directory  string
	afterStop  []func()
	publishers []*integrationPublisher
	ingress    []*integrationProcess
	relays     []*integrationProcess
	controls   []*integrationProcess
}

func newRuntimeTopology(t *testing.T) *runtimeTopology {
	t.Helper()
	f := &runtimeTopology{directory: t.TempDir()}
	t.Cleanup(func() {
		for _, publisher := range f.publishers {
			if err := publisher.stop(); err != nil {
				t.Errorf("publisher cleanup: %v", err)
			}
		}
		for _, processes := range [][]*integrationProcess{f.ingress, f.relays, f.controls} {
			for _, process := range processes {
				process.cancel()
			}
			for _, process := range processes {
				if err := process.wait(); err != nil {
					t.Errorf("tnld %s cleanup: %v", process.name, err)
				}
			}
		}
		for _, close := range f.afterStop {
			close()
		}
	})
	return f
}

func (f *runtimeTopology) cleanupResource(t *testing.T, close func()) {
	t.Helper()
	if f == nil {
		t.Cleanup(close)
	} else {
		f.afterStop = append(f.afterStop, close)
	}
}

func cleanupIntegrationHTTPServer(t *testing.T, server *httptest.Server, owner *runtimeTopology) {
	t.Helper()
	owner.cleanupResource(t, func() {
		// Cancel active handlers before joining; httptest.Close alone can wait
		// forever on an interrupted scenario's stream or gated request.
		server.CloseClientConnections()
		done := make(chan struct{})
		go func() { server.Close(); close(done) }()
		if err := waitForDoneWithin(done, 5*time.Second); err != nil {
			t.Errorf("HTTP fixture did not stop: %v", err)
		}
	})
}

func (f *runtimeTopology) own(role tnldconfig.Role, p *integrationProcess) {
	switch role {
	case tnldconfig.RoleIngress:
		f.ingress = append(f.ingress, p)
	case tnldconfig.RoleRelay:
		f.relays = append(f.relays, p)
	default:
		f.controls = append(f.controls, p)
	}
}

func startIntegrationProcess(t *testing.T, cfg tnldconfig.Config, acmeHTTPClient, serviceHTTPClient *http.Client) *integrationProcess {
	t.Helper()
	return startIntegrationProcessWithOptions(t, cfg, integrationProcessOptions{
		acmeHTTPClient: acmeHTTPClient, serviceHTTPClient: serviceHTTPClient,
	})
}

func startIntegrationProcessWithOptions(t *testing.T, cfg tnldconfig.Config, options integrationProcessOptions) *integrationProcess {
	t.Helper()
	if options.acmeHTTPClient == nil {
		options.acmeHTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if options.serviceHTTPClient == nil {
		options.serviceHTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	ctx, cancel := context.WithCancel(context.Background())
	name := string(cfg.Role)
	if cfg.IngressID != "" {
		name += " " + cfg.IngressID
	}
	if cfg.RelayID != "" {
		name += " " + cfg.RelayID
	}
	process := &integrationProcess{cancel: cancel, done: make(chan struct{}), metricsAddress: cfg.MetricsListen, name: name}
	if options.owner != nil {
		options.owner.own(cfg.Role, process)
	} else {
		t.Cleanup(func() {
			process.cancel()
			if err := process.wait(); err != nil {
				t.Errorf("tnld %s cleanup: %v", process.name, err)
			}
		})
	}
	go func() {
		err := serveWithRelayClientTLS(ctx, cfg, options.acmeHTTPClient, options.serviceHTTPClient, options.relayClientTLS)
		process.mu.Lock()
		process.err = err
		process.mu.Unlock()
		close(process.done)
	}()
	return process
}

func (p *integrationProcess) result() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}

func (p *integrationProcess) wait() error {
	return p.waitWithin(10 * time.Second)
}

func (p *integrationProcess) waitWithin(timeout time.Duration) error {
	if err := waitForDoneWithin(p.done, timeout); err != nil {
		return fmt.Errorf("process did not shut down within its drain deadline: %w", err)
	}
	return p.result()
}

func stopIntegrationProcess(t *testing.T, process *integrationProcess) {
	t.Helper()
	process.cancel()
	waitForIntegrationProcess(t, process)
}

func stopIntegrationProcessWithin(t *testing.T, process *integrationProcess, timeout time.Duration) {
	t.Helper()
	process.cancel()
	if err := process.waitWithin(timeout); err != nil {
		t.Fatal(err)
	}
}

func waitForIntegrationProcess(t *testing.T, process *integrationProcess) {
	t.Helper()
	if err := process.wait(); err != nil {
		t.Fatal(err)
	}
}

func waitForProcessReady(t *testing.T, process *integrationProcess) {
	t.Helper()
	client := &http.Client{Timeout: time.Second}
	waitForIntegrationCondition(t, 10*time.Second, func(ctx context.Context) (bool, error) {
		select {
		case <-process.done:
			t.Fatalf("tnld %s process exited before readiness: %v", process.name, process.result())
		default:
		}
		response, err := integrationGET(ctx, client, "http://"+process.metricsAddress+"/ready")
		if err != nil {
			return false, fmt.Errorf("tnld %s process still running; metrics listener probe: %w", process.name, err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			return false, fmt.Errorf("tnld %s process still running; /ready returned %s", process.name, response.Status)
		}
		return true, nil
	})
}

func waitForIntegrationCondition(t *testing.T, timeout time.Duration, check func(context.Context) (bool, error)) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()
	if err := pollCondition(ctx, 25*time.Millisecond, 2*time.Second, check); err != nil {
		t.Fatalf("integration condition did not become ready: %v", err)
	}
}

func integrationGET(ctx context.Context, client *http.Client, url string) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return client.Do(request)
}

// For individual assertions outside a polling loop. A fresh deadline belongs
// to each operation, and cancellation is registered even if Scan/Fatal exits.
func integrationOperationContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func waitUntilIntegrationTime(t *testing.T, at time.Time) {
	t.Helper()
	delay := time.Until(at)
	if delay <= 0 {
		return
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-t.Context().Done():
		t.Fatal(context.Cause(t.Context()))
	}
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

var issuedIntegrationTCPAddresses = struct {
	sync.Mutex
	addresses map[string]struct{}
}{addresses: make(map[string]struct{})}

// These probes do not reserve addresses. tnld configuration rejects port 0 and
// tnld/Pebble accept address strings, not inherited listeners. Harness-owned
// HTTP/DNS servers instead retain :0 listeners and use their actual addresses.
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
		issuedIntegrationTCPAddresses.addresses[address] = struct{}{}
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

func splitTestConfig(role tnldconfig.Role, metricsAddress string) tnldconfig.Config {
	return tnldconfig.Config{
		Role: role, MetricsListen: metricsAddress,
		PublicURLCertificateWorkers: 4,
		SourceConnectionRate:        50, SourceConnectionBurst: 200,
		ClientHelloConnectionLimit: 1024, ChallengeConnectionLimit: 1024, ChallengeHostnameConnectionLimit: 8,
		StandaloneControlConnectionLimit: 1024, StandaloneRelayConnectionLimit: 4096,
		VisitorConnectionLimit: 100, PublicURLConnectionLimit: 10, PublisherConnectionLimit: 10,
		RelayStreamCapacity: 100, QUICMaxIncomingStreams: 100, QUICIdleTimeout: time.Minute,
		IngressLeaseDuration: 2 * time.Second,
		RelayLeaseDuration:   2 * time.Second, LeaseRenewalInterval: 500 * time.Millisecond,
		ControlRetryInterval: 50 * time.Millisecond, RoutingTableWait: time.Second, DrainTimeout: time.Second,
	}
}

func splitTestRelayConfig(t *testing.T, controlHostname, relayServiceID, relayID, certificateFile, privateKeyFile string) tnldconfig.Config {
	t.Helper()
	cfg := splitTestConfig(tnldconfig.RoleRelay, unusedTCPAddress(t))
	cfg.ControlHostname = controlHostname
	cfg.ClusterSecret = testClusterSecret
	cfg.RelayServiceID = relayServiceID
	cfg.RelayID = relayID
	cfg.RelayAddress = relayServiceID + ".127.0.0.1.nip.io:443"
	cfg.RelayTLSCertificateFile = certificateFile
	cfg.RelayTLSPrivateKeyFile = privateKeyFile
	cfg.RelayTCPListen = unusedTCPAddress(t)
	cfg.RelayUDPListen = unusedUDPAddress(t)
	cfg.InternalRelayListen = unusedTCPAddress(t)
	cfg.InternalRelayAddress = cfg.InternalRelayListen
	return cfg
}

func splitTestServiceHTTPClient(t *testing.T, roots *x509.CertPool, controlAddress string) *http.Client {
	t.Helper()
	dialer := new(net.Dialer)
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, controlAddress)
		},
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}
}
