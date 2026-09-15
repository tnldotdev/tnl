package tnldruntime

import (
	"bufio"
	"bytes"
	"context"
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
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/testutil"
)

type integrationBinaryStandalone struct {
	repositoryRoot string
	tnlPath        string
	databaseURL    string
	stateDirectory string
	environment    []string
	server         *integrationBinaryProcess
	pebble         integrationPebble
}

func startIntegrationBinaryStandalone(t *testing.T) *integrationBinaryStandalone {
	t.Helper()
	if os.Getenv("TNL_TEST_BINARY_INTEGRATION") != "1" {
		t.Skip("TNL_TEST_BINARY_INTEGRATION=1 is required")
	}
	assertIntegrationPort443Available(t)
	testutil.PostgresURL(t)
	if runtime.GOOS == "darwin" {
		t.Fatal("binary integration requires a disposable Linux environment: macOS binaries use the login Keychain and do not use SSL_CERT_FILE for system trust; in-process keyring mocks cannot isolate these subprocesses")
	}
	repositoryRoot := integrationRepositoryRoot(t)
	binaryDirectory := t.TempDir()
	tnldPath := filepath.Join(binaryDirectory, "tnld")
	tnlPath := filepath.Join(binaryDirectory, "tnl")
	buildIntegrationBinary(t, repositoryRoot, tnldPath, "./cmd/tnld")
	buildIntegrationBinary(t, repositoryRoot, tnlPath, "./cmd/tnl")

	databaseURL := testutil.NewDisposablePostgresDatabaseURL(t, "standalone")
	trustRoot := newIntegrationTestCA(t)
	serverCertificate := trustRoot.issueServer(t, "*.127.0.0.1.nip.io")
	pebble := startIntegrationPebble(t, 443, startIntegrationDNS(t))
	trustFile := filepath.Join(t.TempDir(), "integration-roots.pem")
	trustedCertificates := append([]byte{}, trustRoot.certificatePEM...)
	trustedCertificates = append(trustedCertificates, pebble.apiRootPEM...)
	trustedCertificates = append(trustedCertificates, pebble.rootPEM...)
	if err := os.WriteFile(trustFile, trustedCertificates, 0o600); err != nil {
		t.Fatal(err)
	}

	migrateEnvironment := integrationBinaryEnvironment(map[string]string{
		"TNLD_DATABASE_DIRECT_URL": databaseURL,
	})
	runIntegrationBinaryCommand(t, repositoryRoot, migrateEnvironment, tnldPath, "migrate")
	metricsAddress := unusedTCPAddress(t)
	serveEnvironment := integrationBinaryEnvironment(map[string]string{
		"SSL_CERT_FILE":                     trustFile,
		"TNLD_ACCESS_TOKEN_LIFETIME":        "5m",
		"TNLD_ACME_ACCEPT_TERMS":            "true",
		"TNLD_ACME_DIRECTORY_URL":           pebble.directoryURL,
		"TNLD_ACME_EMAIL":                   "integration@example.test",
		"TNLD_ACME_PROFILE":                 "tlsserver",
		"TNLD_CONTROL_LISTEN":               "127.0.0.1:443",
		"TNLD_CONTROL_TLS_CERTIFICATE_FILE": serverCertificate.certificateFile,
		"TNLD_CONTROL_TLS_PRIVATE_KEY_FILE": serverCertificate.privateKeyFile,
		"TNLD_DATABASE_URL":                 databaseURL,
		"TNLD_DRAIN_TIMEOUT":                "1s",
		"TNLD_INGRESS_LEASE_DURATION":       "5s",
		"TNLD_INGRESS_LISTEN":               "127.0.0.1:443",
		"TNLD_INTERNAL_RELAY_LISTEN":        unusedTCPAddress(t),
		"TNLD_LEASE_RENEWAL_INTERVAL":       "500ms",
		"TNLD_LOGIN_TOKEN":                  testLoginToken,
		"TNLD_MANAGED_DEPLOYMENT_DOMAIN":    "routes.127.0.0.1.nip.io",
		"TNLD_METRICS_LISTEN":               metricsAddress,
		"TNLD_MODE":                         "standalone",
		"TNLD_PRIVATE_CONTROL_LISTEN":       unusedTCPAddress(t),
		"TNLD_REFRESH_TOKEN_LIFETIME":       "1h",
		"TNLD_RELAY_LEASE_DURATION":         "5s",
		"TNLD_RELAY_TCP_LISTEN":             "127.0.0.1:443",
		"TNLD_RELAY_TLS_CERTIFICATE_FILE":   serverCertificate.certificateFile,
		"TNLD_RELAY_TLS_PRIVATE_KEY_FILE":   serverCertificate.privateKeyFile,
		"TNLD_RELAY_UDP_LISTEN":             "127.0.0.1:443",
		"TNLD_ROUTING_TABLE_WAIT":           "1s",
		"TNLD_SERVER_DOMAIN":                "127.0.0.1.nip.io",
		"TNLD_STORAGE_KEY":                  testStorageKey,
		"TNLD_TUNNEL_FALLBACK_DELAY":        "10ms",
	})
	server := startIntegrationBinaryProcess(t, repositoryRoot, serveEnvironment, tnldPath, "serve")
	waitForIntegrationBinaryReady(t, server, metricsAddress, databaseURL)

	stateDirectory := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(stateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	clientEnvironment := integrationBinaryEnvironment(map[string]string{
		"SSL_CERT_FILE":    trustFile,
		"TNL_LOGIN_TOKEN":  testLoginToken,
		"TNL_NO_TELEMETRY": "1",
		"TNL_SERVER":       "https://control.127.0.0.1.nip.io",
		"TNL_STATE_DIR":    stateDirectory,
	})
	runIntegrationBinaryCommand(t, repositoryRoot, clientEnvironment, tnlPath, "login", "--token")
	// The login credential is not needed by publishers or their development children.
	for index, value := range clientEnvironment {
		if strings.HasPrefix(value, "TNL_LOGIN_TOKEN=") {
			clientEnvironment = append(clientEnvironment[:index], clientEnvironment[index+1:]...)
			break
		}
	}
	return &integrationBinaryStandalone{
		repositoryRoot: repositoryRoot, tnlPath: tnlPath, databaseURL: databaseURL,
		stateDirectory: stateDirectory, environment: clientEnvironment, server: server, pebble: pebble,
	}
}

func TestIntegrationBinaryStandalonePublish(t *testing.T) {
	fixture := startIntegrationBinaryStandalone(t)
	target := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("X-Tnl-Integration", "binary")
		_, _ = io.WriteString(response, request.URL.RequestURI())
	}))
	t.Cleanup(target.Close)
	publish := startIntegrationBinaryPublish(t, fixture.repositoryRoot, fixture.environment, fixture.tnlPath,
		"--no-config", "publish", target.URL, "--host", "binary.routes.127.0.0.1.nip.io",
		"--allow-ip", "127.0.0.1/32", "--output", "ndjson",
	)
	ready := waitForIntegrationBinaryPublishEvent(t, publish, "ready", 45*time.Second)
	if ready.SchemaVersion != 1 || ready.URL != "https://binary.routes.127.0.0.1.nip.io" || ready.RouteVersion != 1 {
		t.Fatalf("binary ready event = %#v", ready)
	}
	visitor := newIntegrationVisitor(t, fixture.pebble.roots, "")
	var response *http.Response
	var body []byte
	var err error
	deadline := time.Now().Add(10 * time.Second)
	for {
		response, body, err = visitor.requestURL(http.MethodGet, ready.URL+"/binary?source=integration", nil)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("binary visitor request: %v\ntnl publish stderr:\n%s\ntnld output:\n%s", err, publish.stderr.String(), fixture.server.output.String())
		}
		time.Sleep(25 * time.Millisecond)
	}
	if response.StatusCode != http.StatusOK || string(body) != "/binary?source=integration" ||
		response.Header.Get("X-Tnl-Integration") != "binary" {
		t.Fatalf("binary visitor response = %s, headers %#v, body %q", response.Status, response.Header, body)
	}
	assertIntegrationRouteCertificate(t, response, "binary.routes.127.0.0.1.nip.io")
	stopIntegrationBinaryPublish(t, publish)
	stopped := waitForIntegrationBinaryPublishEvent(t, publish, "stopped", 10*time.Second)
	if stopped.Reason != "canceled" || stopped.TunnelID != ready.TunnelID {
		t.Fatalf("binary stopped event = %#v after ready %#v", stopped, ready)
	}
	waitForIntegrationBinaryPublish(t, publish)
}

type synchronizedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *synchronizedBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(data)
}

func (b *synchronizedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

type integrationBinaryProcess struct {
	command      *exec.Cmd
	done         chan struct{}
	output       synchronizedBuffer
	wantExitCode int

	mu  sync.Mutex
	err error
}

func startIntegrationBinaryProcess(
	t *testing.T,
	directory string,
	environment []string,
	name string,
	arguments ...string,
) *integrationBinaryProcess {
	t.Helper()
	process := &integrationBinaryProcess{done: make(chan struct{})}
	process.command = exec.Command(name, arguments...)
	process.command.Dir = directory
	process.command.Env = environment
	process.command.WaitDelay = time.Second
	process.command.Stdout = &process.output
	process.command.Stderr = &process.output
	if err := process.command.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		err := process.command.Wait()
		process.mu.Lock()
		process.err = err
		process.mu.Unlock()
		close(process.done)
	}()
	t.Cleanup(func() { stopIntegrationBinaryProcess(t, process) })
	return process
}

func (p *integrationBinaryProcess) result() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}

func stopIntegrationBinaryProcess(t *testing.T, process *integrationBinaryProcess) {
	t.Helper()
	select {
	case <-process.done:
		assertIntegrationBinaryProcessResult(t, process)
		return
	default:
	}
	if err := process.command.Process.Signal(os.Interrupt); err != nil && !errors.Is(err, os.ErrProcessDone) {
		t.Errorf("interrupt binary process: %v", err)
	}
	select {
	case <-process.done:
		assertIntegrationBinaryProcessResult(t, process)
	case <-time.After(15 * time.Second):
		_ = process.command.Process.Kill()
		<-process.done
		t.Errorf("binary process did not stop\n%s", process.output.String())
	}
}

func assertIntegrationBinaryProcessResult(t *testing.T, process *integrationBinaryProcess) {
	t.Helper()
	err := process.result()
	if err == nil && process.wantExitCode == 0 {
		return
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) && exitError.ExitCode() == process.wantExitCode {
		return
	}
	t.Errorf("binary process exited: %v, want exit code %d\n%s", err, process.wantExitCode, process.output.String())
}

func waitForIntegrationBinaryReady(t *testing.T, process *integrationBinaryProcess, metricsAddress, databaseURL string) {
	t.Helper()
	ready := false
	defer func() {
		if ready {
			return
		}
		t.Logf("tnld output before readiness failure:\n%s", process.output.String())
		// Migration success does not prove that the database is still reachable.
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		database := inspectStandaloneTestDatabase(t, databaseURL)
		if err := database.PingContext(ctx); err != nil {
			t.Logf("independent PostgreSQL connectivity probe failed (system resolver, not TNLD_DNS_SERVER): %v", err)
		} else {
			t.Log("independent PostgreSQL connectivity probe succeeded; this does not establish tnld pool readiness")
		}
	}()
	client := &http.Client{Timeout: time.Second}
	waitForIntegrationCondition(t, 15*time.Second, func() (bool, error) {
		select {
		case <-process.done:
			t.Fatalf("tnld exited before readiness: %v", process.result())
		default:
		}
		response, err := client.Get("http://" + metricsAddress + "/ready")
		if err != nil {
			return false, fmt.Errorf("tnld process still running; metrics listener probe: %w", err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			return false, fmt.Errorf("tnld process still running; metrics listener reachable, /ready returned %s", response.Status)
		}
		return true, nil
	})
	ready = true
}

type integrationBinaryPublishEvent struct {
	SchemaVersion int    `json:"schema_version"`
	Type          string `json:"type"`
	TunnelID      string `json:"tunnel_id"`
	URL           string `json:"url"`
	RouteVersion  uint64 `json:"route_version"`
	Reason        string `json:"reason"`
}

type integrationBinaryPublish struct {
	command *exec.Cmd
	events  chan integrationBinaryPublishEvent
	done    chan struct{}
	stderr  synchronizedBuffer

	mu      sync.Mutex
	err     error
	scanErr error
}

func startIntegrationBinaryPublish(
	t *testing.T,
	directory string,
	environment []string,
	name string,
	arguments ...string,
) *integrationBinaryPublish {
	t.Helper()
	publish := &integrationBinaryPublish{
		events: make(chan integrationBinaryPublishEvent, 16), done: make(chan struct{}),
	}
	publish.command = exec.Command(name, arguments...)
	publish.command.Dir = directory
	publish.command.Env = environment
	stdout, err := publish.command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	publish.command.Stderr = &publish.stderr
	if err := publish.command.Start(); err != nil {
		t.Fatal(err)
	}
	scanDone := make(chan struct{})
	go func() {
		defer close(scanDone)
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			var event integrationBinaryPublishEvent
			if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
				publish.mu.Lock()
				publish.scanErr = fmt.Errorf("decode NDJSON event %q: %w", scanner.Text(), err)
				publish.mu.Unlock()
				break
			}
			publish.events <- event
		}
		publish.mu.Lock()
		if publish.scanErr == nil {
			publish.scanErr = scanner.Err()
		}
		publish.mu.Unlock()
		close(publish.events)
	}()
	go func() {
		<-scanDone
		err := publish.command.Wait()
		publish.mu.Lock()
		publish.err = err
		publish.mu.Unlock()
		close(publish.done)
	}()
	t.Cleanup(func() {
		stopIntegrationBinaryPublish(t, publish)
		waitForIntegrationBinaryPublish(t, publish)
	})
	return publish
}

func (p *integrationBinaryPublish) result() (error, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err, p.scanErr
}

func waitForIntegrationBinaryPublishEvent(
	t *testing.T,
	publish *integrationBinaryPublish,
	eventType string,
	timeout time.Duration,
) integrationBinaryPublishEvent {
	t.Helper()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case event, open := <-publish.events:
			if !open {
				processErr, scanErr := publish.result()
				t.Fatalf(
					"tnl publish ended before %q event: process %v, scanner %v\nstderr:\n%s",
					eventType, processErr, scanErr, publish.stderr.String(),
				)
			}
			if event.Type == eventType {
				return event
			}
		case <-timer.C:
			processErr, scanErr := publish.result()
			t.Fatalf(
				"tnl publish did not emit %q: process %v, scanner %v\nstderr:\n%s",
				eventType, processErr, scanErr, publish.stderr.String(),
			)
		}
	}
}

func stopIntegrationBinaryPublish(t *testing.T, publish *integrationBinaryPublish) {
	t.Helper()
	select {
	case <-publish.done:
		return
	default:
	}
	if err := publish.command.Process.Signal(os.Interrupt); err != nil && !errors.Is(err, os.ErrProcessDone) {
		t.Errorf("interrupt tnl publish: %v", err)
	}
}

func waitForIntegrationBinaryPublish(t *testing.T, publish *integrationBinaryPublish) {
	t.Helper()
	select {
	case <-publish.done:
		processErr, scanErr := publish.result()
		if processErr != nil || scanErr != nil {
			t.Errorf("tnl publish exited: process %v, scanner %v\nstderr:\n%s", processErr, scanErr, publish.stderr.String())
		}
	case <-time.After(15 * time.Second):
		_ = publish.command.Process.Kill()
		t.Errorf("tnl publish did not stop\nstderr:\n%s", publish.stderr.String())
	}
}

func integrationRepositoryRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate binary integration test")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
}

func buildIntegrationBinary(t *testing.T, directory, output, commandPackage string) {
	t.Helper()
	command := exec.Command("go", "build", "-p=2", "-o", output, commandPackage)
	command.Dir = directory
	if combined, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", commandPackage, err, combined)
	}
}

func runIntegrationBinaryCommand(
	t *testing.T,
	directory string,
	environment []string,
	name string,
	arguments ...string,
) {
	t.Helper()
	command := exec.Command(name, arguments...)
	command.Dir = directory
	command.Env = environment
	if combined, err := command.CombinedOutput(); err != nil {
		t.Fatalf("run %s %s: %v\n%s", name, strings.Join(arguments, " "), err, combined)
	}
}

func integrationBinaryEnvironment(values map[string]string) []string {
	blocked := func(name string) bool {
		for _, prefix := range []string{"TNLD_", "TNL_", "AWS_"} {
			if strings.HasPrefix(name, prefix) {
				return true
			}
		}
		switch strings.ToUpper(name) {
		case "SSL_CERT_FILE", "SSL_CERT_DIR", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY":
			return true
		default:
			return false
		}
	}
	environment := make([]string, 0, len(os.Environ())+len(values)+2)
	for _, value := range os.Environ() {
		name, _, _ := strings.Cut(value, "=")
		if !blocked(name) {
			environment = append(environment, value)
		}
	}
	environment = append(environment, "NO_PROXY=*", "no_proxy=*")
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		environment = append(environment, key+"="+values[key])
	}
	return environment
}

func assertIntegrationPort443Available(t *testing.T) {
	t.Helper()
	tcpListener, err := net.Listen("tcp", "127.0.0.1:443")
	if err != nil {
		t.Fatalf("TNL_TEST_BINARY_INTEGRATION=1 requires TCP port 443 on 127.0.0.1: %v", err)
	}
	defer tcpListener.Close()
	udpListener, err := net.ListenPacket("udp", "127.0.0.1:443")
	if err != nil {
		t.Fatalf("TNL_TEST_BINARY_INTEGRATION=1 requires UDP port 443 on 127.0.0.1: %v", err)
	}
	_ = udpListener.Close()
	_ = tcpListener.Close()
}
