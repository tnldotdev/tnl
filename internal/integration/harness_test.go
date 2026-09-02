package integration_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/serverclient"
	"github.com/tnldotdev/tnl/internal/testutil/integrationtest"
	"tailscale.com/tailcfg"
)

const (
	testDomain      = "tnl.test"
	testControlHost = "tnl." + testDomain
	processWait     = 45 * time.Second
	readinessWait   = 90 * time.Second
)

var (
	repositoryRoot string
	tnlBinary      string
	tnldBinary     string
)

func TestMain(m *testing.M) {
	if os.Getenv(integrationtest.IntegrationEnv) != "1" {
		os.Exit(m.Run())
	}
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		fmt.Fprintln(os.Stderr, "resolve integration source path")
		os.Exit(1)
	}
	repositoryRoot = filepath.Clean(filepath.Join(filepath.Dir(source), "..", ".."))
	buildDir, err := os.MkdirTemp("", "tnl-system-integration-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create integration build directory: %v\n", err)
		os.Exit(1)
	}
	tnlBinary = filepath.Join(buildDir, "tnl")
	tnldBinary = filepath.Join(buildDir, "tnld")
	for _, build := range []struct {
		output  string
		command string
	}{
		{output: tnlBinary, command: "./cmd/tnl"},
		{output: tnldBinary, command: "./cmd/tnld"},
	} {
		command := exec.Command(
			"go", "build", "-mod=readonly", "-trimpath", "-tags=ts_omit_ssh", "-o", build.output, build.command,
		)
		command.Dir = repositoryRoot
		command.Env = replaceEnvironment(os.Environ(), map[string]string{"CGO_ENABLED": "0", "GOFLAGS": ""})
		if output, buildErr := command.CombinedOutput(); buildErr != nil {
			fmt.Fprintf(os.Stderr, "build %s: %v\n%s", build.command, buildErr, output)
			_ = os.RemoveAll(buildDir)
			os.Exit(1)
		}
	}
	code := m.Run()
	_ = os.RemoveAll(buildDir)
	os.Exit(code)
}

type systemOptions struct {
	mode        string
	workerToken string
}

type systemFixture struct {
	t           *testing.T
	stateDir    string
	clientState string
	controlURL  string
	workerURL   string
	proxyURL    string
	trustBundle string
	pebble      *integrationtest.Pebble
	daemon      *childProcess
	transport   *http.Transport
	client      *http.Client
	accessToken string
}

func newSystem(t *testing.T, options systemOptions) *systemFixture {
	t.Helper()
	pebblePath := integrationtest.RequirePebble(t)
	root := t.TempDir()
	publicAddress := reserveTCPAddress(t)
	_, publicPortText, err := net.SplitHostPort(publicAddress)
	if err != nil {
		t.Fatal(err)
	}
	dnsAddress := integrationtest.StartChallengeDNS(t)
	pebble := integrationtest.StartPebble(t, pebblePath, mustPort(t, publicPortText), dnsAddress)
	relayMapPath := writePinnedRelayMap(t, root)
	proxyURL := startConnectProxy(t, publicAddress)
	controlURL := "https://" + net.JoinHostPort(testControlHost, publicPortText)
	fixture := &systemFixture{
		t: t, stateDir: filepath.Join(root, "server"), clientState: filepath.Join(root, "client"),
		controlURL: controlURL,
		workerURL:  "wss://" + net.JoinHostPort(testControlHost, publicPortText) + "/internal/v1/worker",
		proxyURL:   proxyURL, trustBundle: pebble.TrustBundlePath(t), pebble: pebble,
	}
	fixture.transport = &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pebble.IssuerRoots(t), MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return new(net.Dialer).DialContext(ctx, network, publicAddress)
		},
		ForceAttemptHTTP2: false,
	}
	t.Cleanup(fixture.transport.CloseIdleConnections)
	fixture.client = &http.Client{Transport: fixture.transport, Timeout: 15 * time.Second}

	args := []string{
		"serve", "--mode", options.mode, "--state-dir", fixture.stateDir,
		"--metrics-listen=", "--public-listen", publicAddress,
		"--domain", testDomain, "--dns-server", dnsAddress,
		"--acme-directory-url", pebble.DirectoryURL(), "--acme-email", "operator@example.com",
		"--acme-accept-terms", "--acme-profile", "tlsserver",
		"--relay-map-file", relayMapPath, "--relay-region", "test",
		"--worker-capacity", "8", "--worker-stream-limit", "32",
		"--public-connection-limit", "64", "--route-connection-limit", "16", "--drain-timeout", "5s",
	}
	if options.mode == "edge" {
		args = append(args, "--worker-token", options.workerToken)
	}
	fixture.daemon = startChild(t, childOptions{
		path: tnldBinary, args: args, dir: repositoryRoot, env: fixture.environment(nil),
	})
	fixture.waitForControl()
	return fixture
}

func (s *systemFixture) environment(overrides map[string]string) []string {
	values := map[string]string{
		"SSL_CERT_FILE":    s.trustBundle,
		"GODEBUG":          "x509sslcertoverrideplatform=1",
		"HTTP_PROXY":       "",
		"http_proxy":       "",
		"HTTPS_PROXY":      s.proxyURL,
		"https_proxy":      s.proxyURL,
		"NO_PROXY":         "",
		"no_proxy":         "",
		"TNL_NO_TELEMETRY": "1",
	}
	for key, value := range overrides {
		values[key] = value
	}
	environment := make([]string, 0, len(os.Environ())+len(values))
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		upper := strings.ToUpper(key)
		if strings.HasPrefix(upper, "TNL_") || strings.HasPrefix(upper, "TNLD_") ||
			upper == "SSL_CERT_FILE" || upper == "GODEBUG" || upper == "HTTP_PROXY" ||
			upper == "HTTPS_PROXY" || upper == "NO_PROXY" {
			continue
		}
		environment = append(environment, entry)
	}
	for key, value := range values {
		environment = append(environment, key+"="+value)
	}
	return environment
}

func (s *systemFixture) waitForControl() {
	s.t.Helper()
	deadline := time.Now().Add(readinessWait)
	var lastErr error
	for time.Now().Before(deadline) {
		if s.daemon.exited() {
			s.t.Fatalf("tnld exited before readiness: %v\n%s", s.daemon.wait(), s.diagnostics())
		}
		response, err := s.client.Get(s.controlURL + "/v1/ready")
		if err == nil {
			_, readErr := io.Copy(io.Discard, response.Body)
			closeErr := response.Body.Close()
			if response.StatusCode == http.StatusOK && readErr == nil && closeErr == nil {
				if s.dnsReady() {
					return
				}
			} else {
				lastErr = fmt.Errorf("ready response: %s, read=%v, close=%v", response.Status, readErr, closeErr)
			}
		} else {
			lastErr = err
		}
		time.Sleep(50 * time.Millisecond)
	}
	s.t.Fatalf("control did not become ready: %v\n%s", lastErr, s.diagnostics())
}

func (s *systemFixture) dnsReady() bool {
	response, err := s.client.Get(s.controlURL + "/v1/capabilities")
	if err != nil {
		return false
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return false
	}
	var capabilities struct {
		DNSReady bool `json:"dns_ready"`
	}
	return json.NewDecoder(response.Body).Decode(&capabilities) == nil && capabilities.DNSReady
}

func (s *systemFixture) authenticate() {
	s.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	output, err := runCommand(ctx, repositoryRoot, s.environment(nil), tnlBinary,
		"admin", "server", "login-token", "--state-dir", s.stateDir,
	)
	if err != nil {
		s.t.Fatalf("read login token: %v\n%s\n%s", err, output.stdout, output.stderr)
	}
	token := credentials.LoginToken(strings.TrimSpace(output.stdout))
	if _, err := credentials.ParseLoginToken(token); err != nil {
		s.t.Fatalf("admin returned invalid login token %q: %v", token, err)
	}
	client, err := serverclient.New(s.controlURL, s.client, "")
	if err != nil {
		s.t.Fatalf("create login client: %v", err)
	}
	session, err := client.Exchange(ctx, token)
	if err != nil {
		s.t.Fatalf("exchange login token: %v\n%s", err, s.diagnostics())
	}
	accessToken := credentials.AccessToken(session.AccessToken)
	if _, _, err := credentials.ParseAccessToken(accessToken); err != nil {
		s.t.Fatalf("server returned invalid access token: %v", err)
	}
	s.accessToken = accessToken.String()
}

func (s *systemFixture) startWorker(t *testing.T, token string) *childProcess {
	t.Helper()
	return startChild(t, childOptions{
		path: tnldBinary,
		args: []string{
			"serve", "--mode", "worker", "--metrics-listen=",
			"--worker-url", s.workerURL, "--worker-token", token,
			"--worker-capacity", "8", "--worker-stream-limit", "32", "--drain-timeout", "5s",
		},
		dir: repositoryRoot, env: s.environment(nil),
	})
}

func (s *systemFixture) diagnostics() string {
	return fmt.Sprintf("tnld:\n%s\nPebble:\n%s", s.daemon.logs(), s.pebble.Logs())
}

type childOptions struct {
	path string
	args []string
	dir  string
	env  []string
}

type childProcess struct {
	command *exec.Cmd
	stdout  *lockedBuffer
	stderr  *lockedBuffer
	done    chan struct{}

	mu  sync.Mutex
	err error
}

func startChild(t *testing.T, options childOptions) *childProcess {
	t.Helper()
	process := &childProcess{
		command: exec.Command(options.path, options.args...),
		stdout:  new(lockedBuffer), stderr: new(lockedBuffer), done: make(chan struct{}),
	}
	process.command.Dir = options.dir
	process.command.Env = options.env
	process.command.Stdout = process.stdout
	process.command.Stderr = process.stderr
	process.command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := process.command.Start(); err != nil {
		t.Fatalf("start %s: %v", filepath.Base(options.path), err)
	}
	go func() {
		err := process.command.Wait()
		process.mu.Lock()
		process.err = err
		process.mu.Unlock()
		close(process.done)
	}()
	t.Cleanup(func() {
		if process.exited() {
			return
		}
		if err := process.stop(15 * time.Second); err != nil {
			t.Errorf("stop %s: %v\n%s", filepath.Base(options.path), err, process.logs())
		}
	})
	return process
}

func (p *childProcess) exited() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

func (p *childProcess) wait() error {
	<-p.done
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}

func (p *childProcess) stop(timeout time.Duration) error {
	if p.exited() {
		return p.wait()
	}
	signalErr := syscall.Kill(-p.command.Process.Pid, syscall.SIGTERM)
	if errors.Is(signalErr, syscall.ESRCH) {
		signalErr = nil
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-p.done:
		return errors.Join(signalErr, p.wait())
	case <-timer.C:
		killErr := syscall.Kill(-p.command.Process.Pid, syscall.SIGKILL)
		if errors.Is(killErr, syscall.ESRCH) {
			killErr = nil
		}
		return errors.Join(signalErr, killErr, p.wait())
	}
}

func (p *childProcess) logs() string {
	return "stdout:\n" + p.stdout.String() + "\nstderr:\n" + p.stderr.String()
}

type lockedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *lockedBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(data)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

type commandOutput struct {
	stdout string
	stderr string
}

func runCommand(ctx context.Context, dir string, environment []string, path string, args ...string) (commandOutput, error) {
	command := exec.CommandContext(ctx, path, args...)
	command.Dir = dir
	command.Env = environment
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	return commandOutput{stdout: stdout.String(), stderr: stderr.String()}, err
}

func writePinnedRelayMap(t *testing.T, directory string) string {
	t.Helper()
	region := integrationtest.DERP(t)
	node := region.Nodes[0]
	address := net.JoinHostPort(node.HostName, fmt.Sprint(node.DERPPort))
	connection, err := tls.Dial("tcp", address, &tls.Config{
		MinVersion: tls.VersionTLS12, InsecureSkipVerify: true, // Pin the local fixture certificate below.
	})
	if err != nil {
		t.Fatal(err)
	}
	state := connection.ConnectionState()
	_ = connection.Close()
	if len(state.PeerCertificates) == 0 {
		t.Fatal("local DERP returned no certificate")
	}
	digest := sha256.Sum256(state.PeerCertificates[0].Raw)
	node.CertName = "sha256-raw:" + hex.EncodeToString(digest[:])
	node.InsecureForTests = false
	node.STUNTestIP = ""
	data, err := json.Marshal(tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{region.RegionID: region}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "relay.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func startConnectProxy(t *testing.T, target string) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var connections sync.Map
	server := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if request.Method != http.MethodConnect {
				http.Error(response, "CONNECT required", http.StatusMethodNotAllowed)
				return
			}
			upstream, err := net.DialTimeout("tcp", target, 5*time.Second)
			if err != nil {
				http.Error(response, err.Error(), http.StatusBadGateway)
				return
			}
			hijacker, ok := response.(http.Hijacker)
			if !ok {
				upstream.Close()
				http.Error(response, "hijacking unavailable", http.StatusInternalServerError)
				return
			}
			client, _, err := hijacker.Hijack()
			if err != nil {
				upstream.Close()
				return
			}
			connections.Store(client, struct{}{})
			connections.Store(upstream, struct{}{})
			defer func() {
				connections.Delete(client)
				connections.Delete(upstream)
				client.Close()
				upstream.Close()
			}()
			if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
				return
			}
			copied := make(chan struct{}, 2)
			go func() { _, _ = io.Copy(upstream, client); copied <- struct{}{} }()
			go func() { _, _ = io.Copy(client, upstream); copied <- struct{}{} }()
			<-copied
		}),
	}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		_ = server.Close()
		connections.Range(func(connection, _ any) bool {
			_ = connection.(net.Conn).Close()
			return true
		})
	})
	return "http://" + listener.Addr().String()
}

func reserveTCPAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func mustPort(t *testing.T, value string) int {
	t.Helper()
	var port int
	if _, err := fmt.Sscan(value, &port); err != nil || port < 1 || port > 65535 {
		t.Fatalf("invalid port %q", value)
	}
	return port
}

func replaceEnvironment(environment []string, replacements map[string]string) []string {
	result := make([]string, 0, len(environment)+len(replacements))
	for _, entry := range environment {
		key, _, _ := strings.Cut(entry, "=")
		if _, replaced := replacements[key]; !replaced {
			result = append(result, entry)
		}
	}
	for key, value := range replacements {
		result = append(result, key+"="+value)
	}
	return result
}
