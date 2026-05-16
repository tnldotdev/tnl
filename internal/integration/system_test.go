package integration_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/tnldotdev/tnl/internal/credentials"
)

func TestIntegrationRealBinariesStandalonePublish(t *testing.T) {
	system := newSystem(t, systemOptions{mode: "standalone"})
	system.authenticate()
	origin := startOrigin(t, "standalone system route")

	publisher, ready := system.startPublisher(t, origin.target, "standalone-system")
	system.fetchEventually(t, ready.URL+"/acceptance", expectBody("standalone system route"))
	assertForwardedRequest(t, origin.requests, "standalone-system."+testDomain)
	stopChild(t, publisher, processWait, "publisher", system.diagnostics())
	stopChild(t, system.daemon, 15*time.Second, "standalone tnld", system.diagnostics())
}

func TestIntegrationRealBinariesEdgeWorkerPublish(t *testing.T) {
	workerToken := newWorkerToken(t)
	system := newSystem(t, systemOptions{mode: "edge", workerToken: workerToken})
	system.authenticate()

	worker := system.startWorker(t, workerToken)
	origin := startOrigin(t, "split system route")
	publisher, ready := system.startPublisher(t, origin.target, "split-system")
	system.fetchEventually(t, ready.URL+"/worker", expectBody("split system route"))
	stopChild(t, publisher, processWait, "split publisher", system.diagnostics())
	stopChild(t, worker, 15*time.Second, "worker")
}

func TestIntegrationRealTNLDevViteHTTPHMRAndCleanup(t *testing.T) {
	system := newSystem(t, systemOptions{mode: "standalone"})
	system.authenticate()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatal("node is required for the Vite system integration test; run mise install")
	}
	viteCLI := filepath.Join(repositoryRoot, "packages", "vite", "node_modules", "vite", "bin", "vite.js")
	viteConfig := filepath.Join(repositoryRoot, "packages", "vite", "dist", "index.js")
	for _, path := range []string{viteCLI, viteConfig} {
		if info, err := os.Stat(path); err != nil || info.IsDir() {
			t.Fatalf("Vite integration dependency %s is unavailable; run pnpm install --frozen-lockfile && pnpm build", path)
		}
	}
	fixture := filepath.Join(repositoryRoot, "packages", "vite", "fixtures", "app")
	viteAddress := reserveTCPAddress(t)
	_, vitePort, err := net.SplitHostPort(viteAddress)
	if err != nil {
		t.Fatal(err)
	}
	dev := startChild(t, childOptions{
		path: tnlBinary,
		args: []string{
			"dev", "--server", system.controlURL, "--state-dir", system.clientState,
			"--access-token", system.accessToken, "--name", "vite-system", "--startup-timeout", "2m", "--",
			node, viteCLI,
		},
		dir: fixture,
		env: system.environment(map[string]string{
			"CI": "true", "NO_COLOR": "1", "TNL_FIXTURE_PORT": vitePort,
		}),
	})
	publicURL := waitForHumanReady(t, dev, readinessWait)
	if publicURL != "https://vite-system."+testDomain {
		t.Fatalf("tnl dev URL = %q", publicURL)
	}
	system.fetchEventually(t, publicURL+"/", func(response responseSnapshot) error {
		if response.status != http.StatusOK || !strings.Contains(response.body, "Vite fixture") ||
			response.header.Get("X-Tnl-Fixture") != "vite" {
			return fmt.Errorf("response = %d, fixture=%q, body=%q", response.status, response.header.Get("X-Tnl-Fixture"), response.body)
		}
		return nil
	})
	clientModule := system.fetchEventually(t, publicURL+"/@vite/client", func(response responseSnapshot) error {
		if response.status != http.StatusOK {
			return fmt.Errorf("status = %d", response.status)
		}
		return nil
	})
	match := regexp.MustCompile(`const wsToken = "([^"]+)"`).FindStringSubmatch(clientModule.body)
	if len(match) != 2 {
		t.Fatal("Vite client did not contain a WebSocket token")
	}
	websocketURL, err := url.Parse(publicURL)
	if err != nil {
		t.Fatal(err)
	}
	websocketURL.Scheme = "wss"
	websocketURL.Path = "/"
	query := websocketURL.Query()
	query.Set("token", match[1])
	websocketURL.RawQuery = query.Encode()
	header := make(http.Header)
	header.Set("Origin", publicURL)
	wsCtx, cancelWebSocket := context.WithTimeout(context.Background(), 20*time.Second)
	connection, _, err := websocket.Dial(wsCtx, websocketURL.String(), &websocket.DialOptions{
		HTTPClient: system.client, HTTPHeader: header, Subprotocols: []string{"vite-hmr"},
	})
	if err != nil {
		cancelWebSocket()
		t.Fatalf("open public Vite HMR WebSocket: %v\n%s\n%s", err, dev.logs(), system.diagnostics())
	}
	_, message, err := connection.Read(wsCtx)
	cancelWebSocket()
	if err != nil {
		_ = connection.CloseNow()
		t.Fatal(err)
	}
	var hmr struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(message, &hmr); err != nil || hmr.Type != "connected" {
		_ = connection.CloseNow()
		t.Fatalf("HMR message = %q, error = %v", message, err)
	}
	if err := connection.Close(websocket.StatusNormalClosure, "integration complete"); err != nil {
		t.Fatal(err)
	}
	stopChild(t, dev, processWait, "tnl dev", system.diagnostics())
	waitForPortClosed(t, net.JoinHostPort("127.0.0.1", vitePort), 10*time.Second)
}

type publishEvent struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

func (s *systemFixture) startPublisher(t *testing.T, target, name string) (*childProcess, publishEvent) {
	t.Helper()
	process := startChild(t, childOptions{
		path: tnlBinary,
		args: []string{
			"publish", target, "--server", s.controlURL, "--state-dir", s.clientState,
			"--access-token", s.accessToken, "--name", name, "--output", "ndjson",
		},
		dir: repositoryRoot, env: s.environment(nil),
	})
	return process, waitForPublishReady(t, process, s)
}

func waitForPublishReady(t *testing.T, process *childProcess, system *systemFixture) publishEvent {
	t.Helper()
	deadline := time.Now().Add(readinessWait)
	for time.Now().Before(deadline) {
		decoder := json.NewDecoder(strings.NewReader(process.stdout.String()))
		for {
			var event publishEvent
			if err := decoder.Decode(&event); err != nil {
				break
			}
			switch event.Type {
			case "ready":
				if event.URL == "" {
					t.Fatalf("publisher ready event omitted URL\n%s", process.logs())
				}
				return event
			case "error":
				t.Fatalf("publisher reported an error\n%s\n%s", process.logs(), system.diagnostics())
			}
		}
		if process.exited() {
			t.Fatalf("publisher exited before readiness: %v\n%s\n%s", process.wait(), process.logs(), system.diagnostics())
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("publisher readiness timed out\n%s\n%s", process.logs(), system.diagnostics())
	return publishEvent{}
}

func waitForHumanReady(t *testing.T, process *childProcess, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for line := range strings.SplitSeq(process.stderr.String(), "\n") {
			candidate := strings.TrimSpace(line)
			parsed, err := url.Parse(candidate)
			if err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.Path == "" {
				return candidate
			}
		}
		if process.exited() {
			t.Fatalf("tnl dev exited before readiness: %v\n%s", process.wait(), process.logs())
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("tnl dev readiness timed out\n%s", process.logs())
	return ""
}

type responseSnapshot struct {
	status int
	body   string
	header http.Header
}

type originFixture struct {
	target   string
	requests chan *http.Request
}

func startOrigin(t *testing.T, body string) originFixture {
	t.Helper()
	requests := make(chan *http.Request, 8)
	server := &http.Server{Handler: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		select {
		case requests <- request.Clone(context.Background()):
		default:
		}
		_, _ = io.WriteString(response, body)
	})}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return originFixture{target: "http://" + listener.Addr().String(), requests: requests}
}

func expectBody(body string) func(responseSnapshot) error {
	return func(response responseSnapshot) error {
		if response.status != http.StatusOK || response.body != body {
			return fmt.Errorf("response = %d %q", response.status, response.body)
		}
		return nil
	}
}

func newWorkerToken(t *testing.T) string {
	t.Helper()
	token, _, err := credentials.NewWorkerToken()
	if err != nil {
		t.Fatal(err)
	}
	return token.String()
}

func stopChild(t *testing.T, process *childProcess, timeout time.Duration, name string, diagnostics ...string) {
	t.Helper()
	if err := process.stop(timeout); err != nil {
		details := strings.Join(diagnostics, "\n")
		t.Fatalf("stop %s: %v\n%s\n%s", name, err, process.logs(), details)
	}
}

func (s *systemFixture) fetchEventually(t *testing.T, rawURL string, validate func(responseSnapshot) error) responseSnapshot {
	t.Helper()
	deadline := time.Now().Add(readinessWait)
	var lastErr error
	for time.Now().Before(deadline) {
		s.transport.CloseIdleConnections()
		response, err := s.client.Get(rawURL)
		if err != nil {
			lastErr = err
			time.Sleep(100 * time.Millisecond)
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 4<<20))
		closeErr := response.Body.Close()
		snapshot := responseSnapshot{status: response.StatusCode, body: string(body), header: response.Header.Clone()}
		if readErr == nil && closeErr == nil {
			if err := validate(snapshot); err == nil {
				return snapshot
			} else {
				lastErr = err
			}
		} else {
			lastErr = errors.Join(readErr, closeErr)
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("request %s did not succeed: %v\n%s", rawURL, lastErr, s.diagnostics())
	return responseSnapshot{}
}

func assertForwardedRequest(t *testing.T, requests <-chan *http.Request, hostname string) {
	t.Helper()
	select {
	case request := <-requests:
		if request.Host != hostname || request.Header.Get("X-Forwarded-For") != "127.0.0.1" ||
			request.Header.Get("X-Forwarded-Proto") != "https" {
			t.Fatalf("forwarded request host=%q for=%q proto=%q", request.Host, request.Header.Get("X-Forwarded-For"), request.Header.Get("X-Forwarded-Proto"))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("origin did not receive forwarded request")
	}
}

func waitForPortClosed(t *testing.T, address string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		connection, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err != nil {
			return
		}
		_ = connection.Close()
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("development server still listens on %s", address)
}
