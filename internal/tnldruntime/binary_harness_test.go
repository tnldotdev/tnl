package tnldruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/tnldconfig"
)

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
	*commandOwner
	output       synchronizedBuffer
	wantExitCode int
}

func startIntegrationBinaryProcess(
	t *testing.T,
	directory string,
	environment []string,
	name string,
	arguments ...string,
) *integrationBinaryProcess {
	t.Helper()
	return startOwnedBinaryProcess(t, func(process *integrationBinaryProcess) {
		t.Cleanup(func() { stopIntegrationBinaryProcess(t, process) })
	}, directory, environment, name, arguments...)
}

func startOwnedBinaryProcess(t *testing.T, own func(*integrationBinaryProcess), directory string, environment []string, name string, arguments ...string) *integrationBinaryProcess {
	t.Helper()
	process := &integrationBinaryProcess{}
	command := exec.Command(name, arguments...)
	command.Dir = directory
	command.Env = environment
	command.Stdout = &process.output
	command.Stderr = &process.output
	owner, err := startOwnedCommand(command, nil)
	if err != nil {
		t.Fatal(err)
	}
	process.commandOwner = owner
	own(process)
	return process
}

type binaryTopology struct {
	processes map[tnldconfig.Role][]*integrationBinaryProcess
}

func newBinaryTopology(t *testing.T) *binaryTopology {
	t.Helper()
	f := &binaryTopology{processes: make(map[tnldconfig.Role][]*integrationBinaryProcess)}
	t.Cleanup(func() {
		for _, role := range []tnldconfig.Role{tnldconfig.RoleIngress, tnldconfig.RoleRelay, tnldconfig.RoleControl, tnldconfig.RoleStandalone} {
			for _, process := range f.processes[role] {
				stopIntegrationBinaryProcess(t, process)
			}
		}
	})
	return f
}

func (f *binaryTopology) start(t *testing.T, role tnldconfig.Role, directory string, environment []string, name string, arguments ...string) *integrationBinaryProcess {
	t.Helper()
	return startOwnedBinaryProcess(t, func(p *integrationBinaryProcess) { f.processes[role] = append(f.processes[role], p) }, directory, environment, name, arguments...)
}

func stopIntegrationBinaryProcess(t *testing.T, process *integrationBinaryProcess) {
	t.Helper()
	if err := process.shutdown(15*time.Second, 5*time.Second); err != nil {
		t.Errorf("binary process shutdown: %v\n%s", err, process.output.String())
	}
	assertIntegrationBinaryProcessResult(t, process)
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
	waitForIntegrationCondition(t, 15*time.Second, func(ctx context.Context) (bool, error) {
		select {
		case <-process.done:
			t.Fatalf("tnld exited before readiness: %v", process.result())
		default:
		}
		response, err := integrationGET(ctx, client, "http://"+metricsAddress+"/ready")
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
	*commandOwner
	events eventRecorder[integrationBinaryPublishEvent]
	cursor int
	stderr synchronizedBuffer
}

// exec's stdout pump always gets a successful Write, including malformed or
// oversized lines. Parsing failure is observable without stopping pipe draining.
type binaryEventWriter struct {
	events     *eventRecorder[integrationBinaryPublishEvent]
	line       []byte
	discarding bool
}

func (w *binaryEventWriter) Write(data []byte) (int, error) {
	const maxLine = 1 << 20
	n := len(data)
	for len(data) != 0 {
		index := bytes.IndexByte(data, '\n')
		part := data
		if index >= 0 {
			part = data[:index]
		}
		if !w.discarding {
			if len(w.line)+len(part) > maxLine {
				w.events.fail(fmt.Errorf("NDJSON event exceeds %d bytes", maxLine))
				w.line = nil
				w.discarding = true
			} else {
				w.line = append(w.line, part...)
			}
		}
		if index < 0 {
			break
		}
		w.decodeLine()
		data = data[index+1:]
	}
	return n, nil
}

func (w *binaryEventWriter) decodeLine() {
	if !w.discarding {
		var event integrationBinaryPublishEvent
		if err := json.Unmarshal(w.line, &event); err != nil {
			w.events.fail(fmt.Errorf("decode NDJSON event: %w", err))
		} else {
			w.events.append(event)
		}
	}
	w.line = w.line[:0]
	w.discarding = false
}

func (w *binaryEventWriter) finish() {
	if len(w.line) != 0 || w.discarding {
		w.decodeLine()
	}
	w.events.close()
}

func startIntegrationBinaryPublish(
	t *testing.T,
	directory string,
	environment []string,
	name string,
	arguments ...string,
) *integrationBinaryPublish {
	t.Helper()
	publish := &integrationBinaryPublish{}
	command := exec.Command(name, arguments...)
	command.Dir = directory
	command.Env = environment
	writer := &binaryEventWriter{events: &publish.events}
	command.Stdout = writer
	command.Stderr = &publish.stderr
	owner, err := startOwnedCommand(command, writer.finish)
	if err != nil {
		t.Fatal(err)
	}
	publish.commandOwner = owner
	t.Cleanup(func() {
		stopIntegrationBinaryPublish(t, publish)
		waitForIntegrationBinaryPublish(t, publish)
	})
	return publish
}

func (p *integrationBinaryPublish) result() (error, error) {
	_, parseErr := p.events.snapshot()
	return p.commandOwner.result(), parseErr
}

func waitForIntegrationBinaryPublishEvent(
	t *testing.T,
	publish *integrationBinaryPublish,
	eventType string,
	timeout time.Duration,
) integrationBinaryPublishEvent {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()
	for {
		event, err := publish.events.next(ctx, &publish.cursor)
		if err != nil {
			processErr, scanErr := publish.result()
			t.Fatalf(
				"tnl publish did not emit %q: %v; process %v, NDJSON %v\nstderr:\n%s",
				eventType, err, processErr, scanErr, publish.stderr.String(),
			)
		}
		if event.Type == eventType {
			return event
		}
	}
}

func stopIntegrationBinaryPublish(t *testing.T, publish *integrationBinaryPublish) {
	t.Helper()
	if err := publish.shutdown(15*time.Second, 5*time.Second); err != nil {
		t.Errorf("tnl publish shutdown: %v\nstderr:\n%s", err, publish.stderr.String())
	}
}

func waitForIntegrationBinaryPublish(t *testing.T, publish *integrationBinaryPublish) {
	t.Helper()
	if err := waitForDoneWithin(publish.done, 15*time.Second); err != nil {
		stopIntegrationBinaryPublish(t, publish)
		t.Errorf("tnl publish did not stop: %v", err)
	}
	processErr, scanErr := publish.result()
	if processErr != nil || scanErr != nil {
		t.Errorf("tnl publish exited: process %v, NDJSON %v\nstderr:\n%s", processErr, scanErr, publish.stderr.String())
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
	runBoundedIntegrationCommand(t, 2*time.Minute, directory, os.Environ(), "go", "build", "-p=2", "-o", output, commandPackage)
}

func runIntegrationBinaryCommand(
	t *testing.T,
	directory string,
	environment []string,
	name string,
	arguments ...string,
) {
	t.Helper()
	runBoundedIntegrationCommand(t, time.Minute, directory, environment, name, arguments...)
}

func runBoundedIntegrationCommand(t *testing.T, timeout time.Duration, directory string, environment []string, name string, arguments ...string) {
	t.Helper()
	command := exec.Command(name, arguments...)
	command.Dir = directory
	command.Env = environment
	var output synchronizedBuffer
	command.Stdout, command.Stderr = &output, &output
	owner, err := startOwnedCommand(command, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := owner.shutdown(time.Second, 5*time.Second); err != nil {
			t.Errorf("command cleanup: %v", err)
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()
	if err := waitForDone(ctx, owner.done); err != nil {
		shutdownErr := owner.shutdown(time.Second, 5*time.Second)
		t.Fatalf("run %s: %v; shutdown %v\n%s", name, err, shutdownErr, output.String())
	}
	if err := owner.result(); err != nil {
		t.Fatalf("run %s %s: %v\n%s", name, strings.Join(arguments, " "), err, output.String())
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
