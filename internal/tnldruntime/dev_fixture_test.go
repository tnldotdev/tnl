package tnldruntime

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/projectmeta"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"golang.org/x/net/websocket"
	"golang.org/x/sys/unix"
)

type integrationViteFixture struct {
	server              *integrationBinaryStandalone
	project             integrationBinaryDevProject
	state               *clientstate.Database
	database            *sql.DB
	accessToken         string
	dev                 *integrationBinaryProcess
	report              integrationBinaryDevReport
	metadata            projectmeta.Metadata
	hostname, publicURL string
}

func newIntegrationViteFixture(t *testing.T, server *integrationBinaryStandalone, name string) *integrationViteFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	state, err := clientstate.Open(ctx, server.stateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	profile, err := state.Server(ctx, "https://control.127.0.0.1.nip.io")
	if err != nil {
		t.Fatal(err)
	}
	session, found, err := profile.ControlSession(ctx)
	if err != nil || !found || session.AccessToken == "" {
		t.Fatalf("read isolated login session: found %t, error %v", found, err)
	}
	return &integrationViteFixture{server: server, project: newIntegrationBinaryDevProject(t, server.repositoryRoot, name),
		state: state, database: inspectStandaloneTestDatabase(t, server.databaseURL), accessToken: session.AccessToken}
}

func (f *integrationViteFixture) disableMaintenance(t *testing.T, name string) {
	t.Helper()
	set := func(allowed bool) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var actual bool
		err := f.database.QueryRowContext(ctx, `UPDATE control.maintenance_controls
			SET allowed = $2, revision = revision + 1, updated_at = now(), updated_by = 'binary-test'
			WHERE control_name = $1 RETURNING allowed`, name, allowed).Scan(&actual)
		if err != nil || actual != allowed {
			t.Errorf("set maintenance control %s to %t: %v", name, allowed, err)
		}
	}
	t.Cleanup(func() { set(true) })
	set(false)
	if t.Failed() {
		t.FailNow()
	}
}

func (f *integrationViteFixture) start(t *testing.T, exitCode int) {
	t.Helper()
	environment := append(append([]string(nil), f.server.environment...), "TNL_ACCESS_TOKEN="+f.accessToken,
		"TNL_LOGIN_TOKEN=test-login-token-sentinel", "TNL_PROJECT_RUNTIME=stale-parent-metadata",
		"TNL_FIXTURE_HOST=127.0.0.1", "TNL_FIXTURE_PORT=0", "XDG_RUNTIME_DIR="+f.project.runtimeDirectory)
	// tnl owns its development process group. This fallback runs only after the
	// parent has tried to stop and reap it, and reports a leaked child as a failure.
	t.Cleanup(func() {
		report, err := readIntegrationBinaryDevReport(f.project.reportPath)
		if err == nil && report.PID > 0 && syscall.Kill(report.PID, 0) == nil {
			_ = syscall.Kill(-report.PID, syscall.SIGKILL)
			t.Error("tnl dev left its Vite process running")
		}
	})
	f.dev = startIntegrationBinaryProcess(t, f.project.root, environment, f.server.tnlPath, "dev", "api", "--allow-all-ips")
	dev := f.dev
	dev.wantExitCode = exitCode
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("tnl dev output:\n%s\ntnld output:\n%s", dev.output.String(), f.server.server.output.String())
		}
	})
}

func (f *integrationViteFixture) waitRegistration(t *testing.T, requireTarget bool) {
	t.Helper()
	previousPID := f.report.PID
	waitForIntegrationCondition(t, 30*time.Second, func(context.Context) (bool, error) {
		var err error
		f.report, err = readIntegrationBinaryDevReport(f.project.reportPath)
		if err == nil && f.report.PID != previousPID && f.report.Runtime != nil && (!requireTarget || f.report.Target != "") {
			return true, nil
		}
		select {
		case <-f.dev.done:
			t.Fatalf("tnl dev exited before Vite registration: %v\n%s", f.dev.result(), f.dev.output.String())
		default:
		}
		return false, err
	})
	r := f.report
	if r.PID <= 0 || r.CWD != f.project.root || r.Protocol != "1" || !strings.HasPrefix(r.Socket, f.project.runtimeDirectory+string(filepath.Separator)) || r.HasAccessToken || r.HasLoginToken || r.HasRuntimeEnvironment {
		t.Fatalf("Vite child environment = %#v", r)
	}
	encoded, err := os.ReadFile(filepath.Join(f.project.root, ".tnl", "project.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, &f.metadata); err != nil {
		t.Fatal(err)
	}
	if err := f.metadata.Validate(); err != nil {
		t.Fatal(err)
	}
	f.hostname = f.project.subdomain + "." + f.metadata.Namespace
	f.publicURL = "https://" + f.hostname
	wantService := projectmeta.Service{Namespace: f.metadata.Namespace, Hostname: f.hostname, URL: f.publicURL}
	if !strings.HasSuffix(f.metadata.Namespace, ".routes.127.0.0.1.nip.io") || len(f.metadata.Services) != 1 ||
		f.metadata.Services["api"] != wantService || f.metadata.ServiceDirectories["api"] != "." || !reflect.DeepEqual(*r.Runtime, f.metadata.Public(true)) {
		t.Fatalf("generated metadata = %#v, Vite runtime = %#v", f.metadata, r.Runtime)
	}
}

func (f *integrationViteFixture) waitTunnel(t *testing.T, wantState clientstate.TunnelState, wantNumber uint64) clientstate.TunnelInfo {
	t.Helper()
	var tunnel clientstate.TunnelInfo
	waitForIntegrationCondition(t, 45*time.Second, func(ctx context.Context) (bool, error) {
		snapshot, err := f.state.SnapshotProject(ctx, f.project.root)
		if err != nil {
			return false, err
		}
		if len(snapshot.Tunnels) == 1 {
			tunnel = snapshot.Tunnels[0]
			if tunnel.State == wantState && tunnel.PublishRunNumber != 0 {
				return true, nil
			}
		}
		select {
		case <-f.dev.done:
			t.Fatalf("tnl dev exited before %s: %v\n%s", wantState, f.dev.result(), f.dev.output.String())
		default:
		}
		return false, nil
	})
	if tunnel.Command != clientstate.TunnelCommandDev || tunnel.Service != "api" || tunnel.ProcessID != f.dev.command.Process.Pid || tunnel.Framework != "vite" || tunnel.Target != f.report.Target || tunnel.Hostname != f.hostname || tunnel.PublicURL != f.publicURL || tunnel.PublicURLID == "" || tunnel.PublishRunNumber != wantNumber {
		t.Fatalf("configured Vite tunnel = %#v, child = %#v", tunnel, f.report)
	}
	return tunnel
}

func (f *integrationViteFixture) assertCertificatePlan(t *testing.T, tunnel clientstate.TunnelInfo) []string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var challenge, scope string
	var identifiers []byte
	if err := f.database.QueryRowContext(ctx, `SELECT certificate_challenge, certificate_scope, to_json(certificate_identifiers)
		FROM control.publish_runs WHERE public_url_id = $1 AND publish_run_number = $2`, tunnel.PublicURLID, tunnel.PublishRunNumber).Scan(&challenge, &scope, &identifiers); err != nil {
		t.Fatal(err)
	}
	var names []string
	if err := json.Unmarshal(identifiers, &names); err != nil {
		t.Fatal(err)
	}
	want := controlv1.CertificatePlan{CacheKey: f.hostname, Scope: f.hostname, Identifiers: []string{f.hostname}, ChallengeMethod: controlv1.TlsAlpn01}
	slices.Sort(names)
	if challenge != string(want.ChallengeMethod) || scope != want.Scope || !slices.Equal(names, want.Identifiers) {
		t.Fatalf("certificate plan = %q, %q, %s, want %#v", challenge, scope, identifiers, want)
	}
	return names
}

func (f *integrationViteFixture) stopTunnel(t *testing.T, tunnel clientstate.TunnelInfo) {
	t.Helper()
	stopIntegrationBinaryProcess(t, f.dev)
	waitForReadyPublisherConnections(t, f.database, tunnel.PublicURLID, tunnel.PublishRunNumber, 0)
}

func (f *integrationViteFixture) assertCleanup(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	snapshot, err := f.state.SnapshotProject(ctx, f.project.root)
	if err != nil || len(snapshot.Tunnels) != 0 {
		t.Fatalf("local tunnel remained active after exit: %#v, %v", snapshot, err)
	}
	waitForIntegrationCondition(t, 10*time.Second, func(ctx context.Context) (bool, error) {
		var open int
		err := f.database.QueryRowContext(ctx, `SELECT count(*) FROM control.publish_runs AS sessions
			JOIN control.public_urls AS routes ON routes.id = sessions.public_url_id
			WHERE routes.canonical_hostname = $1 AND sessions.closed_at IS NULL`, f.hostname).Scan(&open)
		return err == nil && open == 0, err
	})
	assertIntegrationBinaryDevCleanup(t, f.report)
}

func dialIntegrationWebsocket(t *testing.T, config *websocket.Config) *websocket.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	connection, err := config.DialContext(ctx)
	if err != nil {
		t.Fatalf("connect HMR through public public_url: %v", err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	if err := connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return connection
}

func assertIntegrationViteHMR(t *testing.T, roots *x509.CertPool, hostname string, client []byte, sourcePath string) {
	t.Helper()
	token := regexp.MustCompile(`const wsToken = "([^"]+)"`).FindSubmatch(client)
	if token == nil {
		t.Fatal("Vite browser client did not contain its WebSocket token")
	}
	config, err := websocket.NewConfig("wss://"+hostname+"/?token="+string(token[1]), "https://"+hostname)
	if err != nil {
		t.Fatal(err)
	}
	config.Protocol = []string{"vite-hmr"}
	config.TlsConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}
	connection := dialIntegrationWebsocket(t, config)
	defer connection.Close()
	var payload string
	if err := websocket.Message.Receive(connection, &payload); err != nil {
		t.Fatalf("receive Vite HMR: %v", err)
	}
	var message struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal([]byte(payload), &message); err != nil || message.Type != "connected" {
		t.Fatalf("Vite HMR message = %q, error %v", payload, err)
	}
	if err := connection.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	replaceIntegrationFixtureText(t, sourcePath, "Vite fixture", "Vite fixture HMR")
	for {
		var payload string
		if err := websocket.Message.Receive(connection, &payload); err != nil {
			t.Fatalf("receive Vite HMR update through public public_url: %v", err)
		}
		var message struct {
			Type    string `json:"type"`
			Updates []struct {
				Path         string `json:"path"`
				AcceptedPath string `json:"acceptedPath"`
			} `json:"updates"`
		}
		if err := json.Unmarshal([]byte(payload), &message); err != nil {
			t.Fatalf("decode Vite HMR update %q: %v", payload, err)
		}
		if message.Type != "update" {
			continue
		}
		for _, update := range message.Updates {
			if update.Path == "/src/main.ts" && update.AcceptedPath == "/src/main.ts" {
				return
			}
		}
		t.Fatalf("Vite HMR update did not include /src/main.ts: %s", payload)
	}
}

func assertIntegrationNextHMR(t *testing.T, roots *x509.CertPool, hostname, sourcePath string) {
	t.Helper()
	config, err := websocket.NewConfig("wss://"+hostname+"/_next/hmr?id=tnl-integration", "https://"+hostname)
	if err != nil {
		t.Fatal(err)
	}
	config.TlsConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}
	connection := dialIntegrationWebsocket(t, config)
	defer connection.Close()
	connected := false
	for !connected {
		var payload string
		if err := websocket.Message.Receive(connection, &payload); err != nil {
			t.Fatalf("receive Next.js HMR connection message through public public_url: %v", err)
		}
		var message struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal([]byte(payload), &message); err != nil {
			t.Fatalf("decode Next.js HMR connection message %q: %v", payload, err)
		}
		switch message.Type {
		case "isrManifest":
		case "turbopack-connected":
			connected = true
		default:
			t.Fatalf("unexpected initial Next.js HMR message: %s", payload)
		}
	}
	if err := connection.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	replaceIntegrationFixtureText(t, sourcePath, "Next.js fixture", "Next.js fixture refreshed")
	for {
		var payload string
		if err := websocket.Message.Receive(connection, &payload); err != nil {
			t.Fatalf("receive Next.js HMR update through public public_url: %v", err)
		}
		var message struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal([]byte(payload), &message); err != nil {
			continue // Next.js may interleave binary Turbopack protocol messages.
		}
		switch message.Type {
		case "building", "built", "turbopack-message", "serverComponentChanges", "clientChanges":
			return
		}
	}
}

func replaceIntegrationFixtureText(t *testing.T, path, old, replacement string) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	updated := bytes.Replace(content, []byte(old), []byte(replacement), 1)
	if bytes.Equal(updated, content) {
		t.Fatalf("fixture %s does not contain %q", path, old)
	}
	if err := os.WriteFile(path, updated, 0o600); err != nil {
		t.Fatal(err)
	}
}

type integrationBinaryDevProject struct{ root, runtimeDirectory, reportPath, subdomain string }

func newIntegrationBinaryNextDevProject(t *testing.T, repositoryRoot string) integrationBinaryDevProject {
	t.Helper()
	packageDirectory := filepath.Join(repositoryRoot, "packages", "tnl")
	if _, err := os.Stat(filepath.Join(packageDirectory, "dist", "next.js")); err != nil {
		t.Fatal("built @tnldotdev/tnl is required; run mise exec -- pnpm --filter @tnldotdev/tnl build")
	}
	runtimeDirectory, err := os.MkdirTemp("/tmp", "tnl-next-dev-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(runtimeDirectory) })
	project := integrationBinaryDevProject{root: filepath.Join(t.TempDir(), "project"), runtimeDirectory: runtimeDirectory, subdomain: "next-hmr"}
	runIntegrationBinaryCommand(t, repositoryRoot, integrationBinaryEnvironment(nil), "pnpm", "--filter", "@tnldotdev/tnl", "deploy", "--legacy", project.root)
	fixtureDirectory := filepath.Join(packageDirectory, "fixtures", "next", "app")
	for _, name := range []string{"next.config.ts", "app/layout.tsx", "app/page.tsx"} {
		source, destination := filepath.Join(fixtureDirectory, filepath.FromSlash(name)), filepath.Join(project.root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
			t.Fatal(err)
		}
		content, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(destination, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	nodeModules := filepath.Join(project.root, "node_modules")
	if err := os.MkdirAll(filepath.Join(nodeModules, "@tnldotdev"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(project.root, filepath.Join(nodeModules, "@tnldotdev", "tnl")); err != nil {
		t.Fatal(err)
	}
	writeIntegrationDevConfig(t, project, map[string]any{"command": []string{"node", filepath.Join(nodeModules, "next", "dist", "bin", "next"), "dev", "--hostname", "127.0.0.1"}})
	return project
}

func newIntegrationBinaryDevProject(t *testing.T, repositoryRoot, name string) integrationBinaryDevProject {
	t.Helper()
	packageDirectory := filepath.Join(repositoryRoot, "packages", "tnl")
	if _, err := os.Stat(filepath.Join(packageDirectory, "dist", "vite.js")); err != nil {
		t.Fatal("built @tnldotdev/tnl is required; run mise exec -- pnpm --filter @tnldotdev/tnl build")
	}
	// Keep runtime sockets below Unix socket path length limits.
	runtimeDirectory, err := os.MkdirTemp("/tmp", "tnl-dev-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(runtimeDirectory) })
	project := integrationBinaryDevProject{root: t.TempDir(), runtimeDirectory: runtimeDirectory, reportPath: filepath.Join(runtimeDirectory, "vite.json"), subdomain: strings.ReplaceAll(name, "_", "-")}
	if err := os.CopyFS(project.root, os.DirFS(filepath.Join(packageDirectory, "fixtures", "vite", "app"))); err != nil {
		t.Fatal(err)
	}
	nodeModules := filepath.Join(project.root, "node_modules")
	if err := os.MkdirAll(filepath.Join(nodeModules, "@tnldotdev"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(os.Symlink(packageDirectory, filepath.Join(nodeModules, "@tnldotdev", "tnl")),
		os.Symlink(filepath.Join(packageDirectory, "node_modules", "vite"), filepath.Join(nodeModules, "vite")),
		os.WriteFile(filepath.Join(project.root, "package.json"), []byte(`{"private":true,"type":"module"}`), 0o600)); err != nil {
		t.Fatal(err)
	}
	writeIntegrationDevConfig(t, project, map[string]any{"command": []string{"node", filepath.Join(packageDirectory, "fixtures", "vite", "dev-binary.ts"), project.reportPath}, "startup_timeout": "30s"})
	return project
}

func writeIntegrationDevConfig(t *testing.T, project integrationBinaryDevProject, dev map[string]any) {
	t.Helper()
	document := map[string]any{"version": 1, "tnl": map[string]any{"server": "https://control.127.0.0.1.nip.io",
		"services": map[string]any{"api": map[string]any{"tunnel": map[string]any{"subdomain": project.subdomain}, "dev": dev}}}}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project.root, "tnl.json"), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
}

type integrationBinaryDevReport struct {
	PID                   int                         `json:"pid"`
	CWD                   string                      `json:"cwd"`
	Protocol              string                      `json:"protocol"`
	Socket                string                      `json:"socket"`
	HasAccessToken        bool                        `json:"hasAccessToken"`
	HasLoginToken         bool                        `json:"hasLoginToken"`
	HasRuntimeEnvironment bool                        `json:"hasRuntimeEnvironment"`
	Target                string                      `json:"target"`
	Runtime               *projectmeta.PublicMetadata `json:"runtime"`
}

func readIntegrationBinaryDevReport(path string) (integrationBinaryDevReport, error) {
	var report integrationBinaryDevReport
	encoded, err := os.ReadFile(path)
	if err == nil {
		err = json.Unmarshal(encoded, &report)
	}
	return report, err
}

func assertIntegrationBinaryDevCleanup(t *testing.T, report integrationBinaryDevReport) {
	t.Helper()
	waitForIntegrationCondition(t, 5*time.Second, func(context.Context) (bool, error) {
		err := syscall.Kill(report.PID, 0)
		return errors.Is(err, syscall.ESRCH), fmt.Errorf("Vite child %d still exists: %v", report.PID, err)
	})
	if report.Target != "" {
		connection, err := net.DialTimeout("tcp", strings.TrimPrefix(report.Target, "http://"), time.Second)
		if err == nil {
			_ = connection.Close()
			t.Error("Vite listener remained reachable after tnl dev exited")
		}
	}
	if _, err := os.Lstat(report.Socket); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("development socket was not removed: %v", err)
	}
	lock, err := os.OpenFile(strings.TrimSuffix(report.Socket, ".sock")+".lock", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatalf("development service lock was not released: %v", err)
	}
	_ = unix.Flock(int(lock.Fd()), unix.LOCK_UN)
}
