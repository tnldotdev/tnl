package tnldruntime

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
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
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/projectmeta"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"golang.org/x/net/websocket"
	"golang.org/x/sys/unix"
)

func TestIntegrationBinaryStandaloneDev(t *testing.T) {
	fixture := startIntegrationBinaryStandalone(t)
	for _, test := range []struct{ name, maintenance string }{
		{name: "visitor_and_cancellation"},
		{name: "cancel_during_provisioning", maintenance: "certificate_issuance"},
		{name: "provisioning_failure", maintenance: "route_creation"},
	} {
		t.Run(test.name, func(t *testing.T) {
			testIntegrationBinaryDev(t, fixture, test.name, test.maintenance)
		})
	}
	t.Run("next_hmr", func(t *testing.T) {
		testIntegrationBinaryNextDev(t, fixture)
	})
}

func testIntegrationBinaryNextDev(t *testing.T, fixture *integrationBinaryStandalone) {
	t.Helper()
	project := newIntegrationBinaryNextDevProject(t, fixture.repositoryRoot)
	environment := append(append([]string(nil), fixture.environment...),
		"XDG_RUNTIME_DIR="+project.runtimeDirectory,
	)
	dev := startIntegrationBinaryProcess(t, project.root, environment, fixture.tnlPath,
		"dev", "api", "--public")
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("tnl dev output:\n%s\ntnld output:\n%s", dev.output.String(), fixture.server.output.String())
		}
	})
	state, err := clientstate.Open(t.Context(), fixture.stateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })

	var tunnel clientstate.TunnelInfo
	waitForIntegrationCondition(t, 60*time.Second, func() (bool, error) {
		snapshot, err := state.SnapshotProject(t.Context(), project.root)
		if err != nil {
			return false, err
		}
		if len(snapshot.Tunnels) == 1 && snapshot.Tunnels[0].State == clientstate.TunnelStateReady {
			tunnel = snapshot.Tunnels[0]
			return true, nil
		}
		select {
		case <-dev.done:
			t.Fatalf("tnl dev exited before Next.js was ready: %v\n%s", dev.result(), dev.output.String())
		default:
		}
		return false, nil
	})
	if tunnel.Command != clientstate.TunnelCommandDev || tunnel.Service != "api" ||
		tunnel.Framework != "next" || tunnel.RouteID == "" || tunnel.RouteVersion != 1 ||
		!strings.HasPrefix(tunnel.Hostname, project.subdomain+".") {
		t.Fatalf("configured Next.js tunnel = %#v", tunnel)
	}
	waitForReadyPublisherConnections(t, inspectStandaloneTestDatabase(t, fixture.databaseURL),
		tunnel.RouteID, tunnel.RouteVersion, 2)
	visitor := newIntegrationVisitor(t, fixture.pebble.roots, "")
	waitForIntegrationCondition(t, 30*time.Second, func() (bool, error) {
		response, body, err := visitor.requestURL(http.MethodGet, tunnel.PublicURL, nil)
		if err != nil {
			return false, err
		}
		if response.StatusCode != http.StatusOK || response.Header.Get("X-Tnl-Fixture") != "next" ||
			!bytes.Contains(body, []byte("Next.js fixture")) {
			return false, fmt.Errorf("Next.js visitor response = %s, %q", response.Status, body)
		}
		assertIntegrationRouteCertificate(t, response, tunnel.Hostname)
		return true, nil
	})
	assertIntegrationNextHMR(t, fixture.pebble.roots, tunnel.Hostname)
	stopIntegrationBinaryProcess(t, dev)
}

func testIntegrationBinaryDev(t *testing.T, fixture *integrationBinaryStandalone, name, maintenance string) {
	t.Helper()
	state, err := clientstate.Open(t.Context(), fixture.stateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	profile, err := state.Server(t.Context(), "https://control.127.0.0.1.nip.io")
	if err != nil {
		t.Fatal(err)
	}
	session, found, err := profile.ControlSession(t.Context())
	if err != nil || !found || session.AccessToken == "" {
		t.Fatalf("read isolated login session: found %t, error %v", found, err)
	}
	database := inspectStandaloneTestDatabase(t, fixture.databaseURL)

	if maintenance != "" {
		// Exercise persisted publishing gates, not the unrelated admin CLI.
		setEnabled := func(enabled bool) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var actual bool
			err := database.QueryRowContext(ctx, `
				UPDATE control.maintenance_controls
				SET enabled = $2, revision = revision + 1, updated_at = now(), updated_by = 'binary-test'
				WHERE control_name = $1 RETURNING enabled
			`, maintenance, enabled).Scan(&actual)
			if err != nil || actual != enabled {
				t.Fatalf("set maintenance control %s to %t: %v", maintenance, enabled, err)
			}
		}
		setEnabled(false)
		t.Cleanup(func() { setEnabled(true) })
	}
	project := newIntegrationBinaryDevProject(t, fixture.repositoryRoot, name)
	environment := append(append([]string(nil), fixture.environment...),
		"TNL_ACCESS_TOKEN="+session.AccessToken,
		"TNL_LOGIN_TOKEN=test-login-token-sentinel",
		"TNL_PROJECT_RUNTIME=stale-parent-metadata",
		"TNL_FIXTURE_HOST=127.0.0.1", "TNL_FIXTURE_PORT=0",
		"XDG_RUNTIME_DIR="+project.runtimeDirectory,
	)
	// Register fallback cleanup before the parent process cleanup so tnl gets
	// the first opportunity to stop its own process group.
	t.Cleanup(func() {
		report, err := readIntegrationBinaryDevReport(project.reportPath)
		if err == nil && report.PID > 0 && syscall.Kill(report.PID, 0) == nil {
			_ = syscall.Kill(-report.PID, syscall.SIGKILL)
			t.Error("tnl dev left its Vite process running")
		}
	})
	dev := startIntegrationBinaryProcess(t, project.root, environment, fixture.tnlPath,
		"dev", "api", "--public")
	if maintenance == "route_creation" {
		dev.wantExitCode = 1
	}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("tnl dev output:\n%s\ntnld output:\n%s", dev.output.String(), fixture.server.output.String())
		}
	})

	var report integrationBinaryDevReport
	waitForIntegrationCondition(t, 30*time.Second, func() (bool, error) {
		var err error
		report, err = readIntegrationBinaryDevReport(project.reportPath)
		if err == nil && report.Runtime != nil && (maintenance == "route_creation" || report.Target != "") {
			return true, nil
		}
		select {
		case <-dev.done:
			t.Fatalf("tnl dev exited before Vite registration: %v\n%s", dev.result(), dev.output.String())
		default:
		}
		return false, err
	})
	if report.PID <= 0 || report.CWD != project.root || report.Protocol != "1" ||
		!strings.HasPrefix(report.Socket, project.runtimeDirectory+string(filepath.Separator)) ||
		report.HasAccessToken || report.HasLoginToken || report.HasRuntimeEnvironment {
		t.Fatalf("Vite child environment = %#v", report)
	}
	var metadata projectmeta.Metadata
	encoded, err := os.ReadFile(filepath.Join(project.root, ".tnl", "project.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, &metadata); err != nil {
		t.Fatalf("decode generated project metadata: %v", err)
	}
	if err := metadata.Validate(); err != nil {
		t.Fatal(err)
	}
	hostname := project.subdomain + "." + metadata.MemberNamespace
	publicURL := "https://" + hostname
	wantService := projectmeta.Service{
		MemberNamespace: metadata.MemberNamespace, Hostname: hostname, URL: publicURL,
	}
	if !strings.HasSuffix(metadata.MemberNamespace, ".routes.127.0.0.1.nip.io") ||
		len(metadata.Services) != 1 || metadata.Services["api"] != wantService ||
		metadata.ServiceDirectories["api"] != "." ||
		!reflect.DeepEqual(*report.Runtime, metadata.Public(true)) {
		t.Fatalf("generated metadata = %#v, Vite runtime = %#v", metadata, report.Runtime)
	}

	if maintenance == "route_creation" {
		select {
		case <-dev.done:
			assertIntegrationBinaryProcessResult(t, dev)
		case <-time.After(15 * time.Second):
			t.Fatal("tnl dev did not exit after route creation was rejected")
		}
		if !strings.Contains(dev.output.String(), controlclient.ErrUnavailable.Error()) {
			t.Fatalf("missing control provisioning error:\n%s", dev.output.String())
		}
	} else {
		wantState := clientstate.TunnelStateReady
		if maintenance != "" {
			wantState = clientstate.TunnelStateProvisioning
		}
		var tunnel clientstate.TunnelInfo
		waitForIntegrationCondition(t, 45*time.Second, func() (bool, error) {
			snapshot, err := state.SnapshotProject(t.Context(), project.root)
			if err != nil {
				return false, err
			}
			if len(snapshot.Tunnels) == 1 {
				tunnel = snapshot.Tunnels[0]
				if tunnel.State == wantState && tunnel.RouteVersion != 0 {
					return true, nil
				}
			}
			select {
			case <-dev.done:
				t.Fatalf("tnl dev exited before %s: %v\n%s", wantState, dev.result(), dev.output.String())
			default:
			}
			return false, nil
		})
		if tunnel.Command != clientstate.TunnelCommandDev || tunnel.Service != "api" ||
			tunnel.ProcessID != dev.command.Process.Pid || tunnel.Framework != "vite" ||
			tunnel.Target != report.Target || tunnel.Hostname != hostname ||
			tunnel.PublicURL != publicURL || tunnel.RouteID == "" || tunnel.RouteVersion != 1 {
			t.Fatalf("configured Vite tunnel = %#v, child = %#v", tunnel, report)
		}
		var challenge, scope string
		var identifiers []byte
		if err := database.QueryRowContext(t.Context(), `
			SELECT certificate_challenge, certificate_scope, to_json(certificate_identifiers)
			FROM control.route_sessions WHERE route_id = $1 AND route_version = $2
		`, tunnel.RouteID, tunnel.RouteVersion).Scan(&challenge, &scope, &identifiers); err != nil {
			t.Fatal(err)
		}
		var names []string
		if err := json.Unmarshal(identifiers, &names); err != nil {
			t.Fatal(err)
		}
		wantPlan := controlv1.CertificatePlan{
			CacheKey: hostname, Scope: hostname, Identifiers: []string{hostname}, ChallengeMethod: controlv1.TlsAlpn01,
		}
		slices.Sort(names)
		if challenge != string(wantPlan.ChallengeMethod) || scope != wantPlan.Scope || !slices.Equal(names, wantPlan.Identifiers) {
			t.Fatalf("certificate plan = %q, %q, %s, want %#v", challenge, scope, identifiers, wantPlan)
		}
		if maintenance == "" {
			var csrDER []byte
			if err := database.QueryRowContext(t.Context(), `
				SELECT csr_der FROM control.acme_orders
				WHERE route_id = $1 AND route_version = $2 ORDER BY created_at DESC LIMIT 1
			`, tunnel.RouteID, tunnel.RouteVersion).Scan(&csrDER); err != nil {
				t.Fatal(err)
			}
			csr, err := x509.ParseCertificateRequest(csrDER)
			if err != nil {
				t.Fatal(err)
			}
			slices.Sort(csr.DNSNames)
			if err := csr.CheckSignature(); err != nil || !slices.Equal(csr.DNSNames, names) {
				t.Fatalf("dev CSR does not match the certificate plan: names %v, signature %v", csr.DNSNames, err)
			}
			waitForReadyPublisherConnections(t, database, tunnel.RouteID, tunnel.RouteVersion, 2)
			visitor := newIntegrationVisitor(t, fixture.pebble.roots, "")
			waitForIntegrationCondition(t, 10*time.Second, func() (bool, error) {
				response, body, err := visitor.requestURL(http.MethodGet, publicURL+"/", nil)
				if err != nil {
					return false, err
				}
				if response.StatusCode != http.StatusOK || response.Header.Get("X-Tnl-Fixture") != "vite" ||
					!bytes.Contains(body, []byte("Vite fixture")) {
					return false, fmt.Errorf("Vite visitor response = %s, %q", response.Status, body)
				}
				assertIntegrationRouteCertificate(t, response, hostname)
				actual := slices.Clone(response.TLS.PeerCertificates[0].DNSNames)
				slices.Sort(actual)
				if !slices.Equal(actual, names) {
					t.Fatalf("visitor certificate SANs = %v, want %v", actual, names)
				}
				return true, nil
			})
			response, body, err := visitor.requestURL(http.MethodGet, publicURL+"/src/main.ts", nil)
			if err != nil || response.StatusCode != http.StatusOK || !bytes.Contains(body, []byte("/dist/index.js")) {
				t.Fatalf("Vite app module: %v, body %q", err, body)
			}
			runtimePath := "/@fs" + filepath.ToSlash(filepath.Join(fixture.repositoryRoot, "packages", "tnl", "dist", "index.js"))
			response, body, err = visitor.requestURL(http.MethodGet, publicURL+runtimePath, nil)
			if err != nil || response.StatusCode != http.StatusOK || bytes.Contains(body, []byte(session.AccessToken)) {
				t.Fatalf("Vite browser runtime module: %v", err)
			}
			// Vite installs development defines through the environment module
			// imported by its client, rather than replacing them in index.js.
			response, body, err = visitor.requestURL(http.MethodGet, publicURL+"/@vite/client", nil)
			if err != nil || response.StatusCode != http.StatusOK {
				t.Fatalf("Vite browser client: %v", err)
			}
			assertIntegrationViteHMR(t, fixture.pebble.roots, hostname, body)
			environmentImport := regexp.MustCompile(`(?m)^import "(/@fs/[^"]+/env\.mjs)";`).FindSubmatch(body)
			if environmentImport == nil {
				t.Fatal("Vite client did not import its environment module")
			}
			response, body, err = visitor.requestURL(http.MethodGet, publicURL+string(environmentImport[1]), nil)
			if err != nil || response.StatusCode != http.StatusOK || bytes.Contains(body, []byte(session.AccessToken)) {
				t.Fatalf("Vite browser environment module: %v", err)
			}
			defines := regexp.MustCompile(`(?m)^const defines = (\{.*\});$`).FindSubmatch(body)
			if defines == nil {
				t.Fatal("Vite environment module did not contain its development defines")
			}
			var values map[string]string
			if err := json.Unmarshal(defines[1], &values); err != nil {
				t.Fatal(err)
			}
			var browserMetadata projectmeta.PublicMetadata
			if err := json.Unmarshal([]byte(values["process.env.TNL_PROJECT_RUNTIME"]), &browserMetadata); err != nil ||
				!reflect.DeepEqual(browserMetadata, metadata.Public(true)) {
				t.Fatalf("Vite browser metadata = %#v, error %v", browserMetadata, err)
			}
		}
		stopIntegrationBinaryProcess(t, dev)
		waitForReadyPublisherConnections(t, database, tunnel.RouteID, tunnel.RouteVersion, 0)
	}

	snapshot, err := state.SnapshotProject(t.Context(), project.root)
	if err != nil || len(snapshot.Tunnels) != 0 {
		t.Fatalf("local tunnel remained active after exit: %#v, %v", snapshot, err)
	}
	waitForIntegrationCondition(t, 10*time.Second, func() (bool, error) {
		var open int
		err := database.QueryRowContext(t.Context(), `
			SELECT count(*) FROM control.route_sessions AS sessions
			JOIN control.routes AS routes ON routes.id = sessions.route_id
			WHERE routes.canonical_hostname = $1 AND sessions.closed_at IS NULL
		`, hostname).Scan(&open)
		return err == nil && open == 0, err
	})
	assertIntegrationBinaryDevCleanup(t, report)
	if maintenance == "" {
		visitor := newIntegrationVisitor(t, fixture.pebble.roots, "")
		response, _, err := visitor.requestURL(http.MethodGet, publicURL+"/", nil)
		if err == nil && response.StatusCode == http.StatusOK {
			t.Error("visitor route remained reachable after tnl dev exited")
		}
	}
}

func assertIntegrationViteHMR(t *testing.T, roots *x509.CertPool, hostname string, client []byte) {
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
	connection, err := websocket.DialConfig(config)
	if err != nil {
		t.Fatalf("connect Vite HMR through public route: %v", err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var payload string
	if err := websocket.Message.Receive(connection, &payload); err != nil {
		t.Fatalf("receive Vite HMR message through public route: %v", err)
	}
	var message struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal([]byte(payload), &message); err != nil || message.Type != "connected" {
		t.Fatalf("Vite HMR message = %q, error %v", payload, err)
	}
}

func assertIntegrationNextHMR(t *testing.T, roots *x509.CertPool, hostname string) {
	t.Helper()
	config, err := websocket.NewConfig("wss://"+hostname+"/_next/hmr?id=tnl-integration", "https://"+hostname)
	if err != nil {
		t.Fatal(err)
	}
	config.TlsConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}
	connection, err := websocket.DialConfig(config)
	if err != nil {
		t.Fatalf("connect Next.js HMR through public route: %v", err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var payload string
	if err := websocket.Message.Receive(connection, &payload); err != nil {
		t.Fatalf("receive Next.js HMR message through public route: %v", err)
	}
	var message struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal([]byte(payload), &message); err != nil ||
		(message.Type != "isrManifest" && message.Type != "turbopack-connected") {
		t.Fatalf("Next.js HMR message = %q, error %v", payload, err)
	}
}

type integrationBinaryDevProject struct {
	root             string
	runtimeDirectory string
	reportPath       string
	subdomain        string
}

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
	project := integrationBinaryDevProject{
		root: filepath.Join(t.TempDir(), "project"), runtimeDirectory: runtimeDirectory, subdomain: "next-hmr",
	}
	runIntegrationBinaryCommand(t, repositoryRoot, integrationBinaryEnvironment(nil), "pnpm",
		"--filter", "@tnldotdev/tnl", "deploy", "--legacy", project.root)
	fixtureDirectory := filepath.Join(packageDirectory, "fixtures", "next", "app")
	for _, name := range []string{"next.config.ts", "app/layout.tsx", "app/page.tsx"} {
		source := filepath.Join(fixtureDirectory, filepath.FromSlash(name))
		destination := filepath.Join(project.root, filepath.FromSlash(name))
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
	document := map[string]any{
		"version": 1,
		"tnl": map[string]any{
			"server": "https://control.127.0.0.1.nip.io",
			"services": map[string]any{"api": map[string]any{
				"tunnel": map[string]any{"subdomain": project.subdomain},
				"dev": map[string]any{
					"command": []string{"node", filepath.Join(nodeModules, "next", "dist", "bin", "next"), "dev", "--hostname", "127.0.0.1"},
				},
			}},
		},
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project.root, "tnl.json"), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	return project
}

func newIntegrationBinaryDevProject(t *testing.T, repositoryRoot, name string) integrationBinaryDevProject {
	t.Helper()
	packageDirectory := filepath.Join(repositoryRoot, "packages", "tnl")
	if _, err := os.Stat(filepath.Join(packageDirectory, "dist", "vite.js")); err != nil {
		t.Fatal("built @tnldotdev/tnl is required; run mise exec -- pnpm --filter @tnldotdev/tnl build")
	}
	// Keep the runtime socket path comfortably below Unix socket length limits.
	runtimeDirectory, err := os.MkdirTemp("/tmp", "tnl-dev-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(runtimeDirectory) })
	project := integrationBinaryDevProject{
		root: t.TempDir(), runtimeDirectory: runtimeDirectory,
		reportPath: filepath.Join(runtimeDirectory, "vite.json"), subdomain: strings.ReplaceAll(name, "_", "-"),
	}
	if err := os.CopyFS(project.root, os.DirFS(filepath.Join(packageDirectory, "fixtures", "vite", "app"))); err != nil {
		t.Fatal(err)
	}
	nodeModules := filepath.Join(project.root, "node_modules")
	if err := os.MkdirAll(filepath.Join(nodeModules, "@tnldotdev"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(
		os.Symlink(packageDirectory, filepath.Join(nodeModules, "@tnldotdev", "tnl")),
		os.Symlink(filepath.Join(packageDirectory, "node_modules", "vite"), filepath.Join(nodeModules, "vite")),
		os.WriteFile(filepath.Join(project.root, "package.json"), []byte(`{"private":true,"type":"module"}`), 0o600),
	); err != nil {
		t.Fatal(err)
	}
	document := map[string]any{
		"version": 1,
		"tnl": map[string]any{
			"server": "https://control.127.0.0.1.nip.io",
			"services": map[string]any{"api": map[string]any{
				"tunnel": map[string]any{"subdomain": project.subdomain},
				"dev": map[string]any{
					"command":         []string{"node", filepath.Join(packageDirectory, "fixtures", "vite", "dev-binary.mjs"), project.reportPath},
					"startup_timeout": "30s",
				},
			}},
		},
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project.root, "tnl.json"), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	return project
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
	waitForIntegrationCondition(t, 5*time.Second, func() (bool, error) {
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
