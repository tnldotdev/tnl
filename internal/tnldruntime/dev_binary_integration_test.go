package tnldruntime

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/projectmeta"
)

func TestBinaryIntegrationStandaloneDev(t *testing.T) {
	fixture := startIntegrationBinaryStandalone(t)
	t.Run("visitor_and_cancellation", func(t *testing.T) { testIntegrationViteHappyPath(t, fixture) })
	t.Run("cancel_during_provisioning", func(t *testing.T) { testIntegrationViteCancelProvisioning(t, fixture) })
	t.Run("provisioning_failure", func(t *testing.T) { testIntegrationViteRejected(t, fixture) })
	t.Run("next_hmr", func(t *testing.T) { testIntegrationBinaryNextDev(t, fixture) })
}

func testIntegrationViteHappyPath(t *testing.T, server *integrationBinaryStandalone) {
	f := newIntegrationViteFixture(t, server, "visitor_and_cancellation")
	f.start(t, 0)
	f.waitRegistration(t, true)
	tunnel := f.waitTunnel(t, clientstate.TunnelStateReady)
	names := f.assertCertificatePlan(t, tunnel)
	var csrDER []byte
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := f.database.QueryRowContext(ctx, `
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
		t.Fatalf("dev CSR does not match certificate plan: names %v, signature %v", csr.DNSNames, err)
	}
	waitForReadyPublisherConnections(t, f.database, tunnel.RouteID, tunnel.RouteVersion, 2)
	visitor := newIntegrationVisitor(t, server.pebble.roots, "")
	waitForIntegrationCondition(t, 10*time.Second, func(ctx context.Context) (bool, error) {
		response, body, err := visitor.requestURLContext(ctx, http.MethodGet, f.publicURL+"/", nil)
		if err != nil {
			return false, err
		}
		if response.StatusCode != http.StatusOK || response.Header.Get("X-Tnl-Fixture") != "vite" || !bytes.Contains(body, []byte("Vite fixture")) {
			return false, fmt.Errorf("Vite visitor response = %s, %q", response.Status, body)
		}
		assertIntegrationRouteCertificate(t, response, f.hostname)
		actual := slices.Clone(response.TLS.PeerCertificates[0].DNSNames)
		slices.Sort(actual)
		if !slices.Equal(actual, names) {
			t.Fatalf("visitor certificate SANs = %v, want %v", actual, names)
		}
		return true, nil
	})
	response, body, err := visitor.requestURL(http.MethodGet, f.publicURL+"/src/main.ts", nil)
	if err != nil || response.StatusCode != http.StatusOK || !bytes.Contains(body, []byte("/dist/index.js")) {
		t.Fatalf("Vite app module: %v, body %q", err, body)
	}
	runtimePath := "/@fs" + filepath.ToSlash(filepath.Join(server.repositoryRoot, "packages", "tnl", "dist", "index.js"))
	response, body, err = visitor.requestURL(http.MethodGet, f.publicURL+runtimePath, nil)
	if err != nil || response.StatusCode != http.StatusOK || bytes.Contains(body, []byte(f.accessToken)) {
		t.Fatalf("Vite browser runtime module: %v", err)
	}
	// Vite installs development defines in the environment module its client imports.
	response, body, err = visitor.requestURL(http.MethodGet, f.publicURL+"/@vite/client", nil)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("Vite browser client: %v", err)
	}
	assertIntegrationViteHMR(t, server.pebble.roots, f.hostname, body,
		filepath.Join(f.project.root, "src", "main.ts"))
	response, updatedBody, err := visitor.requestURL(http.MethodGet,
		f.publicURL+"/src/main.ts?t="+fmt.Sprint(time.Now().UnixNano()), nil)
	if err != nil || response.StatusCode != http.StatusOK ||
		!bytes.Contains(updatedBody, []byte("Vite fixture HMR")) {
		t.Fatalf("updated Vite app module: %v, body %q", err, updatedBody)
	}
	environmentImport := regexp.MustCompile(`(?m)^import "(/@fs/[^"]+/env\.mjs)";`).FindSubmatch(body)
	if environmentImport == nil {
		t.Fatal("Vite client did not import its environment module")
	}
	response, body, err = visitor.requestURL(http.MethodGet, f.publicURL+string(environmentImport[1]), nil)
	if err != nil || response.StatusCode != http.StatusOK || bytes.Contains(body, []byte(f.accessToken)) {
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
	if err := json.Unmarshal([]byte(values["process.env.TNL_PROJECT_RUNTIME"]), &browserMetadata); err != nil || !reflect.DeepEqual(browserMetadata, f.metadata.Public(true)) {
		t.Fatalf("Vite browser metadata = %#v, error %v", browserMetadata, err)
	}
	f.stopTunnel(t, tunnel)
	f.assertCleanup(t)
	response, _, err = visitor.requestURL(http.MethodGet, f.publicURL+"/", nil)
	if err == nil && response.StatusCode == http.StatusOK {
		t.Error("visitor route remained reachable after tnl dev exited")
	}
}

func testIntegrationViteCancelProvisioning(t *testing.T, server *integrationBinaryStandalone) {
	f := newIntegrationViteFixture(t, server, "cancel_during_provisioning")
	f.disableMaintenance(t, "certificate_issuance")
	f.start(t, 0)
	f.waitRegistration(t, true)
	tunnel := f.waitTunnel(t, clientstate.TunnelStateProvisioning)
	f.assertCertificatePlan(t, tunnel)
	f.stopTunnel(t, tunnel)
	f.assertCleanup(t)
}

func testIntegrationViteRejected(t *testing.T, server *integrationBinaryStandalone) {
	f := newIntegrationViteFixture(t, server, "provisioning_failure")
	f.disableMaintenance(t, "route_creation")
	f.start(t, 1)
	f.waitRegistration(t, false)
	if err := waitForDoneWithin(f.dev.done, 15*time.Second); err != nil {
		t.Fatal("tnl dev did not exit after route creation was rejected")
	}
	assertIntegrationBinaryProcessResult(t, f.dev)
	if !strings.Contains(f.dev.output.String(), controlclient.ErrUnavailable.Error()) {
		t.Fatalf("missing control provisioning error:\n%s", f.dev.output.String())
	}
	f.assertCleanup(t)
}

func testIntegrationBinaryNextDev(t *testing.T, fixture *integrationBinaryStandalone) {
	t.Helper()
	project := newIntegrationBinaryNextDevProject(t, fixture.repositoryRoot)
	environment := append(append([]string(nil), fixture.environment...), "XDG_RUNTIME_DIR="+project.runtimeDirectory)
	dev := startIntegrationBinaryProcess(t, project.root, environment, fixture.tnlPath, "dev", "api", "--allow-all-ips")
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("tnl dev output:\n%s\ntnld output:\n%s", dev.output.String(), fixture.server.output.String())
		}
	})
	state, err := clientstate.Open(integrationOperationContext(t), fixture.stateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	var tunnel clientstate.TunnelInfo
	waitForIntegrationCondition(t, 60*time.Second, func(ctx context.Context) (bool, error) {
		snapshot, err := state.SnapshotProject(ctx, project.root)
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
	if tunnel.Command != clientstate.TunnelCommandDev || tunnel.Service != "api" || tunnel.Framework != "next" || tunnel.RouteID == "" || tunnel.RouteVersion != 1 || !strings.HasPrefix(tunnel.Hostname, project.subdomain+".") {
		t.Fatalf("configured Next.js tunnel = %#v", tunnel)
	}
	waitForReadyPublisherConnections(t, inspectStandaloneTestDatabase(t, fixture.databaseURL), tunnel.RouteID, tunnel.RouteVersion, 2)
	visitor := newIntegrationVisitor(t, fixture.pebble.roots, "")
	waitForIntegrationCondition(t, 30*time.Second, func(ctx context.Context) (bool, error) {
		response, body, err := visitor.requestURLContext(ctx, http.MethodGet, tunnel.PublicURL, nil)
		if err != nil {
			return false, err
		}
		if response.StatusCode != http.StatusOK || response.Header.Get("X-Tnl-Fixture") != "next" || !bytes.Contains(body, []byte("Next.js fixture")) {
			return false, fmt.Errorf("Next.js visitor response = %s, %q", response.Status, body)
		}
		assertIntegrationRouteCertificate(t, response, tunnel.Hostname)
		return true, nil
	})
	assertIntegrationNextHMR(t, fixture.pebble.roots, tunnel.Hostname,
		filepath.Join(project.root, "app", "page.tsx"))
	waitForIntegrationCondition(t, 30*time.Second, func(ctx context.Context) (bool, error) {
		response, body, err := visitor.requestURLContext(ctx, http.MethodGet, tunnel.PublicURL, nil)
		if err != nil {
			return false, err
		}
		if response.StatusCode != http.StatusOK {
			return false, fmt.Errorf("Next.js post-edit visitor response = %s, %q", response.Status, body)
		}
		return bytes.Contains(body, []byte("Next.js fixture refreshed")), nil
	})
	stopIntegrationBinaryProcess(t, dev)
}
