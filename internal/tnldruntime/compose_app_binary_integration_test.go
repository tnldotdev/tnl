package tnldruntime

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/projectmeta"
)

func TestBinaryIntegrationComposeAppAndDatabaseVisitor(t *testing.T) {
	fixture := startIntegrationBinaryStandaloneTCP(t)
	control, err := controlstate.Open(t.Context(), fixture.databaseURL, testStorageKey, "", naming.ManagedURLModeSimple)
	if err != nil {
		t.Fatal(err)
	}
	if err := control.EnsurePrimaryIngressPool(t.Context(), "127.0.0.1", "", []int32{15432, 15433}, time.Now()); err != nil {
		t.Fatal(err)
	}
	control.Close()
	bridgeCommand := exec.CommandContext(t.Context(), "docker", "network", "inspect", "bridge", "--format", "{{(index .IPAM.Config 0).Gateway}}")
	bridgeOutput, err := bridgeCommand.Output()
	if err != nil {
		t.Fatal(err)
	}
	gateway := strings.TrimSpace(string(bridgeOutput))
	if address, err := netip.ParseAddr(gateway); err != nil || !address.Is4() || address.IsLoopback() {
		t.Fatalf("disposable Docker bridge has no host address: %q, %v", gateway, err)
	}
	stopContainerPublicProxy := startIntegrationPublicProxy(t, "127.0.0.2:443",
		net.JoinHostPort(gateway, "443"), net.JoinHostPort(gateway, "15432"), net.JoinHostPort(gateway, "15433"))
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	labelProcess := startIntegrationBinaryProcess(t, root, fixture.environment, fixture.tnlPath, "project", "label", "--output", "raw")
	if err := waitForDoneWithin(labelProcess.done, 20*time.Second); err != nil {
		t.Fatal(err)
	}
	assertIntegrationBinaryProcessResult(t, labelProcess)
	label := strings.TrimSpace(labelProcess.output.String())
	ownerFile := filepath.Join(t.TempDir(), "publisher-owner")
	configuration := fmt.Sprintf(`{"version":1,"tnl":{"server":"https://control.127.0.0.1.nip.io","publisher":{"type":"docker","compose":{"file":"compose.yaml","project":%q,"service":"publisher"},"container_port":3781,"owner_credential_file":%q},"services":{"web":{"target":{"type":"app"},"tunnel":{"name":"binary-compose-web","allow_all_ips":true}},"orders":{"protocol":"postgres","target":{"type":"address","address":"db:5432"},"tunnel":{"name":"binary-compose-orders","allow_all_ips":true}}}}}`, label, ownerFile)
	if err := os.WriteFile(filepath.Join(root, "tnl.json"), []byte(configuration), 0600); err != nil {
		t.Fatal(err)
	}
	runIntegrationBinaryCommand(t, root, fixture.environment, fixture.tnlPath, "config", "generate")
	metadataFile := filepath.Join(root, ".tnl", "project.json")
	data, err := os.ReadFile(metadataFile)
	if err != nil {
		t.Fatal(err)
	}
	var metadata projectmeta.Metadata
	if err := json.Unmarshal(data, &metadata); err != nil || metadata.Worktree == nil || metadata.Worktree.Label.FullLabel != label || metadata.Services["orders"].Port == nil {
		t.Fatalf("saved web/database metadata before start = %s, %v", data, err)
	}
	webURL, databaseURL := metadata.Services["web"].URL, metadata.Services["orders"].URL
	if webURL == "" || databaseURL == "" {
		t.Fatal("project preparation omitted a saved public URL")
	}
	webOrigin, err := url.Parse(webURL)
	if err != nil {
		t.Fatal(err)
	}
	publicDatabaseHost, _, err := net.SplitHostPort(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	runIntegrationBinaryCommand(t, root, fixture.environment, fixture.tnlPath, "project", "publisher", "credential", "create")
	appModule := (&url.URL{Scheme: "file", Path: filepath.Join(fixture.repositoryRoot, "packages", "ts", "dist", "internal", "app.js")}).String()
	appSource := fmt.Sprintf(`import {createServer} from "node:http";
import {writeFileSync} from "node:fs";
import {prepareService} from %q;
const handle = await prepareService({directory: "/app", service: "web"});
const server = createServer((_request, response) => response.setHeader("Content-Type", "application/json").end(JSON.stringify({databaseURL:handle.services.orders.url})));
await new Promise(resolve => server.listen(0, "0.0.0.0", resolve));
await handle.register(server);
writeFileSync("/app/ready.json", JSON.stringify({port:server.address().port,url:handle.publicURL}));
`, appModule)
	if err := os.WriteFile(filepath.Join(root, "app.mjs"), []byte(appSource), 0644); err != nil {
		t.Fatal(err)
	}
	compose := `services:
  publisher-state-init:
    image: tnl:publisher-dev-integration
    user: "0:0"
    entrypoint: ["/bin/sh", "-c", "chown ${TNL_UID}:${TNL_GID} /state /run/tnl-apps/web && chmod 0700 /state /run/tnl-apps/web"]
    volumes: [publisher-state:/state, web-endpoint:/run/tnl-apps/web]
  publisher:
    image: tnl:publisher-dev-integration
    user: "${TNL_UID}:${TNL_GID}"
    working_dir: ${PROJECT_ROOT}
    command: ["runtime", "serve", "--directory", "${PROJECT_ROOT}"]
    environment:
      TNL_PUBLISHER_EXTERNAL: "1"
      TNL_STATE_DIR: /state
      TNL_PUBLISHER_APP_ENDPOINT_DIR: /run/tnl-apps
      TNL_SERVER: https://control.127.0.0.1.nip.io
      SSL_CERT_FILE: /trust/roots.pem
    volumes:
      - ${PROJECT_ROOT}:${PROJECT_ROOT}
      - ${OWNER_FILE}:${OWNER_FILE}:ro
      - ${TRUST_FILE}:/trust/roots.pem:ro
      - publisher-state:/state
      - web-endpoint:/run/tnl-apps/web
    extra_hosts:
      - control.127.0.0.1.nip.io:host-gateway
      - relay.127.0.0.1.nip.io:host-gateway
      - ${PUBLIC_WEB_HOST}:host-gateway
      - ${PUBLIC_DB_HOST}:host-gateway
    ports: ["127.0.0.1::3781"]
    depends_on:
      publisher-state-init: {condition: service_completed_successfully}
  web:
    image: mirror.gcr.io/library/node:22.23.2-bookworm-slim@sha256:48e4b67d85f87bd551df43704e24d252f56cc5f8e9718841aace50f19948f0f9
    user: "${TNL_UID}:${TNL_GID}"
    working_dir: /app
    command: ["node", "/app/app.mjs"]
    environment:
      TNL_PUBLISHER_ENDPOINT_FILE: /run/tnl-app/publisher.endpoint.json
    volumes:
      - ${PROJECT_ROOT}:/app
      - ${TNL_REPOSITORY}:${TNL_REPOSITORY}:ro
      - web-endpoint:/run/tnl-app:ro
    depends_on: [publisher]
  db:
    image: mirror.gcr.io/library/postgres:17.6-alpine@sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94
    environment:
      POSTGRES_USER: shop
      POSTGRES_PASSWORD: devpassword
      POSTGRES_DB: shop
    volumes: [db-data:/var/lib/postgresql/data]
volumes:
  publisher-state:
  web-endpoint:
  db-data:
`
	if err := os.WriteFile(filepath.Join(root, "compose.yaml"), []byte(compose), 0600); err != nil {
		t.Fatal(err)
	}
	composeEnvironment := append([]string{}, fixture.environment...)
	composeEnvironment = append(composeEnvironment,
		"PROJECT_ROOT="+root, "TRUST_FILE="+fixture.trustFile, "TNL_REPOSITORY="+fixture.repositoryRoot,
		"OWNER_FILE="+ownerFile,
		"TNL_UID="+strconv.Itoa(os.Getuid()), "TNL_GID="+strconv.Itoa(os.Getgid()),
		"PUBLIC_WEB_HOST="+webOrigin.Hostname(), "PUBLIC_DB_HOST="+publicDatabaseHost)
	runCompose := func(timeout time.Duration, arguments ...string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		args := append([]string{"compose", "--project-directory", root, "--file", filepath.Join(root, "compose.yaml"), "--project-name", label}, arguments...)
		command := exec.CommandContext(ctx, "docker", args...)
		command.Dir, command.Env = root, composeEnvironment
		output, err := command.CombinedOutput()
		return string(output), err
	}
	t.Cleanup(func() {
		if t.Failed() {
			if output, err := runCompose(10*time.Second, "logs"); err == nil {
				t.Logf("Compose app publisher logs:\n%s", output)
			}
			t.Logf("standalone output:\n%s", fixture.server.output.String())
		}
		if output, err := runCompose(30*time.Second, "down", "--volumes", "--remove-orphans"); err != nil {
			t.Errorf("remove Compose app publisher: %v (%s)", err, output)
		}
	})
	if output, err := runCompose(90*time.Second, "up", "-d", "publisher", "db"); err != nil {
		t.Fatalf("start Compose publisher/database: %v (%s)", err, output)
	}
	loginEnvironment := append(append([]string{}, composeEnvironment...), "TNL_LOGIN_TOKEN="+testLoginToken)
	waitForIntegrationCondition(t, 20*time.Second, func(ctx context.Context) (bool, error) {
		command := exec.CommandContext(ctx, fixture.tnlPath, "auth", "login", "--login-token")
		command.Dir, command.Env = root, loginEnvironment
		output, err := command.CombinedOutput()
		if err != nil {
			return false, fmt.Errorf("selected publisher login: %w (%s)", err, output)
		}
		return true, nil
	})
	waitForIntegrationCondition(t, 20*time.Second, func(_ context.Context) (bool, error) {
		_, err := runCompose(10*time.Second, "exec", "-T", "publisher", "test", "-f", "/run/tnl-apps/web/publisher.endpoint.json")
		return err == nil, err
	})
	if _, err := os.Stat(filepath.Join(root, ".tnl", "publisher-web.endpoint.json")); !os.IsNotExist(err) {
		t.Fatalf("app descriptor was written into shared checkout: %v", err)
	}
	if output, err := runCompose(90*time.Second, "up", "-d", "web"); err != nil {
		t.Fatalf("start Compose app: %v (%s)", err, output)
	}
	var app struct {
		Port int    `json:"port"`
		URL  string `json:"url"`
	}
	waitForIntegrationCondition(t, 25*time.Second, func(_ context.Context) (bool, error) {
		data, err := os.ReadFile(filepath.Join(root, "ready.json"))
		if err != nil {
			return false, err
		}
		if err := json.Unmarshal(data, &app); err != nil {
			return false, err
		}
		return app.Port > 0 && app.URL == webURL, fmt.Errorf("app did not report its saved public URL")
	})
	named := startIntegrationBinaryProcess(t, root, composeEnvironment, fixture.tnlPath, "publish", "orders", "--output=ndjson")
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("Compose database publication output:\n%s", named.output.String())
		}
	})
	runIntegrationBinaryCommand(t, root, composeEnvironment, fixture.tnlPath, "wait", "--service", "web", "--service", "orders", "--timeout", "75s", "--output=json")
	visitor := newIntegrationVisitor(t, fixture.pebble.roots, "")
	waitForIntegrationCondition(t, 30*time.Second, func(ctx context.Context) (bool, error) {
		response, body, err := visitor.requestURLContext(ctx, http.MethodGet, webURL+"/", nil)
		if err != nil || response.StatusCode != http.StatusOK {
			return false, err
		}
		var result struct {
			DatabaseURL string `json:"databaseURL"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			return false, err
		}
		return result.DatabaseURL == databaseURL, fmt.Errorf("app did not receive the saved public database URL")
	})
	waitForIntegrationCondition(t, 30*time.Second, func(ctx context.Context) (bool, error) {
		connection, err := connectPublicPostgres(ctx, fixture, databaseURL)
		if err != nil {
			return false, err
		}
		defer connection.Close(context.Background())
		var answer int
		err = connection.QueryRow(ctx, "SELECT 42").Scan(&answer)
		return err == nil && answer == 42, err
	})
	oldDescriptor, err := runCompose(10*time.Second, "exec", "-T", "publisher", "cat", "/run/tnl-apps/web/publisher.endpoint.json")
	if err != nil {
		t.Fatal(err)
	}
	var oldScope struct {
		Credential string `json:"credential"`
	}
	if err := json.Unmarshal([]byte(oldDescriptor), &oldScope); err != nil {
		t.Fatal(err)
	}
	webContainer, err := runCompose(10*time.Second, "ps", "-q", "web")
	if err != nil || strings.TrimSpace(webContainer) == "" {
		t.Fatalf("app container is not running before publisher restart: %v", err)
	}
	if output, err := runCompose(30*time.Second, "restart", "publisher"); err != nil {
		t.Fatalf("restart Compose publisher: %v (%s)", err, output)
	}
	waitForIntegrationCondition(t, 20*time.Second, func(_ context.Context) (bool, error) {
		_, err := runCompose(10*time.Second, "exec", "-T", "publisher", "test", "-f", "/run/tnl-apps/web/publisher.endpoint.json")
		return err == nil, err
	})
	currentDescriptor, err := runCompose(10*time.Second, "exec", "-T", "publisher", "cat", "/run/tnl-apps/web/publisher.endpoint.json")
	if err != nil {
		t.Fatal(err)
	}
	var currentScope struct {
		Credential string `json:"credential"`
	}
	if err := json.Unmarshal([]byte(currentDescriptor), &currentScope); err != nil || currentScope.Credential == oldScope.Credential {
		t.Fatalf("restarted publisher retained a stale app credential: %v", err)
	}
	runIntegrationBinaryCommand(t, root, composeEnvironment, fixture.tnlPath, "wait", "--service", "web", "--service", "orders", "--timeout", "75s", "--output=json")
	if currentWeb, err := runCompose(10*time.Second, "ps", "-q", "web"); err != nil || strings.TrimSpace(currentWeb) != strings.TrimSpace(webContainer) {
		t.Fatalf("app did not stay running through publisher replacement: %v", err)
	}
	waitForIntegrationCondition(t, 30*time.Second, func(ctx context.Context) (bool, error) {
		response, body, err := visitor.requestURLContext(ctx, http.MethodGet, webURL+"/", nil)
		if err != nil || response.StatusCode != http.StatusOK {
			return false, err
		}
		var result struct {
			DatabaseURL string `json:"databaseURL"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			return false, err
		}
		return result.DatabaseURL == databaseURL, fmt.Errorf("app URL did not recover after publisher restart")
	})
	waitForIntegrationCondition(t, 30*time.Second, func(ctx context.Context) (bool, error) {
		connection, err := connectPublicPostgres(ctx, fixture, databaseURL)
		if err != nil {
			return false, err
		}
		defer connection.Close(context.Background())
		var answer int
		err = connection.QueryRow(ctx, "SELECT 42").Scan(&answer)
		return err == nil && answer == 42, err
	})
	stopContainerPublicProxy()
}
