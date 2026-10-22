package daemon

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	clientruntime "github.com/tnldotdev/tnl/internal/publisher/app"
	publishertarget "github.com/tnldotdev/tnl/internal/publisher/target"
	"github.com/tnldotdev/tnl/internal/testutil"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

var composeHostAddress = flag.String("tnl-test-compose-host-address", "host-gateway", "address of the disposable binary test's ingress on the Docker host")

// an ordinary Compose service publishes a public HTTP target and a private
// database. visitors use public HTTPS or the production tnl connect client.
func TestBinaryIntegrationManualComposePublisherPublicHTTPAndPostgres(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierBinary)
	fixture := startIntegrationBinaryStandaloneWithBind(t, true, "simple")
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	initializeIntegrationBinaryProject(t, root, "compose")
	appBinary := filepath.Join(root, "compose-app-linux")
	buildIntegrationBinary(t, fixture.repositoryRoot, appBinary, "./tests/integration/fixtures/compose-publisher")
	if *composeHostAddress != "host-gateway" {
		if address := net.ParseIP(*composeHostAddress); address == nil || address.To4() == nil {
			t.Fatal("-tnl-test-compose-host-address must be an IPv4 address or host-gateway")
		}
	}
	image := "mirror.gcr.io/library/golang:1.27.3-bookworm@sha256:5c3e9b43cfd3bb95c7937462e29d87ada57b481a96fa23ad0eb61778d7a00110"
	postgresImage := "mirror.gcr.io/library/postgres:17.6-alpine@sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94"
	base := filepath.Join(root, "compose.yaml")
	configuration := fmt.Sprintf("services:\n  publisher:\n    image: %s\n    command: [sleep, infinity]\n    working_dir: /workspace\n    extra_hosts:\n      - control.127.0.0.1.nip.io:host-gateway\n      - relay.127.0.0.1.nip.io:host-gateway\n    environment:\n      SSL_CERT_FILE: /run/tnl/roots.pem\n      TNL_SERVER: https://control.127.0.0.1.nip.io:8445\n      TNL_STATE_DIR: /run/tnl/state/owner-state\n    volumes:\n      - %q\n      - %q\n      - %q\n      - publisher-state:/run/tnl/state\n  web:\n    image: %s\n    command: [/fixture/app]\n    volumes:\n      - %q\n  db:\n    image: %s\n    environment:\n      POSTGRES_PASSWORD: postgres\n    healthcheck:\n      test: [CMD-SHELL, pg_isready -U postgres -d postgres]\n      interval: 2s\n      timeout: 5s\n      retries: 10\nvolumes:\n  publisher-state:\n", image, fixture.tnlPath+":/usr/local/bin/tnl:ro", fixture.trustFile+":/run/tnl/roots.pem:ro", root+":/workspace", image, appBinary+":/fixture/app:ro", postgresImage)
	configuration = strings.ReplaceAll(configuration, ":host-gateway", ":"+*composeHostAddress)
	// the publisher runs as container root while CI owns the mounted repository
	// as the runner user. trust only this fixture's exact checkout for Git reads.
	configuration = strings.Replace(configuration, "      SSL_CERT_FILE:", "      GIT_CONFIG_COUNT: '1'\n      GIT_CONFIG_KEY_0: safe.directory\n      GIT_CONFIG_VALUE_0: /workspace\n      SSL_CERT_FILE:", 1)
	if err := os.WriteFile(base, []byte(configuration), 0600); err != nil {
		t.Fatal(err)
	}
	projectConfig := "version: 1\ntnl:\n  server: https://control.127.0.0.1.nip.io:8445\n  services:\n    web:\n      name: compose-web\n      target: {type: address, address: 'http://web:3000'}\n      public_url: {access: anonymous}\n    db:\n      name: compose-db\n      protocol: postgres\n      access: {team: true}\n      target: {type: address, address: 'db:5432'}\n"
	if err := os.WriteFile(filepath.Join(root, "tnl.yml"), []byte(projectConfig), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	state, err := clientstate.Open(ctx, fixture.stateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	salt, err := state.WorktreeHashSalt(ctx)
	closeErr := state.Close()
	if err != nil || closeErr != nil {
		t.Fatalf("resolve host worktree identity: %v, close: %v", err, closeErr)
	}
	selection, err := clientproject.SelectProjectConfig(ctx, root, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	project, err := clientproject.Resolve(ctx, selection, root, salt)
	if err != nil {
		t.Fatal(err)
	}
	args := publishertarget.ComposeArgs(root, base, project.Worktree.Label.FullLabel)
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 45*time.Second)
		defer stop()
		command := exec.CommandContext(cleanup, "docker", append(append([]string{}, args...), "down", "--volumes", "--remove-orphans", "--timeout", "2")...)
		command.Dir = root
		if output, err := command.CombinedOutput(); err != nil {
			t.Errorf("remove disposable Compose project: %v\n%s", err, output)
		}
	})
	compose := func(arguments ...string) []byte {
		t.Helper()
		command := exec.CommandContext(ctx, "docker", append(append([]string{}, args...), arguments...)...)
		command.Dir = root
		var diagnostics bytes.Buffer
		command.Stderr = &diagnostics
		output, err := command.Output()
		if err != nil {
			t.Fatalf("run disposable Compose command: %v\n%s\n%s", err, output, diagnostics.String())
		}
		return output
	}
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		diagnostic, stop := context.WithTimeout(context.Background(), 8*time.Second)
		defer stop()
		command := exec.CommandContext(diagnostic, "docker", append(append([]string{}, args...), "logs", "--no-color", "--tail", "25", "publisher", "web")...)
		command.Dir = root
		if output, err := command.CombinedOutput(); err == nil {
			t.Logf("Compose publisher and app output:\n%s", output)
		}
		status := exec.CommandContext(diagnostic, "docker", append(append([]string{}, args...), "exec", "--no-TTY", "publisher", "tnl", "status", "--scope", "local", "--output=json")...)
		status.Dir = root
		if output, err := status.Output(); err == nil {
			var result struct {
				Projects []struct {
					Local *struct {
						Snapshot clientruntime.Snapshot `json:"snapshot"`
					} `json:"local"`
				} `json:"projects"`
			}
			if json.Unmarshal(output, &result) == nil {
				for _, project := range result.Projects {
					if project.Local != nil {
						for _, service := range project.Local.Snapshot.Services {
							t.Logf("Compose service=%s failure=%s stage=%s", service.Name, service.Failure, service.ProvisioningStage)
						}
					}
				}
			}
		}
		t.Logf("disposable server output:\n%s", fixture.server.output.String())
	})
	compose("up", "--detach", "--wait")
	op := binaryApproveDevice(t, compose("run", "--rm", "--no-deps", "--no-TTY", "publisher", "tnl", "auth", "login", "start", "--output=json"), fixture.trustFile)
	compose("run", "--rm", "--no-deps", "--no-TTY", "publisher", "tnl", "auth", "login", "wait", op.ID, "--output=json")
	start := func(service string) *integrationBinaryPublish {
		t.Helper()
		arguments := append(append([]string{}, args...), "exec", "--no-TTY", "publisher", "tnl", "publish", service, "--output=ndjson")
		publish := startIntegrationBinaryPublish(t, root, os.Environ(), "docker", arguments...)
		publish.acceptDockerInterrupt = true
		return publish
	}
	visitor := newIntegrationVisitor(t, fixture.pebble.roots, "127.0.0.1:443")
	webPublish := start("web")
	webReady := waitForIntegrationBinaryPublishEvent(t, webPublish, "ready", 90*time.Second)
	publicURL := webReady.URL
	if !strings.HasPrefix(publicURL, "https://") {
		t.Fatalf("Compose HTTP public URL is not HTTPS: %q", publicURL)
	}
	request := func(previous string) string {
		t.Helper()
		var body string
		waitForIntegrationCondition(t, 45*time.Second, func(ctx context.Context) (bool, error) {
			response, data, err := visitor.requestURLContext(ctx, http.MethodGet, publicURL+"/", nil)
			if err != nil {
				return false, err
			}
			body = strings.TrimSpace(string(data))
			return response.StatusCode == http.StatusOK && body != "" && body != previous, nil
		})
		return body
	}
	first := request("")
	databasePublish := start("db")
	databaseReady := waitForIntegrationBinaryPublishEvent(t, databasePublish, "ready", 90*time.Second)
	if databaseReady.URL != "" || databaseReady.PublishRunNumber == 0 {
		t.Fatalf("database publication is not private: %+v", databaseReady)
	}
	available := startIntegrationBinaryProcess(t, fixture.repositoryRoot, fixture.environment, fixture.tnlPath,
		"--no-config", "connect", "available", "--output=json")
	if err := waitForDoneWithin(available.done, 15*time.Second); err != nil {
		t.Fatal("service discovery did not finish")
	}
	assertIntegrationBinaryProcessResult(t, available)
	var services []controlv1.Service
	if err := json.Unmarshal([]byte(available.output.String()), &services); err != nil {
		t.Fatalf("decode available services: %v", err)
	}
	var databaseServiceID, databaseHostname string
	for _, service := range services {
		if strings.HasPrefix(service.Name, "compose-db-") && service.Protocol == controlv1.Postgres && service.ServiceRunId != nil {
			if databaseServiceID != "" {
				t.Fatal("private database discovery returned multiple services")
			}
			databaseServiceID = service.Id
			if service.Endpoint == nil {
				t.Fatal("private database has no managed TLS endpoint")
			}
			databaseHostname = service.Endpoint.Hostname
		}
	}
	if databaseServiceID == "" {
		t.Fatalf("published database is not available to the signed-in visitor: %+v", services)
	}
	listenAddress := unusedTCPAddress(t)
	connector := startIntegrationBinaryProcess(t, fixture.repositoryRoot, fixture.environment, fixture.tnlPath,
		"--no-config", "connect", databaseServiceID, "--listen", listenAddress)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("tnl connect output:\n%s", connector.output.String())
		}
	})
	queryDatabase := func() time.Time {
		t.Helper()
		var started time.Time
		waitForIntegrationCondition(t, 45*time.Second, func(ctx context.Context) (bool, error) {
			settings, err := pgx.ParseConfig("postgres://postgres:postgres@" + listenAddress + "/postgres?sslmode=verify-full")
			if err != nil {
				return false, err
			}
			settings.ConnectTimeout = 3 * time.Second
			settings.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: fixture.pebble.roots, ServerName: databaseHostname}
			settings.Fallbacks = nil
			connection, err := pgx.ConnectConfig(ctx, settings)
			if err != nil {
				return false, err
			}
			defer connection.Close(ctx)
			var value int
			err = connection.QueryRow(ctx, "SELECT 42, pg_postmaster_start_time()").Scan(&value, &started)
			return err == nil && value == 42, err
		})
		return started
	}
	firstDatabase := queryDatabase()
	compose("up", "--detach", "--no-deps", "--force-recreate", "web")
	second := request(first)
	if started := queryDatabase(); !started.Equal(firstDatabase) {
		t.Fatal("recreating the HTTP app replaced the database")
	}
	compose("up", "--detach", "--no-deps", "--force-recreate", "db")
	compose("up", "--detach", "--wait", "db")
	if started := queryDatabase(); started.Equal(firstDatabase) {
		t.Fatal("recreated database answered with its old process identity")
	}
	if second == first {
		t.Fatal("recreated app answered with its old container identity")
	}
}
