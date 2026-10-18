package tnldruntime

import (
	"context"
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
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/internal/publishertarget"
	"github.com/tnldotdev/tnl/internal/testutil"
)

var composeHostAddress = flag.String("tnl-test-compose-host-address", "host-gateway", "address of the disposable binary test's ingress on the Docker host")

// an ordinary Compose service runs tnl publish against private HTTP and TCP
// targets. visitors still cross public ingress, relay, and the publisher.
func TestBinaryIntegrationManualComposePublisherPublicHTTPAndPostgres(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierBinary)
	fixture := startIntegrationBinaryStandaloneWithBind(t, true, "simple")
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	appBinary := filepath.Join(root, "compose-app-linux")
	buildIntegrationBinary(t, fixture.repositoryRoot, appBinary, "./internal/tnldruntime/testdata/compose-publisher")
	if *composeHostAddress != "host-gateway" {
		if address := net.ParseIP(*composeHostAddress); address == nil || address.To4() == nil {
			t.Fatal("-tnl-test-compose-host-address must be an IPv4 address or host-gateway")
		}
	}
	image := "mirror.gcr.io/library/golang:1.27.2-bookworm@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61"
	postgresImage := "mirror.gcr.io/library/postgres:17.6-alpine@sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94"
	base := filepath.Join(root, "compose.yaml")
	configuration := fmt.Sprintf("services:\n  publisher:\n    image: %s\n    command: [sleep, infinity]\n    working_dir: /workspace\n    extra_hosts:\n      - control.127.0.0.1.nip.io:host-gateway\n      - relay.127.0.0.1.nip.io:host-gateway\n    environment:\n      SSL_CERT_FILE: /run/tnl/roots.pem\n      TNL_SERVER: https://control.127.0.0.1.nip.io\n      TNL_STATE_DIR: /run/tnl/state/owner-state\n    volumes:\n      - %q\n      - %q\n      - %q\n      - publisher-state:/run/tnl/state\n  web:\n    image: %s\n    command: [/fixture/app]\n    volumes:\n      - %q\n  db:\n    image: %s\n    environment:\n      POSTGRES_PASSWORD: postgres\n    healthcheck:\n      test: [CMD-SHELL, pg_isready -U postgres -d postgres]\n      interval: 2s\n      timeout: 5s\n      retries: 10\nvolumes:\n  publisher-state:\n", image, fixture.tnlPath+":/usr/local/bin/tnl:ro", fixture.trustFile+":/run/tnl/roots.pem:ro", root+":/workspace:ro", image, appBinary+":/fixture/app:ro", postgresImage)
	configuration = strings.ReplaceAll(configuration, ":host-gateway", ":"+*composeHostAddress)
	if err := os.WriteFile(base, []byte(configuration), 0600); err != nil {
		t.Fatal(err)
	}
	projectConfig := "version: 1\ntnl:\n  server: https://control.127.0.0.1.nip.io\n  services:\n    web:\n      target: {type: address, address: 'http://web:3000'}\n      tunnel: {name: compose-web, access: anonymous}\n    db:\n      protocol: postgres\n      target: {type: address, address: 'db:5432'}\n      tunnel: {name: compose-db, access: anonymous}\n"
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
	selection, err := projectconfig.SelectProjectConfig(ctx, root, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	project, err := projectconfig.Resolve(ctx, selection, root, salt)
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
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("run disposable Compose command: %v\n%s", err, output)
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
		t.Logf("disposable server output:\n%s", fixture.server.output.String())
	})
	compose("up", "--detach", "--wait")
	compose("run", "--rm", "--no-deps", "--no-TTY", "--env", "TNL_LOGIN_TOKEN="+testLoginToken, "publisher", "tnl", "auth", "login", "--login-token")
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
	queryDatabase := func() {
		t.Helper()
		hostname, port, err := net.SplitHostPort(databaseReady.URL)
		if err != nil || port != "15432" {
			t.Fatalf("database public address has no verified ingress port: %q, %v", databaseReady.URL, err)
		}
		waitForIntegrationCondition(t, 45*time.Second, func(ctx context.Context) (bool, error) {
			settings, err := pgx.ParseConfig("postgres://postgres:postgres@" + databaseReady.URL + "/postgres?sslmode=verify-full&channel_binding=disable")
			if err != nil {
				return false, err
			}
			settings.TLSConfig.RootCAs = fixture.pebble.roots
			settings.TLSConfig.ServerName = hostname
			settings.Fallbacks = nil
			settings.DialFunc = func(ctx context.Context, network, _ string) (net.Conn, error) {
				return new(net.Dialer).DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
			}
			connection, err := pgx.ConnectConfig(ctx, settings)
			if err != nil {
				return false, err
			}
			defer connection.Close(ctx)
			var value int
			err = connection.QueryRow(ctx, "SELECT 42").Scan(&value)
			return err == nil && value == 42, err
		})
	}
	queryDatabase()
	compose("up", "--detach", "--no-deps", "--force-recreate", "web")
	second := request(first)
	queryDatabase()
	compose("up", "--detach", "--no-deps", "--force-recreate", "db")
	compose("up", "--detach", "--wait", "db")
	queryDatabase()
	if second == first {
		t.Fatal("recreated app answered with its old container identity")
	}
}
