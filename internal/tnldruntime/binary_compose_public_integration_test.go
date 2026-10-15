package tnldruntime

import (
	"context"
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
	"github.com/tnldotdev/tnl/internal/clientruntime"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/localpublisher"
	"github.com/tnldotdev/tnl/internal/privateprotocol"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/internal/publishertarget"
	"github.com/tnldotdev/tnl/internal/testutil"
)

var composeHostAddress = flag.String("tnl-test-compose-host-address", "host-gateway", "address of the disposable binary test's ingress on the Docker host")

// this test crosses the generated Compose owner and real public URLs for an
// app and a database. it verifies replacement through visitor connections.
func TestBinaryIntegrationGeneratedComposePublicHTTPAndPostgres(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierBinary)
	fixture := startIntegrationBinaryStandaloneWithBind(t, true, "simple")
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	appBinary := filepath.Join(root, "compose-app-linux")
	buildIntegrationBinary(t, fixture.repositoryRoot, appBinary, "./internal/tnldruntime/testdata/compose-owner")
	if *composeHostAddress != "host-gateway" {
		if address := net.ParseIP(*composeHostAddress); address == nil || address.To4() == nil {
			t.Fatal("-tnl-test-compose-host-address must be an IPv4 address or host-gateway")
		}
	}
	image := "mirror.gcr.io/library/golang:1.27.2-bookworm@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61"
	postgresImage := "mirror.gcr.io/library/postgres:17.6-alpine@sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94"
	base := filepath.Join(root, "compose.yaml")
	configuration := fmt.Sprintf("services:\n  publisher:\n    image: %s\n    extra_hosts:\n      - control.127.0.0.1.nip.io:host-gateway\n      - relay.127.0.0.1.nip.io:host-gateway\n    environment:\n      SSL_CERT_FILE: /run/tnl/roots.pem\n    volumes:\n      - %q\n      - %q\n  web:\n    image: %s\n    command: [/fixture/app, app-register]\n    volumes:\n      - %q\n      - %q\n  db:\n    image: %s\n    environment:\n      POSTGRES_PASSWORD: postgres\n    healthcheck:\n      test: [CMD-SHELL, pg_isready -U postgres -d postgres]\n      interval: 2s\n      timeout: 5s\n      retries: 10\n", image, fixture.tnlPath+":/usr/local/bin/tnl:ro", fixture.trustFile+":/run/tnl/roots.pem:ro", image, appBinary+":/fixture/app:ro", root+":/workspace:ro", postgresImage)
	configuration = strings.ReplaceAll(configuration, ":host-gateway", ":"+*composeHostAddress)
	if err := os.WriteFile(base, []byte(configuration), 0600); err != nil {
		t.Fatal(err)
	}
	projectConfig := "version: 1\ntnl:\n  server: https://control.127.0.0.1.nip.io\n  publisher: {type: compose, service: publisher}\n  services:\n    web:\n      target: {type: app}\n      tunnel:\n        name: compose-web\n        allow_all_ips: true\n    db:\n      protocol: postgres\n      target: {type: compose, service: db, port: 5432}\n      tunnel:\n        name: compose-db\n        allow_all_ips: true\n"
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
	runIntegrationBinaryCommand(t, root, fixture.environment, fixture.tnlPath, "compose", "prepare")
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
	var databasePublish *integrationBinaryPublish
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		diagnostic, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		path, err := privateprotocol.DescriptorPath(fixture.stateDirectory, root)
		if err == nil {
			var endpoint privateprotocol.Endpoint
			endpoint, err = privateprotocol.ReadEndpoint(path)
			if err == nil {
				var snapshot clientruntime.Snapshot
				err = privateprotocol.Call(diagnostic, endpoint, "GET", "/v1/status", nil, &snapshot)
				if err == nil {
					for _, service := range snapshot.Services {
						t.Logf("Compose owner service=%s registered=%t routable=%t run=%d stage=%s failure=%s", service.Name, service.Registered, service.Routable, service.PublishRunNumber, service.ProvisioningStage, service.Failure)
					}
				}
			}
		}
		if err != nil {
			t.Logf("read Compose owner state: %v", err)
		}
		if databasePublish != nil {
			events, _ := databasePublish.events.snapshot()
			for _, event := range events {
				t.Logf("Compose database publication event=%s run=%d reason=%s", event.Type, event.PublishRunNumber, event.Reason)
			}
		}
		command := exec.CommandContext(diagnostic, "docker", append(append([]string{}, args...), "ps", "--all")...)
		command.Dir = root
		if output, err := command.CombinedOutput(); err == nil {
			t.Logf("Compose containers:\n%s", output)
		}
		command = exec.CommandContext(diagnostic, "docker", append(append([]string{}, args...), "logs", "--no-color", "--tail", "25", "publisher", "web")...)
		command.Dir = root
		if output, err := command.CombinedOutput(); err == nil {
			t.Logf("Compose publisher and app output:\n%s", output)
		}
		inspect := inspectStandaloneTestDatabase(t, fixture.databaseURL)
		rows, err := inspect.QueryContext(diagnostic, `
			SELECT u.service_protocol, r.state, r.certificate_installed_at IS NOT NULL,
			       COALESCE(a.state, ''), COALESCE(a.attempts, 0)
			FROM control.publish_runs r
			JOIN control.public_urls u ON u.id = r.public_url_id
			LEFT JOIN control.acme_orders a ON a.publish_run_id = r.id
			ORDER BY u.service_protocol, r.publish_run_number, a.created_at`)
		if err == nil {
			for rows.Next() {
				var protocol, runState, orderState string
				var certificate bool
				var attempts int
				if err := rows.Scan(&protocol, &runState, &certificate, &orderState, &attempts); err != nil {
					break
				}
				t.Logf("Compose public %s run=%s certificate=%t issuance=%s attempts=%d", protocol, runState, certificate, orderState, attempts)
			}
			_ = rows.Close()
		}
		t.Logf("disposable server output:\n%s", fixture.server.output.String())
	})
	ownerEndpoint := func() {
		t.Helper()
		ready, stop := context.WithTimeout(ctx, 30*time.Second)
		defer stop()
		if err := pollCondition(ready, 250*time.Millisecond, 15*time.Second, func(operation context.Context) (bool, error) {
			command := exec.CommandContext(operation, fixture.tnlPath, "runtime", "owner-endpoint", "--directory", root)
			command.Dir, command.Env = root, fixture.environment
			output, err := command.CombinedOutput()
			if err != nil {
				return false, fmt.Errorf("start Compose owner endpoint: %w: %s", err, output)
			}
			return true, nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	runIntegrationBinaryCommand(t, root, fixture.environment, fixture.tnlPath, "compose", "up", "--detach")
	ownerEndpoint()
	compose("exec", "--no-TTY", "--env", "TNL_LOGIN_TOKEN="+testLoginToken, "publisher", "tnl", "auth", "login", "--login-token")
	compose("up", "--detach", "--wait", "db")
	visitor := newIntegrationVisitor(t, fixture.pebble.roots, "")
	service := func() (clientruntime.Service, error) {
		query := compose("exec", "--no-TTY", "web", "/fixture/app", "query", "--path", "/v1/status")
		var reply localpublisher.ComposeReply
		if err := json.Unmarshal(query, &reply); err != nil || reply.Status != http.StatusOK {
			return clientruntime.Service{}, fmt.Errorf("read app-scoped publisher status: %v, status %d", err, reply.Status)
		}
		var snapshot clientruntime.Snapshot
		if err := json.Unmarshal(reply.Body, &snapshot); err != nil || len(snapshot.Services) != 1 {
			return clientruntime.Service{}, fmt.Errorf("read app service snapshot: %v, services %d", err, len(snapshot.Services))
		}
		return snapshot.Services[0], nil
	}
	var publicURL string
	waitForIntegrationCondition(t, 80*time.Second, func(context.Context) (bool, error) {
		current, err := service()
		if err != nil || current.PublicURL == "" || !current.Routable {
			return false, err
		}
		publicURL = current.PublicURL
		return true, nil
	})
	request := func(previous string) string {
		t.Helper()
		var body string
		var status int
		t.Cleanup(func() {
			if t.Failed() {
				t.Logf("Compose public visitor previous=%q status=%d body=%q", previous, status, body)
			}
		})
		waitForIntegrationCondition(t, 40*time.Second, func(ctx context.Context) (bool, error) {
			response, data, err := visitor.requestURLContext(ctx, http.MethodGet, publicURL+"/", nil)
			if err != nil {
				return false, err
			}
			status = response.StatusCode
			body = strings.TrimSpace(string(data))
			return response.StatusCode == http.StatusOK && body != "" && body != previous, nil
		})
		return body
	}
	first := request("")
	databasePublish = startIntegrationBinaryPublish(t, root, fixture.environment, fixture.tnlPath, "publish", "db", "--output=ndjson")
	databaseReady := waitForIntegrationBinaryPublishEvent(t, databasePublish, "ready", 90*time.Second)
	if _, port, err := net.SplitHostPort(databaseReady.URL); err != nil || port != "15432" {
		t.Fatalf("Compose database public address has no verified ingress port: %q, %v", databaseReady.URL, err)
	}
	queryDatabase := func() {
		t.Helper()
		hostname, port, err := net.SplitHostPort(databaseReady.URL)
		if err != nil {
			t.Fatal(err)
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
	if second == first {
		t.Fatal("replaced app answered with the old container identity")
	}
	compose("up", "--detach", "--no-deps", "--force-recreate", "db")
	compose("up", "--detach", "--wait", "db")
	queryDatabase()
	compose("exec", "--no-TTY", "web", "/fixture/app", "query", "--save", "/tmp/old-endpoint.json", "--path", "/v1/status")
	compose("up", "--detach", "--no-deps", "--force-recreate", "publisher")
	ownerEndpoint()
	if after := request(""); after != second {
		t.Fatalf("owner replacement changed the selected app container: %q, want %q", after, second)
	}
	if current, err := service(); err != nil || current.PublicURL != publicURL {
		t.Fatalf("owner replacement lost the saved public URL: %v, url %q", err, current.PublicURL)
	}
	previousDatabaseRun := databaseReady.PublishRunNumber
	previousDatabaseAddress := databaseReady.URL
	databaseReady = waitForIntegrationBinaryPublishEvent(t, databasePublish, "ready", 90*time.Second)
	if databaseReady.PublishRunNumber <= previousDatabaseRun || databaseReady.URL != previousDatabaseAddress {
		t.Fatalf("owner replacement did not restore the saved database public address: run=%d address=%q", databaseReady.PublishRunNumber, databaseReady.URL)
	}
	queryDatabase()
	stale := compose("exec", "--no-TTY", "web", "/fixture/app", "query", "--descriptor", "/tmp/old-endpoint.json", "--path", "/v1/status")
	var reply localpublisher.ComposeReply
	if err := json.Unmarshal(stale, &reply); err != nil || reply.Status != http.StatusUnauthorized {
		t.Fatalf("replacement owner accepted a stale app capability: %v, status %d", err, reply.Status)
	}
}
