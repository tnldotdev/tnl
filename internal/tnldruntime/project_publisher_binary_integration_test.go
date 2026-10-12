package tnldruntime

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/projectmeta"
)

const projectPostgresCompose = `services:
  db:
    image: public.ecr.aws/docker/library/postgres:17.6-alpine@sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94
    environment:
      POSTGRES_USER: shop
      POSTGRES_PASSWORD: devpassword
      POSTGRES_DB: shop
    ports:
      - "127.0.0.1::5432"
    volumes:
      - db-data:/var/lib/postgresql/data
volumes:
  db-data:
`

func TestBinaryIntegrationTwoWorktreeComposePostgresVisitors(t *testing.T) {
	fixture := startIntegrationBinaryStandaloneTCP(t)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("standalone output:\n%s", fixture.server.output.String())
		}
	})
	// the test owns the front listener and verifies its ports before recording
	// the equivalent operator inventory in the disposable control database.
	control, err := controlstate.Open(t.Context(), fixture.databaseURL, testStorageKey, "", naming.ManagedURLModeSimple)
	if err != nil {
		t.Fatal(err)
	}
	if err := control.EnsurePrimaryIngressPool(t.Context(), "127.0.0.1", "", []int32{15432, 15433}, time.Now()); err != nil {
		t.Fatal(err)
	}
	control.Close()
	type worktree struct {
		root, label, publicURL, privateAddress, marker string
		port                                           int
		publish                                        *integrationBinaryProcess
	}
	var worktrees []worktree
	for index := 0; index < 2; index++ {
		root, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		labelCommand := startIntegrationBinaryProcess(t, root, fixture.environment, fixture.tnlPath, "project", "label", "--output", "raw")
		if err := waitForDoneWithin(labelCommand.done, 20*time.Second); err != nil {
			t.Fatal(err)
		}
		assertIntegrationBinaryProcessResult(t, labelCommand)
		label := strings.TrimSpace(labelCommand.output.String())
		if label == "" || strings.ContainsAny(label, " \n") {
			t.Fatalf("worktree label = %q", label)
		}
		if err := os.WriteFile(filepath.Join(root, "compose.yaml"), []byte(projectPostgresCompose), 0600); err != nil {
			t.Fatal(err)
		}
		name := fmt.Sprintf("binary-orders-%d", index+1)
		configuration := fmt.Sprintf(`{"version":1,"tnl":{"server":"https://control.127.0.0.1.nip.io","services":{"orders":{"protocol":"postgres","target":{"type":"docker","compose":{"file":"compose.yaml","project":%q,"service":"db"},"container_port":5432},"tunnel":{"name":%q,"allow_all_ips":true}}}}}`, label, name)
		if err := os.WriteFile(filepath.Join(root, "tnl.json"), []byte(configuration), 0600); err != nil {
			t.Fatal(err)
		}
		runIntegrationBinaryCommand(t, root, fixture.environment, fixture.tnlPath, "config", "generate")
		data, err := os.ReadFile(filepath.Join(root, ".tnl", "project.json"))
		if err != nil {
			t.Fatal(err)
		}
		var metadata projectmeta.Metadata
		if err := json.Unmarshal(data, &metadata); err != nil || metadata.Worktree == nil || metadata.Worktree.Label.FullLabel != label || metadata.Services["orders"].Port == nil {
			t.Fatalf("saved public PostgreSQL metadata before publication = %s, %v", data, err)
		}
		orders := metadata.Services["orders"]
		if orders.Protocol != "postgres" || orders.URL != net.JoinHostPort(orders.Hostname, strconv.Itoa(*orders.Port)) || *orders.Port != 15432 && *orders.Port != 15433 {
			t.Fatalf("public PostgreSQL address before readiness = %+v", orders)
		}
		compose := func(action ...string) (string, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			args := append([]string{"compose", "--project-directory", root, "--file", filepath.Join(root, "compose.yaml"), "--project-name", label}, action...)
			command := exec.CommandContext(ctx, "docker", args...)
			command.Dir = root
			output, err := command.CombinedOutput()
			return string(output), err
		}
		t.Cleanup(func() {
			if output, err := compose("down", "--volumes", "--remove-orphans"); err != nil {
				t.Errorf("remove disposable worktree database: %v (%s)", err, output)
			}
		})
		if output, err := compose("up", "-d", "db"); err != nil {
			t.Fatalf("start worktree database: %v (%s)", err, output)
		}
		binding, err := compose("port", "db", "5432")
		if err != nil {
			t.Fatal(err)
		}
		privateAddress := strings.TrimSpace(binding)
		publish := startIntegrationBinaryProcess(t, root, fixture.environment, fixture.tnlPath, "publish", "orders", "--output=ndjson")
		worktrees = append(worktrees, worktree{root: root, label: label, publicURL: orders.URL, port: *orders.Port,
			privateAddress: privateAddress, publish: publish, marker: fmt.Sprintf("worktree-%d", index+1)})
	}
	if worktrees[0].label == worktrees[1].label || worktrees[0].privateAddress == worktrees[1].privateAddress || worktrees[0].port == worktrees[1].port {
		t.Fatalf("worktrees reused a Compose project, private port, or public port: %+v", worktrees)
	}
	for _, selected := range worktrees {
		waitForIntegrationCondition(t, 90*time.Second, func(ctx context.Context) (bool, error) {
			select {
			case <-selected.publish.done:
				return false, fmt.Errorf("named publisher stopped: %v; %s", selected.publish.result(), selected.publish.output.String())
			default:
			}
			connection, err := connectPublicPostgres(ctx, fixture, selected.publicURL)
			if err != nil {
				return false, err
			}
			defer connection.Close(context.Background())
			var value int
			err = connection.QueryRow(ctx, "SELECT 42").Scan(&value)
			return err == nil && value == 42, err
		})
		runIntegrationBinaryCommand(t, selected.root, fixture.environment, fixture.tnlPath, "wait", "--service", "orders", "--timeout", "30s", "--output=json")
	}
}

func connectPublicPostgres(ctx context.Context, fixture *integrationBinaryStandalone, address string) (*pgx.Conn, error) {
	config, err := pgx.ParseConfig("postgres://shop:devpassword@" + address + "/shop?sslmode=verify-full")
	if err != nil {
		return nil, err
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	config.TLSConfig = &tls.Config{RootCAs: fixture.pebble.roots, ServerName: host, MinVersion: tls.VersionTLS12}
	config.Fallbacks = nil
	return pgx.ConnectConfig(ctx, config)
}
