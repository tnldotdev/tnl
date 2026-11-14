package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestIntegrationCLINativeConnectRequiresReadyPublisher(t *testing.T) {
	if !cliWorkflowInChild(t) {
		return
	}
	f := newCLIWorkflow(t)
	person := f.state(t, "person")
	f.loginPerson(t, person)
	session, err := openTeamSession(t.Context(), remoteFlags{ServerURL: f.url, StateDir: person}, "connect workflow", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	root := t.TempDir()
	for _, args := range [][]string{{"init", "--quiet", root}, {"-C", root, "remote", "add", "origin", "https://example.test/cli/native-connect.git"}} {
		if output, err := exec.CommandContext(t.Context(), "git", args...).CombinedOutput(); err != nil {
			t.Fatalf("fixture Git setup: %v %s", err, output)
		}
	}
	configuration := filepath.Join(root, "tnl.json")
	for _, public := range []bool{true, false} {
		data, _ := json.Marshal(map[string]any{"version": 1, "tnl": map[string]any{"server": f.url, "team": session.Identity().PersonalTeamId, "services": map[string]any{"inventory": map[string]any{}, "orders": map[string]any{"protocol": "postgres"}, "profile": map[string]any{"protocol": "mysql"}}, "deployments": map[string]any{"production": map[string]any{"targets": map[string]any{
			"inventory": map[string]any{"address": "http://do-not-dial.invalid:3000", "public": public},
			"orders":    map[string]any{"address": "do-not-dial.invalid:5432", "public": public},
			"profile":   map[string]any{"address": "do-not-dial.invalid:3306", "public": public},
		}}}}})
		if err := os.WriteFile(configuration, data, 0600); err != nil {
			t.Fatal(err)
		}
		cliCall(t, t.Context(), []string{"--config", configuration, "apply", "--deployment", "production", "--state-dir", person, "--output=json"})
		for _, name := range []string{"inventory", "orders", "profile"} {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			var output bytes.Buffer
			err := run(ctx, []string{"--no-telemetry", "--config", configuration, "connect", name, "--deployment", "production", "--state-dir", person, "--output=json", "--listen=127.0.0.1:15432"}, &output, io.Discard)
			cancel()
			if err == nil || output.Len() != 0 {
				t.Fatal("offline service returned ready instructions", public, name, err)
			}
		}
	}
	inspect, err := pgx.Connect(t.Context(), f.databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer inspect.Close(t.Context())
	var certificates int
	if err := inspect.QueryRow(t.Context(), `SELECT count(*) FROM control.service_client_certificates`).Scan(&certificates); err != nil || certificates != 0 {
		t.Fatal("connect issued application credentials", certificates, err)
	}
}
