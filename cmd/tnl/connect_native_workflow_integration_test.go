package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestIntegrationCLINativeConnectIsFiniteAndRebindsCredentials(t *testing.T) {
	if !cliWorkflowInChild(t) {
		return
	}
	f := newCLIWorkflow(t)
	person := f.state(t, "person")
	f.loginPerson(t, person)
	session, err := openTeamSession(t.Context(), remoteFlags{ServerURL: f.url, StateDir: person}, "profile workflow", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	root := t.TempDir()
	for _, args := range [][]string{{"init", "--quiet", root}, {"-C", root, "remote", "add", "origin", "https://example.test/cli/native-profiles.git"}} {
		if output, err := exec.CommandContext(t.Context(), "git", args...).CombinedOutput(); err != nil {
			t.Fatalf("fixture Git setup: %v %s", err, output)
		}
	}
	configuration := filepath.Join(root, "tnl.json")
	write := func(public bool) controlv1.AppliedProjectConfiguration {
		t.Helper()
		data, err := json.Marshal(map[string]any{"version": 1, "tnl": map[string]any{"server": f.url, "team": session.identity.PersonalTeamId, "publishers": map[string]any{"production": map[string]any{"public": public}}, "services": map[string]any{
			"api":     map[string]any{"publisher": "production", "target": map[string]any{"type": "address", "address": "http://do-not-dial.invalid:3000"}},
			"orders":  map[string]any{"publisher": "production", "protocol": "postgres", "target": map[string]any{"type": "address", "address": "do-not-dial.invalid:5432"}},
			"profile": map[string]any{"publisher": "production", "protocol": "mysql", "target": map[string]any{"type": "address", "address": "do-not-dial.invalid:3306"}},
			"setup":   map[string]any{"publisher": "production", "protocol": "postgres", "target": map[string]any{"type": "address", "address": "do-not-dial.invalid:5432"}},
		}}})
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(configuration, data, 0600); err != nil {
			t.Fatal(err)
		}
		var applied controlv1.AppliedProjectConfiguration
		if err = json.Unmarshal(cliCall(t, t.Context(), []string{"--config", configuration, "apply", "--state-dir", person, "--output=json"}), &applied); err != nil {
			t.Fatal(err)
		}
		return applied
	}
	profile := func(name string) nativeConnectionProfile {
		t.Helper()
		encoded := cliCall(t, t.Context(), []string{"--config", configuration, "connect", name, "--state-dir", person, "--output=json"})
		if bytes.Contains(encoded, []byte("BEGIN PRIVATE KEY")) || bytes.Contains(encoded, []byte("do-not-dial.invalid")) {
			t.Fatal("profile exposed key material or target data")
		}
		var result nativeConnectionProfile
		if err := json.Unmarshal(encoded, &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	write(true)
	for _, incompatible := range []string{"--detach", "--listen=15432", "--foreground", "--stdio"} {
		var output bytes.Buffer
		if err := run(t.Context(), []string{"--no-telemetry", "--config", configuration, "connect", "orders", "--state-dir", person, incompatible}, &output, io.Discard); err == nil || output.Len() != 0 {
			t.Fatal("finite mode accepted incompatible listener options", incompatible, err)
		}
	}
	public := profile("orders")
	if public.Authentication != connectionMTLS || public.ClientCertificate == nil || public.ConnectorRequired || public.Command[0] != "psql" {
		t.Fatal("public database profile started a connector or omitted mTLS")
	}
	if _, err = tls.LoadX509KeyPair(public.ClientCertificate.CertificateFile, public.ClientCertificate.KeyFile); err != nil {
		t.Fatal("native client could not load the issued credential", err)
	}
	retry := profile("orders")
	if retry.ClientCertificate == nil || *retry.ClientCertificate != *public.ClientCertificate {
		t.Fatal("repeated profile setup changed client credentials")
	}
	inspect, err := pgx.Connect(t.Context(), f.databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer inspect.Close(t.Context())
	// a new login must bind the same certificate to the new session even while
	// the cached leaf remains valid for days. neither the key nor leaf changes.
	previous, found, err := session.store.ControlSession(t.Context())
	if err != nil || !found {
		t.Fatal(err)
	}
	f.loginPerson(t, person)
	current, found, err := session.store.ControlSession(t.Context())
	if err != nil || !found || current.SessionID == previous.SessionID {
		t.Fatal("login did not create a fresh session", err)
	}
	retry = profile("orders")
	if *retry.ClientCertificate != *public.ClientCertificate {
		t.Fatal("reauthentication replaced a valid certificate")
	}
	var bound string
	if err := inspect.QueryRow(t.Context(), `SELECT control_session_id FROM control.service_client_certificates WHERE private_service_id=$1`, public.ServiceID).Scan(&bound); err != nil || bound != current.SessionID {
		t.Fatal("cached certificate retained an old control session", bound, err)
	}
	for name, command := range map[string]string{"api": "curl", "profile": "mysql", "setup": "psql"} {
		result := profile(name)
		if result.Authentication != connectionMTLS || result.ClientCertificate == nil || result.ConnectorRequired || result.Command[0] != command {
			t.Fatal("incorrect automatic native mode", result)
		}
		if name == "api" && result.URL == "" {
			t.Fatal("public HTTP omitted allocated-port URL")
		}
	}
	var connectors, runs, certificates int
	if err = inspect.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM control.private_connector_sessions),(SELECT count(*) FROM control.private_service_runs),(SELECT count(*) FROM control.service_client_certificates)`).Scan(&connectors, &runs, &certificates); err != nil || connectors != 0 || runs != 0 || certificates != 4 {
		t.Fatal("finite profile setup created a data path", connectors, runs, certificates, err)
	}
	device, found, err := session.store.VisitorDevice(t.Context(), session.identity.Identity.Id)
	if err != nil || !found {
		t.Fatal(err)
	}
	if _, err := inspect.Exec(t.Context(), `UPDATE control.visitor_devices SET revoked_at=now() WHERE id=$1`, device.ID); err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"revoked", "missing"} {
		if state == "missing" {
			if _, err := inspect.Exec(t.Context(), `DELETE FROM control.service_client_certificates WHERE device_id=$1`, device.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := inspect.Exec(t.Context(), `DELETE FROM control.visitor_devices WHERE id=$1`, device.ID); err != nil {
				t.Fatal(err)
			}
		}
		var output bytes.Buffer
		if err := run(t.Context(), []string{"--no-telemetry", "--config", configuration, "connect", "orders", "--state-dir", person, "--output=json"}, &output, io.Discard); err == nil || output.Len() != 0 {
			t.Fatal("cached credential bypassed device rejection", state, err)
		}
		if _, err := tls.LoadX509KeyPair(public.ClientCertificate.CertificateFile, public.ClientCertificate.KeyFile); err != nil {
			t.Fatal("rejected request damaged old files", err)
		}
	}
	entries, err := os.ReadDir(person + "/service-clients")
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if len(entries) != 4 {
		t.Fatal("rejected requests exported new credentials", len(entries))
	}
}
