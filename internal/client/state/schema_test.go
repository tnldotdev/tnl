package state

import (
	"bytes"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func TestV1ProjectJournalAndHandoffState(t *testing.T) {
	ctx := t.Context()
	root := filepath.Join(t.TempDir(), "state")
	database, err := Open(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if got := filepath.Base(DatabasePath(root)); got != "v1.db" {
		t.Fatalf("client database filename = %q", got)
	}
	if _, err := database.db.ExecContext(ctx, `UPDATE installation_settings SET telemetry_enabled = 2 WHERE id = 1`); err == nil {
		t.Fatal("an invalid SQLite boolean was accepted")
	}
	const server = "https://control.example.test"
	now := time.Now().UTC().UnixNano()
	if _, err := database.db.ExecContext(ctx, `INSERT INTO server_profiles (origin, created_at, last_used_at) VALUES (?, ?, ?)`, server, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := database.db.ExecContext(ctx, `INSERT INTO local_tunnels
		(id, command, process_id, server_origin, project_root, hostname, target, framework,
		 public_url_id, publish_run_number, state, started_at, updated_at, heartbeat_at, lease_expires_at, failure_code)
		VALUES (?, 'publish', 1, ?, ?, NULL, 'http://127.0.0.1:3000', NULL, NULL, NULL, 'starting', ?, ?, ?, ?, NULL)`,
		"tun_0123456789abcdefghijkl", server, root, now, now, now, now+int64(time.Minute)); err != nil {
		t.Fatal(err)
	}
	var unknownURL, unknownHost sql.NullString
	var unknownRun sql.NullInt64
	if err := database.db.QueryRowContext(ctx, `SELECT public_url_id, hostname, publish_run_number
		FROM local_tunnels WHERE id = ?`, "tun_0123456789abcdefghijkl").Scan(&unknownURL, &unknownHost, &unknownRun); err != nil ||
		unknownURL.Valid || unknownHost.Valid || unknownRun.Valid {
		t.Fatalf("unallocated public address was not NULL: url=%v host=%v run=%v: %v",
			unknownURL, unknownHost, unknownRun, err)
	}
	if _, err := database.db.ExecContext(ctx, `UPDATE local_tunnels SET public_url_id = ?, hostname = ?, state = 'provisioning', updated_at = ? WHERE id = ?`,
		"url_example", "app.example.test", now+1, "tun_0123456789abcdefghijkl"); err != nil {
		t.Fatal(err)
	}
	var journalEvents, knownURLs int
	if err := database.db.QueryRowContext(ctx, `SELECT count(*) FROM project_events WHERE project_root = ?`, root).Scan(&journalEvents); err != nil || journalEvents != 2 {
		t.Fatalf("project journal events = %d, %v; want 2", journalEvents, err)
	}
	if err := database.db.QueryRowContext(ctx, `SELECT count(*) FROM project_url_inventory WHERE project_root = ? AND server_origin = ?`, root, server).Scan(&knownURLs); err != nil || knownURLs != 1 {
		t.Fatalf("known project URLs = %d, %v; want 1", knownURLs, err)
	}
	urls, err := database.KnownProjectURLs(ctx, root, server+"/")
	if err != nil || len(urls) != 1 || urls[0] != "url_example" {
		t.Fatalf("read-only project URL selection: %v %v", urls, err)
	}
	other, err := database.KnownProjectURLs(ctx, root, "https://other.example.test")
	if err != nil || len(other) != 0 {
		t.Fatalf("project URL selection crossed servers: %v %v", other, err)
	}
	if _, err := database.db.ExecContext(ctx, `UPDATE local_tunnels SET primary_project_root = ?, integration_namespace = ? WHERE id = ?`,
		root, "member.example.test", "tun_0123456789abcdefghijkl"); err != nil {
		t.Fatal(err)
	}
	var primary, namespace string
	if err := database.db.QueryRowContext(ctx, `SELECT primary_project_root, integration_namespace FROM local_tunnels WHERE id = ?`,
		"tun_0123456789abcdefghijkl").Scan(&primary, &namespace); err != nil ||
		primary != root || namespace != "member.example.test" {
		t.Fatalf("stored integration scope = %q / %q: %v", primary, namespace, err)
	}
	for _, components := range [][2]any{
		{root, nil}, {nil, "member.example.test"}, {"", "member.example.test"},
		{root + "\x00other", "member.example.test"}, {root, "member.example.test\x00other"},
	} {
		if _, err := database.db.ExecContext(ctx, `UPDATE local_tunnels SET primary_project_root = ?, integration_namespace = ? WHERE id = ?`,
			components[0], components[1], "tun_0123456789abcdefghijkl"); err == nil {
			t.Fatalf("accepted incomplete or NUL-containing scope: %#v", components)
		}
	}
	for _, table := range []string{"local_tunnels", "webhook_owners"} {
		var projections int
		if err := database.db.QueryRowContext(ctx, `SELECT count(*) FROM pragma_table_xinfo(?) WHERE name = 'integration_group'`, table).Scan(&projections); err != nil || projections != 0 {
			t.Fatalf("%s retained an encoded integration projection: %v", table, err)
		}
	}
	if _, err := database.db.ExecContext(ctx, `INSERT INTO oauth_alias_handoffs
		(server_origin, hostname, state_digest, callback_path, public_url_id, publish_run_number, created_at, expires_at)
		VALUES (?, 'alias.example.test', ?, '/callback', 'url_example', 1, ?, ?)`, server, bytes.Repeat([]byte{1}, 32), now, now+int64(time.Minute)); err != nil {
		t.Fatal(err)
	}
	for attempt := 1; attempt <= 2; attempt++ {
		result, err := database.db.ExecContext(ctx, `UPDATE oauth_alias_handoffs SET consumed_at = ?
			WHERE server_origin = ? AND hostname = 'alias.example.test' AND consumed_at IS NULL AND expires_at > ?`, now+1, server, now+1)
		if err != nil {
			t.Fatal(err)
		}
		rows, err := result.RowsAffected()
		if err != nil || rows != int64(2-attempt) {
			t.Fatalf("handoff attempt %d changed %d rows, %v", attempt, rows, err)
		}
	}
}
