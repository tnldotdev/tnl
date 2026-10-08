package clientstate

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestRequestHistorySurvivesTunnelAndFiltersProjects(t *testing.T) {
	ctx := context.Background()
	state, err := Open(ctx, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	project := filepath.Join(t.TempDir(), "app")
	tunnel, err := state.BeginTunnel(ctx, BeginTunnelOptions{Command: TunnelCommandPublish,
		Server: "https://control.example", Target: "3000", Project: project, Service: "web"})
	if err != nil {
		t.Fatal(err)
	}
	recorder := tunnel.NewRequestRecorder(project, "web")
	recorder.Observe(RequestRecord{ReceivedAt: time.Now().UTC(), Method: "GET", Path: "/broken", Status: 500, Origin: "local_service", DurationMS: 15})
	recorder.Close()
	if err := tunnel.Finish(ctx, nil); err != nil {
		t.Fatal(err)
	}
	filter := RequestFilter{Project: project, Status: 500, Method: "GET", Service: "web", Since: time.Now().Add(-time.Minute), Limit: 10}
	items, err := state.ListRequests(ctx, filter)
	if err != nil || len(items) != 1 || items[0].TunnelID != tunnel.ID() || items[0].Path != "/broken" {
		t.Fatalf("history = %+v, %v", items, err)
	}
	item, err := state.GetRequest(ctx, project, items[0].ID)
	if err != nil || item.Status != 500 {
		t.Fatalf("request = %+v, %v", item, err)
	}
	filter.Project = filepath.Join(t.TempDir(), "other")
	items, err = state.ListRequests(ctx, filter)
	if err != nil || len(items) != 0 {
		t.Fatalf("other project = %+v, %v", items, err)
	}
}

func TestRequestHistoryPrunesOldAndExcessRecords(t *testing.T) {
	ctx := context.Background()
	state, err := Open(ctx, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	now := time.Now().UTC()
	state.now = func() time.Time { return now }
	for index := range requestMaxRows + 2 {
		at := now
		if index == 0 {
			at = now.Add(-25 * time.Hour)
		}
		_, err := state.db.ExecContext(ctx, `INSERT INTO local_requests
			(tunnel_id, project_root, service, received_at, method, path, status, duration_ms, origin)
			VALUES ('tun_test', '/app', '', ?, 'GET', '/', 200, 1, 'local_service')`, at.UnixNano())
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := state.pruneRequests(ctx); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := state.db.QueryRowContext(ctx, `SELECT count(*) FROM local_requests`).Scan(&count); err != nil || count != requestMaxRows {
		t.Fatalf("count = %d, %v", count, err)
	}
	var stale int
	if err := state.db.QueryRowContext(ctx, `SELECT count(*) FROM local_requests WHERE received_at < ?`, now.Add(-24*time.Hour).UnixNano()).Scan(&stale); err != nil || stale != 0 {
		t.Fatalf("stale = %d, %v", stale, err)
	}
}
