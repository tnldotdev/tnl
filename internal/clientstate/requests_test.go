package clientstate

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

func TestRequestNumbersAndSharedProjectAcrossWorktrees(t *testing.T) {
	ctx := context.Background()
	state, err := Open(ctx, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	primary := filepath.Join(t.TempDir(), "shop")
	project := filepath.Join(primary, "apps/web")
	otherWorktree := filepath.Join(t.TempDir(), "shop-feature", "apps/web")
	for _, entry := range []struct {
		project string
		details json.RawMessage
	}{
		{project, nil}, {otherWorktree, json.RawMessage(`{"query":"token=secret"}`)},
	} {
		if err := state.saveRequest(ctx, "tun_test", primary, entry.project, project, "web",
			RequestRecord{ReceivedAt: time.Now().UTC(), Method: "POST", Path: "/hook", Status: 500,
				Origin: "local_service", CaptureMode: "detailed", Detail: entry.details}); err != nil {
			t.Fatal(err)
		}
	}
	filter := RequestFilter{Project: project, SharedProject: project, Since: time.Now().Add(-time.Minute), Limit: 10}
	items, err := state.ListRequests(ctx, filter)
	if err != nil || len(items) != 1 || items[0].RequestNumber != 1 || items[0].DetailAvailable {
		t.Fatalf("current worktree = %+v, %v", items, err)
	}
	filter.AllWorktrees = true
	items, err = state.ListRequests(ctx, filter)
	if err != nil || len(items) != 2 || items[0].RequestNumber != 2 || !items[0].DetailAvailable || len(items[0].Detail) != 0 {
		t.Fatalf("linked worktrees = %+v, %v", items, err)
	}
	item, err := state.GetRequest(ctx, primary, 2)
	if err != nil || string(item.Detail) != `{"query":"token=secret"}` || item.Project != otherWorktree {
		t.Fatalf("detail = %+v, %v", item, err)
	}
	if _, err := state.GetRequest(ctx, filepath.Join(t.TempDir(), "different"), 2); err == nil {
		t.Fatal("another checkout resolved request number 2")
	}
	if err := state.pruneRequests(ctx); err != nil {
		t.Fatal(err)
	}
	if err := state.saveRequest(ctx, "tun_test", primary, project, project, "web",
		RequestRecord{ReceivedAt: time.Now().UTC(), Method: "GET", Path: "/", Status: 200, Origin: "local_service"}); err != nil {
		t.Fatal(err)
	}
	item, err = state.GetRequest(ctx, primary, 3)
	if err != nil || item.RequestNumber != 3 {
		t.Fatalf("next number = %+v, %v", item, err)
	}
}

func TestRequestHistoryPrunesOldAndExcessRows(t *testing.T) {
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
			(request_number, primary_checkout_root, tunnel_id, project_root, shared_project_root,
			 service, received_at, method, path, status, duration_ms, origin, capture_mode)
			 VALUES (?, '/shop', 'tun_test', '/shop/web', '/shop/web', 'web', ?, 'GET', '/', 200, 1, 'local_service', 'summary')`, index+1, at.UnixNano())
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := state.pruneRequests(ctx); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := state.db.QueryRowContext(ctx, `SELECT count(*) FROM local_requests`).Scan(&count); err != nil || count != requestMaxRows {
		t.Fatalf("retained = %d, %v", count, err)
	}
	if _, err := state.GetRequest(ctx, "/shop", 1); err == nil {
		t.Fatal("expired request remained queryable")
	}
	if _, err := state.GetRequest(ctx, "/shop", int64(requestMaxRows+2)); err != nil {
		t.Fatal(err)
	}
}
