package clientstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/inspection"
)

func TestInspectionProtocolStorageAndFilterContracts(t *testing.T) {
	state, err := Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	project := t.TempDir()
	now := time.Now().UTC()
	for _, protocol := range []inspection.Protocol{"", inspection.Postgres, inspection.MySQL, inspection.Redis} {
		record := InspectionRecord{Protocol: protocol, ReceivedAt: now, Origin: "tnl"}
		switch protocol {
		case "":
			record.Method, record.Path, record.Status = "GET", "/health", 200
		case inspection.Redis:
			record.RedisCommand, record.Result = "PING", inspection.ResultOK
		default:
			record.Operation, record.Result = inspection.OperationQuery, inspection.ResultOK
		}
		if err := state.saveInspection(t.Context(), "tun_test", project, project, project, "service", record, testInspectionPolicy()); err != nil {
			t.Fatal(err)
		}
	}
	filter := InspectionFilter{Project: project, SharedProject: project, Limit: 10}
	items, err := state.ListInspections(t.Context(), filter)
	if err != nil || len(items) != 4 {
		t.Fatalf("empty protocol filter = %d, %v", len(items), err)
	}
	for index, protocol := range []inspection.Protocol{inspection.HTTP, inspection.Postgres, inspection.MySQL, inspection.Redis} {
		var stored string
		if err := state.db.QueryRowContext(t.Context(), `SELECT service_protocol FROM inspections WHERE number = ?`, index+1).Scan(&stored); err != nil || stored != string(protocol) {
			t.Fatalf("stored protocol = %q, %v", stored, err)
		}
		filter.Protocol = protocol
		items, err := state.ListInspections(t.Context(), filter)
		if err != nil || len(items) != 1 || items[0].Protocol != protocol {
			t.Fatalf("typed filter %s = %+v, %v", protocol, items, err)
		}
		data, err := json.Marshal(items[0])
		if err != nil || !strings.Contains(string(data), `"protocol":"`+string(protocol)+`"`) {
			t.Fatalf("protocol JSON = %s, %v", data, err)
		}
	}
	for _, protocol := range []inspection.Protocol{"tcp", "kubernetes", "HTTP", "unknown"} {
		filter.Protocol = protocol
		if _, err := state.ListInspections(t.Context(), filter); err == nil {
			t.Fatalf("accepted unsupported filter %q", protocol)
		}
		if err := state.saveInspection(t.Context(), "tun_test", project, project, project, "service", InspectionRecord{Protocol: protocol, ReceivedAt: now}, testInspectionPolicy()); err == nil {
			t.Fatalf("accepted unsupported observation %q", protocol)
		}
	}
}

func testInspectionPolicy() inspection.Policy {
	return inspection.Policy{Retention: inspection.DefaultRetention, MaxBytes: inspection.DefaultMaxBytes}
}

func TestInspectionNumbersAndTypedResultsAcrossWorktrees(t *testing.T) {
	state, err := Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	primary := filepath.Join(t.TempDir(), "shop")
	project := filepath.Join(primary, "apps/web")
	otherWorktree := filepath.Join(t.TempDir(), "shop-feature", "apps/web")
	now := time.Now().UTC()
	for _, entry := range []struct {
		project string
		record  InspectionRecord
	}{
		{project, InspectionRecord{ReceivedAt: now, Method: "POST", Path: "/checkout", Status: 500,
			Origin: "local_service"}},
		{otherWorktree, InspectionRecord{ReceivedAt: now.Add(time.Second), Protocol: "postgres",
			Origin: "tnl", Operation: inspection.OperationExecute, Result: inspection.ResultError, SQLState: "42703"}},
		{project, InspectionRecord{ReceivedAt: now.Add(2 * time.Second), Protocol: "mysql",
			Origin: "tnl", Operation: inspection.OperationQuery, Result: inspection.ResultOK, Rows: 2, ResultSets: 1}},
		{project, InspectionRecord{ReceivedAt: now.Add(3 * time.Second), Protocol: "redis",
			Origin: "tnl", RedisCommand: "PING", Result: inspection.ResultOK}},
	} {
		if err := state.saveInspection(t.Context(), "tun_test", primary, entry.project, project, "orders", entry.record, testInspectionPolicy()); err != nil {
			t.Fatal(err)
		}
	}
	filter := InspectionFilter{Project: project, SharedProject: project, Limit: 10, Result: inspection.ResultError}
	items, err := state.ListInspections(t.Context(), filter)
	if err != nil || len(items) != 1 || items[0].Number != 1 || items[0].Protocol != inspection.HTTP {
		t.Fatalf("current worktree errors = %+v, %v", items, err)
	}
	filter.AllWorktrees = true
	items, err = state.ListInspections(t.Context(), filter)
	if err != nil || len(items) != 2 || items[0].Number != 2 || items[0].Protocol != "postgres" || items[1].Number != 1 {
		t.Fatalf("linked worktree failures = %+v, %v", items, err)
	}
	filter.Result = inspection.ResultOK
	filter.Protocol = "mysql"
	items, err = state.ListInspections(t.Context(), filter)
	if err != nil || len(items) != 1 || items[0].Number != 3 || items[0].ResultSets != 1 || items[0].Rows != 2 {
		t.Fatalf("MySQL outcomes = %+v, %v", items, err)
	}
	show, err := state.GetInspection(t.Context(), primary, 2)
	if err != nil || show.SQLState != "42703" || show.Operation != inspection.OperationExecute {
		t.Fatalf("local SQL summary = %+v, %v", show, err)
	}
	filter.Protocol = "redis"
	filter.Method = ""
	items, err = state.ListInspections(t.Context(), filter)
	if err != nil || len(items) != 1 || items[0].Number != 4 || items[0].RedisCommand != "PING" || items[0].Result != inspection.ResultOK {
		t.Fatalf("Redis summary = %+v, %v", items, err)
	}
	invalid := InspectionRecord{Protocol: "redis", ReceivedAt: now, Origin: "tnl", Result: inspection.ResultOK, RedisCommand: "AUTH password"}
	if err := state.saveInspection(t.Context(), "tun_test", primary, project, project, "orders", invalid, testInspectionPolicy()); err == nil {
		t.Fatal("Redis inspection retained command arguments")
	}
	filter.Protocol = "mysql"
	if _, err := state.GetInspection(t.Context(), filepath.Join(t.TempDir(), "different"), 2); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("another checkout found inspection: %v", err)
	}
	filter.Method = "GET"
	if _, err := state.ListInspections(t.Context(), filter); err == nil {
		t.Fatal("MySQL method filter was accepted")
	}
}

func TestInspectionRetentionAndByteBudgetArePerServiceAndWorktree(t *testing.T) {
	state, err := Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	project := t.TempDir()
	now := time.Now().UTC()
	state.now = func() time.Time { return now }
	short := inspection.Policy{Retention: time.Hour, MaxBytes: inspection.MinMaxBytes}
	long := inspection.Policy{Retention: 48 * time.Hour, MaxBytes: inspection.MinMaxBytes}
	observation := InspectionRecord{ReceivedAt: now, Method: "GET", Path: "/", Status: 200, Origin: "local_service"}
	if err := state.saveInspection(t.Context(), "tun_test", project, project, project, "web", observation, short); err != nil {
		t.Fatal(err)
	}
	if err := state.saveInspection(t.Context(), "tun_test", project, project, project, "orders", observation, long); err != nil {
		t.Fatal(err)
	}
	state.now = func() time.Time { return now.Add(2 * time.Hour) }
	if _, err := state.GetInspection(t.Context(), project, 1); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("short-lived inspection survived: %v", err)
	}
	if _, err := state.GetInspection(t.Context(), project, 2); err != nil {
		t.Fatalf("long-lived inspection expired early: %v", err)
	}
	state.now = func() time.Time { return now.Add(3 * time.Hour) }
	if err := state.saveInspection(t.Context(), "tun_test", project, project, project, "web", observation, short); err != nil {
		t.Fatal(err)
	}
	for index := range 150 {
		record := InspectionRecord{ReceivedAt: now.Add(time.Duration(index) * time.Second), Method: "GET",
			Path: "/" + strings.Repeat("x", 8<<10), Status: 200, Origin: "local_service"}
		if err := state.saveInspection(t.Context(), "tun_test", project, project, project, "orders", record, long); err != nil {
			t.Fatal(err)
		}
	}
	var size int64
	if err := state.db.QueryRowContext(context.Background(), `SELECT coalesce(sum(stored_bytes), 0) FROM inspections
		WHERE project_root = ? AND service = 'orders'`, project).Scan(&size); err != nil || size > long.MaxBytes {
		t.Fatalf("service inspection budget = %d, %v", size, err)
	}
	var accounted int64
	if err := state.db.QueryRowContext(t.Context(), `SELECT used_bytes FROM inspection_storage_usage
		WHERE project_root = ? AND service = 'orders'`, project).Scan(&accounted); err != nil || accounted != size {
		t.Fatalf("stored inspection byte accounting = %d, actual %d, %v", accounted, size, err)
	}
	if _, err := state.GetInspection(t.Context(), project, 2); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("oldest service inspection survived byte eviction: %v", err)
	}
	if _, err := state.GetInspection(t.Context(), project, 3); err != nil {
		t.Fatalf("other service was pruned by orders' budget: %v", err)
	}
	other := filepath.Join(t.TempDir(), "other-checkout")
	if err := state.saveInspection(t.Context(), "tun_other", other, other, project, "orders", observation, short); err != nil {
		t.Fatal(err)
	}
	if _, err := state.GetInspection(t.Context(), other, 1); err != nil {
		t.Fatalf("another worktree lost its service budget: %v", err)
	}
}
