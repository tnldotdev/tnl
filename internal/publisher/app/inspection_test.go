package app

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/observability/inspection"
)

func TestAppSummaryObservationStoresHTTPAndSQL(t *testing.T) {
	if SummaryObservation(nil) != nil {
		t.Fatal("disabled recording installed an observer")
	}
	root := t.TempDir()
	database, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(root, "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	tunnel, err := database.BeginTunnel(t.Context(), clientstate.BeginTunnelOptions{Command: clientstate.TunnelCommandPublish, Server: "https://control.example", Target: "http://127.0.0.1:3000", Project: root, Service: "web"})
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Finish(context.Background(), nil)
	recorder := tunnel.NewInspectionRecorder(root, root, root, "web", inspection.Policy{Mode: inspection.SummaryMode, Retention: time.Hour, MaxBytes: 1 << 20})
	observe := SummaryObservation(recorder)
	now := time.Now()
	observe(inspection.Summary{Protocol: inspection.HTTP, ReceivedAt: now, Method: "GET", Path: "/health", Status: 503, Result: inspection.ResultError, Duration: 2500 * time.Microsecond, Origin: "local_service"})
	observe(inspection.Summary{Protocol: inspection.HTTP, ReceivedAt: now.Add(500 * time.Microsecond), Method: "GET", Path: "/interrupted-response", Status: 200, Result: inspection.ResultError, Origin: "local_service"})
	observe(inspection.Summary{Protocol: inspection.MySQL, ReceivedAt: now.Add(time.Second), Operation: inspection.OperationExecute, Result: inspection.ResultError, SQLState: "HY000", MySQLErrorCode: 1045, Rows: 1, ResultSets: 2, Duration: 3 * time.Millisecond, Origin: "tnl"})
	recorder.Close()
	items, err := database.ListInspections(t.Context(), clientstate.InspectionFilter{Project: root, SharedProject: root, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 3 {
		t.Fatalf("stored summaries = %+v", items)
	}
	sql, appHTTP, http := items[0], items[1], items[2]
	if sql.Protocol != inspection.MySQL || sql.Operation != inspection.OperationExecute || sql.Result != inspection.ResultError || sql.SQLState != "HY000" || sql.MySQLErrorCode != 1045 || sql.Rows != 1 || sql.ResultSets != 2 || sql.DurationMS != 3 {
		t.Fatalf("database summary lost its outcome: %+v", sql)
	}
	if http.Protocol != inspection.HTTP || http.Result != inspection.ResultError || http.Path != "/health" || http.Status != 503 || http.DurationMS != 2 || http.Service != "web" || http.TunnelID != tunnel.ID() {
		t.Fatalf("HTTP summary changed storage policy or scope: %+v", http)
	}
	if appHTTP.Protocol != inspection.HTTP || appHTTP.Result != inspection.ResultError || appHTTP.Path != "/interrupted-response" || appHTTP.Status != 200 {
		t.Fatalf("app HTTP summary lost its completion outcome: %+v", appHTTP)
	}
}
