package main

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/inspection"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestInspectCommandsScopeTypedJSONToCurrentProject(t *testing.T) {
	project := t.TempDir()
	t.Chdir(project)
	stateRoot := filepath.Join(t.TempDir(), "state")
	t.Setenv("TNL_STATE_DIR", stateRoot)
	var stdout, stderr bytes.Buffer
	var events []telemetryPayload
	factory := func(string) telemetryReporter {
		return telemetryReporterFunc(func(event telemetryPayload) { events = append(events, event) })
	}
	if err := run(t.Context(), []string{"inspect", "list", "--output=json"}, &stdout, &stderr, factory); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].Command != telemetryInspect || events[0].Action != "list" ||
		events[1].Event != telemetryCommandCompleted || events[1].Action != "list" {
		t.Fatalf("list telemetry = %+v", events)
	}
	var list struct {
		SchemaVersion int                `json:"schema_version"`
		Inspections   []inspectionRecord `json:"inspections"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &list); err != nil || list.SchemaVersion != 2 || len(list.Inspections) != 0 {
		t.Fatalf("list = %+v, %v", list, err)
	}
	stdout.Reset()
	events = nil
	if err := run(t.Context(), []string{"inspect", "show", "1", "--output=json"}, &stdout, &stderr, factory); err == nil {
		t.Fatal("unknown inspection was found")
	}
	if len(events) != 2 || events[0].Action != "show" || events[1].Event != telemetryCommandFailed {
		t.Fatalf("show telemetry = %+v", events)
	}
	if err := run(t.Context(), []string{"requests", "list"}, &stdout, &stderr, factory); err == nil {
		t.Fatal("retired requests command is still accepted")
	}
}

func TestInspectListAndShowTypeAnHTTPObservation(t *testing.T) {
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(project)
	stateRoot := filepath.Join(t.TempDir(), "state")
	t.Setenv("TNL_STATE_DIR", stateRoot)
	database, err := clientstate.Open(t.Context(), stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	tunnel, err := database.BeginTunnel(t.Context(), clientstate.BeginTunnelOptions{
		Command: clientstate.TunnelCommandPublish, Server: "https://server.example", Target: "3000", Project: project, Service: "web",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Finish(context.Background(), nil)
	primary, shared, err := inspectionRoots(t.Context(), project)
	if err != nil {
		t.Fatal(err)
	}
	recorder := tunnel.NewInspectionRecorder(primary, project, shared, "web", inspection.Policy{Retention: 24 * time.Hour, MaxBytes: 64 << 20})
	recorder.Observe(clientstate.InspectionRecord{
		ReceivedAt: time.Now().UTC(), Method: "GET", Path: "/health", Status: 200,
		Origin: "local_service", DurationMS: 12,
	})
	recorder.Observe(clientstate.InspectionRecord{
		ReceivedAt: time.Now().UTC(), Method: "POST", Path: "/checkout", Status: 500,
		Origin: "local_service", DurationMS: 25,
	})
	recorder.Observe(clientstate.InspectionRecord{
		ReceivedAt: time.Now().UTC(), Method: "GET", Path: "/missing", Status: 404,
		Origin: "tnl", DurationMS: 1,
	})
	recorder.Close()
	var listOutput bytes.Buffer
	if err := run(t.Context(), []string{"inspect", "list", "--output=json"}, &listOutput, &bytes.Buffer{}, nil); err != nil {
		t.Fatal(err)
	}
	var list struct {
		SchemaVersion int                `json:"schema_version"`
		Inspections   []inspectionRecord `json:"inspections"`
	}
	if err := json.Unmarshal(listOutput.Bytes(), &list); err != nil || len(list.Inspections) != 3 ||
		list.Inspections[0].Protocol != "http" || list.Inspections[0].HTTP == nil ||
		list.Inspections[0].Result != "error" || list.Inspections[0].HTTP.Status != 404 ||
		list.Inspections[1].Result != "error" || list.Inspections[1].HTTP.Status != 500 ||
		list.Inspections[2].Result != "ok" || list.Inspections[2].HTTP.Status != 200 {
		t.Fatalf("typed HTTP list = %s, %v", listOutput.String(), err)
	}
	listOutput.Reset()
	if err := run(t.Context(), []string{"inspect", "list", "--result=ok", "--limit=1", "--output=json"}, &listOutput, &bytes.Buffer{}, nil); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(listOutput.Bytes(), &list); err != nil || len(list.Inspections) != 1 ||
		list.Inspections[0].Number != 1 || list.Inspections[0].Result != "ok" {
		t.Fatalf("HTTP result filter before limit = %s, %v", listOutput.String(), err)
	}
	listOutput.Reset()
	if err := run(t.Context(), []string{"inspect", "list", "--result=error", "--output=json"}, &listOutput, &bytes.Buffer{}, nil); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(listOutput.Bytes(), &list); err != nil || len(list.Inspections) != 2 ||
		list.Inspections[0].HTTP.Status != 404 || list.Inspections[1].HTTP.Status != 500 {
		t.Fatalf("HTTP error results = %s, %v", listOutput.String(), err)
	}
	if err := run(t.Context(), []string{"inspect", "list", "--result=unknown"}, &bytes.Buffer{}, &bytes.Buffer{}, nil); err == nil {
		t.Fatal("unknown inspection result was accepted")
	}
	var showOutput bytes.Buffer
	if err := run(t.Context(), []string{"inspect", "show", "1", "--output=json"}, &showOutput, &bytes.Buffer{}, nil); err != nil {
		t.Fatal(err)
	}
	var show struct {
		Inspection inspectionRecord `json:"inspection"`
	}
	if err := json.Unmarshal(showOutput.Bytes(), &show); err != nil || show.Inspection.Number != 1 ||
		show.Inspection.HTTP == nil || show.Inspection.HTTP.Path != "/health" || show.Inspection.Result != "ok" {
		t.Fatalf("typed HTTP inspection = %s, %v", showOutput.String(), err)
	}
}

func TestInspectSQLAndRedisListAndShowSummaries(t *testing.T) {
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(project)
	stateRoot := filepath.Join(t.TempDir(), "state")
	t.Setenv("TNL_STATE_DIR", stateRoot)
	database, err := clientstate.Open(t.Context(), stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	tunnel, err := database.BeginTunnel(t.Context(), clientstate.BeginTunnelOptions{
		Command: clientstate.TunnelCommandPublish, Server: "https://server.example", Target: "127.0.0.1:5432",
		Project: project, Service: "orders", ServiceProtocol: controlv1.Postgres,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Finish(context.Background(), nil)
	primary, shared, err := inspectionRoots(t.Context(), project)
	if err != nil {
		t.Fatal(err)
	}
	policy := inspection.Policy{Retention: 24 * time.Hour, MaxBytes: 64 << 20}
	recorder := tunnel.NewInspectionRecorder(primary, project, shared, "orders", policy)
	recorder.Observe(clientstate.InspectionRecord{
		Protocol: controlv1.Postgres, ReceivedAt: time.Now().UTC(), Origin: "tnl",
		Operation: inspection.OperationExecute, Result: inspection.ResultError, SQLState: "42703",
	})
	recorder.Observe(clientstate.InspectionRecord{
		Protocol: controlv1.Mysql, ReceivedAt: time.Now().UTC().Add(time.Second), Origin: "tnl",
		Operation: inspection.OperationQuery, Result: inspection.ResultError, SQLState: "42S22", MySQLErrorCode: 1054,
	})
	recorder.Observe(clientstate.InspectionRecord{
		Protocol: controlv1.Redis, ReceivedAt: time.Now().UTC().Add(2 * time.Second), Origin: "tnl",
		RedisCommand: "PING", Result: inspection.ResultOK,
	})
	redisObservation(recorder)(publisher.RedisObservation{
		ReceivedAt: time.Now().UTC().Add(3 * time.Second), Command: "AUTH", Result: inspection.ResultError,
		Duration: 3 * time.Millisecond,
	})
	recorder.Close()
	var output bytes.Buffer
	if err := run(t.Context(), []string{"inspect", "list", "--protocol=postgres", "--result=error", "--output=json"}, &output, &bytes.Buffer{}, nil); err != nil {
		t.Fatal(err)
	}
	var list struct {
		Inspections []inspectionRecord `json:"inspections"`
	}
	if err := json.Unmarshal(output.Bytes(), &list); err != nil || len(list.Inspections) != 1 ||
		list.Inspections[0].Protocol != controlv1.Postgres || list.Inspections[0].Result != inspection.ResultError ||
		list.Inspections[0].Postgres == nil || list.Inspections[0].Postgres.SQLState != "42703" {
		t.Fatalf("PostgreSQL inspection list = %s, %v", output.String(), err)
	}
	for _, absent := range []string{`"capture_mode"`, `"detail_available"`, `"detail_hint"`, `"statement"`} {
		if bytes.Contains(output.Bytes(), []byte(absent)) {
			t.Fatalf("obsolete inspection detail %s: %s", absent, output.String())
		}
	}
	output.Reset()
	if err := run(t.Context(), []string{"inspect", "show", "1", "--output=json"}, &output, &bytes.Buffer{}, nil); err != nil {
		t.Fatal(err)
	}
	var show struct {
		Inspection inspectionRecord `json:"inspection"`
	}
	if err := json.Unmarshal(output.Bytes(), &show); err != nil || show.Inspection.Postgres == nil ||
		show.Inspection.Postgres.Operation != inspection.OperationExecute || show.Inspection.Postgres.SQLState != "42703" {
		t.Fatalf("PostgreSQL inspection summary = %s, %v", output.String(), err)
	}
	output.Reset()
	if err := run(t.Context(), []string{"inspect", "show", "2", "--output=json"}, &output, &bytes.Buffer{}, nil); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(output.Bytes(), &show); err != nil || show.Inspection.MySQL == nil ||
		show.Inspection.MySQL.ErrorCode != 1054 || show.Inspection.MySQL.SQLState != "42S22" {
		t.Fatalf("MySQL summary inspection = %s, %v", output.String(), err)
	}
	output.Reset()
	if err := run(t.Context(), []string{"inspect", "list", "--protocol=redis", "--result=ok", "--output=json"}, &output, &bytes.Buffer{}, nil); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(output.Bytes(), &list); err != nil || len(list.Inspections) != 1 ||
		list.Inspections[0].Redis == nil || list.Inspections[0].Redis.Command != "PING" || list.Inspections[0].Result != inspection.ResultOK {
		t.Fatalf("Redis inspection list = %s, %v", output.String(), err)
	}
	output.Reset()
	if err := run(t.Context(), []string{"inspect", "show", "3", "--output=json"}, &output, &bytes.Buffer{}, nil); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(output.Bytes(), &show); err != nil || show.Inspection.Redis == nil ||
		show.Inspection.Redis.Command != "PING" || show.Inspection.Result != inspection.ResultOK {
		t.Fatalf("Redis inspection summary = %s, %v", output.String(), err)
	}
	for _, args := range [][]string{
		{"inspect", "list", "--protocol=redis", "--output=json"},
		{"inspect", "show", "4", "--output=json"},
		{"inspect", "list", "--protocol=redis"},
		{"inspect", "show", "4"},
	} {
		output.Reset()
		if err := run(t.Context(), args, &output, &bytes.Buffer{}, nil); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(output.String(), "AUTH") || strings.Contains(output.String(), "testpass") ||
			strings.Contains(output.String(), "reply_body") || strings.Contains(output.String(), "arguments") {
			t.Fatalf("Redis inspection output for %v = %s", args, output.String())
		}
	}
	if err := run(t.Context(), []string{"inspect", "list", "--protocol=mysql", "--status=500"}, &bytes.Buffer{}, &bytes.Buffer{}, nil); err == nil {
		t.Fatal("HTTP-only status filter was accepted for MySQL")
	}
}
