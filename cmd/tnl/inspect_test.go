package main

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
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
	if err := json.Unmarshal(stdout.Bytes(), &list); err != nil || list.SchemaVersion != 1 || len(list.Inspections) != 0 {
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
	primary, shared, err := requestRoots(t.Context(), project)
	if err != nil {
		t.Fatal(err)
	}
	recorder := tunnel.NewRequestRecorder(primary, project, shared, "web")
	recorder.Observe(clientstate.RequestRecord{
		ReceivedAt: time.Now().UTC(), Method: "GET", Path: "/health", Status: 200,
		Origin: "local_service", CaptureMode: "summary", DurationMS: 12,
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
	if err := json.Unmarshal(listOutput.Bytes(), &list); err != nil || len(list.Inspections) != 1 ||
		list.Inspections[0].Protocol != "http" || list.Inspections[0].HTTP == nil ||
		list.Inspections[0].Postgres != nil || list.Inspections[0].HTTP.Method != "GET" ||
		list.Inspections[0].HTTP.Status != 200 {
		t.Fatalf("typed HTTP list = %s, %v", listOutput.String(), err)
	}
	var showOutput bytes.Buffer
	if err := run(t.Context(), []string{"inspect", "show", "1", "--output=json"}, &showOutput, &bytes.Buffer{}, nil); err != nil {
		t.Fatal(err)
	}
	var show struct {
		Inspection inspectionRecord `json:"inspection"`
	}
	if err := json.Unmarshal(showOutput.Bytes(), &show); err != nil || show.Inspection.Number != 1 ||
		show.Inspection.HTTP == nil || show.Inspection.HTTP.Path != "/health" || show.Inspection.Postgres != nil {
		t.Fatalf("typed HTTP inspection = %s, %v", showOutput.String(), err)
	}
}
