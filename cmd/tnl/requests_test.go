package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/tnldotdev/tnl/internal/clientstate"
)

func TestRequestsCommandsScopeJSONToCurrentProject(t *testing.T) {
	project := t.TempDir()
	t.Chdir(project)
	stateRoot := filepath.Join(t.TempDir(), "state")
	t.Setenv("TNL_STATE_DIR", stateRoot)
	var stdout, stderr bytes.Buffer
	var events []telemetryPayload
	factory := func(string) telemetryReporter {
		return telemetryReporterFunc(func(event telemetryPayload) { events = append(events, event) })
	}
	if err := run(t.Context(), []string{"requests", "list", "--output=json"}, &stdout, &stderr, factory); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].Command != telemetryRequests || events[0].CommandPath != "requests list" ||
		events[1].Event != telemetryCommandCompleted || events[1].CommandPath != "requests list" {
		t.Fatalf("list telemetry = %+v", events)
	}
	var list struct {
		SchemaVersion int                         `json:"schema_version"`
		Requests      []clientstate.RequestRecord `json:"requests"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &list); err != nil || list.SchemaVersion != 1 || len(list.Requests) != 0 {
		t.Fatalf("list = %+v, %v", list, err)
	}
	stdout.Reset()
	events = nil
	if err := run(t.Context(), []string{"requests", "show", "1", "--output=json"}, &stdout, &stderr, factory); err == nil {
		t.Fatal("unknown request was found")
	}
	if len(events) != 2 || events[0].CommandPath != "requests show" || events[1].Event != telemetryCommandFailed {
		t.Fatalf("show telemetry = %+v", events)
	}
}
