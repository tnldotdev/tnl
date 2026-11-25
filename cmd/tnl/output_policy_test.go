package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
)

func TestOutputPreferenceUsesCommandAndMode(t *testing.T) {
	for _, tt := range []struct {
		env, args, output string
		machine           bool
	}{
		{"auto", "status", "human", false},
		{"machine", "status", "json", true},
		{"machine", "wait", "json", true},
		{"machine", "watch", "ndjson", true},
		{"human", "feedback watch", "human", false},
		{"machine", "status --output human", "human", false},
		{"human", "status --output json", "json", true},
		{"machine", "publish 3000", "ndjson", true},
		{"machine", "publish 3000 --bg", "json", true},
		{"machine", "publish 3000 --background", "json", true},
		{"machine", "publish 3000 --install", "human", false},
		{"machine", "connect orders", "json", true},
		{"machine", "connect orders --stdio", "human", false},
		{"machine", "connect orders --client psql", "human", false},
		{"machine", "connect orders -- psql --output=json", "human", false},
		{"machine", "share token create orders.example.com", "human", false},
		{"machine", "share service token create orders", "human", false},
		{"human", "runtime connections read --handle path --service orders", "json", true},
		{"machine", "version", "", false},
	} {
		t.Run(tt.env+"/"+tt.args, func(t *testing.T) {
			t.Setenv("AI_AGENT", "custom-agent@2")
			t.Setenv("TNL_OUTPUT", tt.env)
			var flags cli
			cmd, err := commandForTest(&flags, io.Discard)(strings.Fields(tt.args))
			if err != nil {
				t.Fatal(err)
			}
			app := commandApp{flags: &flags}
			if err := app.selectOutput(cmd); err != nil {
				t.Fatal(err)
			}
			var output string
			if f := cmd.Flags().Lookup("output"); f != nil {
				output = f.Value.String()
			}
			if output != tt.output || app.machineOutput != tt.machine {
				t.Errorf("output %q, machine error %t; want %q, %t", output, app.machineOutput, tt.output, tt.machine)
			}
		})
	}
}

func TestOutputIntentSurvivesArgumentErrors(t *testing.T) {
	for _, tt := range []struct {
		env, args, message string
		machine            bool
	}{
		{"machine", "status --typo", "Unknown flag: --typo", true},
		{"machine", "status --typo --output human", "Unknown flag: --typo", false},
		{"auto", "status --typo --output=json --output=human", "Unknown flag: --typo", false},
		{"human", "status --typo --output json", "Unknown flag: --typo", true},
		{"auto", "auth login --server --output=json --typo", "Unknown flag: --typo", false},
		{"machine", "connect orders --typo --stdio", "Unknown flag: --typo", false},
		{"machine", "connect orders --typo -- psql --output=json", "Unknown flag: --typo", false},
		{"machine", "connect --typo -- orders", "Unknown flag: --typo", true},
		{"human", "--typo runtime connections capabilities", "Unknown flag: --typo", true},
		{"auto", "status --output=ndjson", "Invalid value for --output. Choose human, json.", true},
		{"auto", "status --output=robot", "Invalid value for --output. Choose human, json.", false},
		{"broken", "status", "Set TNL_OUTPUT to human, machine, or auto.", false},
		{"broken", "status --typo --output=json", "Unknown flag: --typo", true},
		{"auto", "connect orders --stdio --output=json", "--stdio carries a raw stream. Remove --output=json to use it.", true},
		{"auto", "publish 3000 --install --output=ndjson", "--install requires --output=human.", true},
	} {
		t.Run(tt.env+"/"+tt.args, func(t *testing.T) {
			t.Setenv("TNL_OUTPUT", tt.env)
			var stdout, stderr bytes.Buffer
			err := run(t.Context(), strings.Fields(tt.args), &stdout, &stderr)
			if err == nil || stdout.Len() != 0 {
				t.Fatalf("err=%v stdout=%q", err, &stdout)
			}
			writeCommandError(&stderr, err)
			var d commandDiagnostic
			if tt.machine {
				if err := json.Unmarshal(stderr.Bytes(), &d); err != nil || d.Message != tt.message {
					t.Fatalf("want a JSON error with message %q; got %q (%v)", tt.message, &stderr, err)
				}
			} else if !strings.HasPrefix(stderr.String(), "Error: "+tt.message+"\n") {
				t.Fatalf("want a human error with message %q; got %q", tt.message, &stderr)
			}
		})
	}
}

func TestObservationRecoveryKeepsInvocationScope(t *testing.T) {
	flags := cli{
		ConfigPath: "/work tree/tnl.yml",
		Wait:       waitCommand{StateDir: "/client state", Service: []string{"accounts"}, Output: "json"},
		Watch:      watchCommand{StateDir: "/other state", Service: "accounts", After: "expired", Count: 1, Timeout: 30 * time.Second, Output: "ndjson"},
	}
	for _, tt := range []struct {
		reason failure.Reason
		want   []string
	}{
		{failure.AppReadinessTimeout, []string{"tnl", "--config", "/work tree/tnl.yml", "status", "--last-known", "--service", "accounts", "--state-dir", "/client state", "--output", "json"}},
		{failure.AppCursorExpired, []string{"tnl", "--config", "/work tree/tnl.yml", "watch", "--service", "accounts", "--count", "1", "--timeout", "30s", "--state-dir", "/other state", "--output", "ndjson"}},
	} {
		err := observationFollowup(failure.Wrap("observe", tt.reason, errors.New("test")), flags)
		if cmd := commandDiagnosticFor(err).Command; !slices.Equal(cmd, tt.want) {
			t.Errorf("got %q, want %q", cmd, tt.want)
		}
		if cmd := presentHumanFailure(err).action; cmd != guidanceCommand(tt.want) {
			t.Errorf("human follow-up = %q", cmd)
		}
	}
}

func TestObservationRecoveryKeepsHumanOverride(t *testing.T) {
	t.Setenv("TNL_OUTPUT", "machine")
	err := failure.Wrap("check readiness", failure.AppReadinessTimeout, errors.New("timeout"))
	flags := cli{Wait: waitCommand{Output: "human"}}
	followup := commandDiagnosticFor(observationFollowup(err, flags)).Command
	var parsedFlags cli
	cmd, err := commandForTest(&parsedFlags, io.Discard)(followup[1:])
	if err != nil {
		t.Fatal(err)
	}
	a := commandApp{flags: &parsedFlags}
	if err := a.selectOutput(cmd); err != nil || a.machineOutput || parsedFlags.Status.Output != statusOutputHuman {
		t.Fatalf("recovery %q: got %q, err %v", followup, parsedFlags.Status.Output, err)
	}
}

func TestJobStopReceiptJSON(t *testing.T) {
	const job = "job_0123456789abcdefghijkl"
	for _, state := range []string{"stopping", "stopped"} {
		var stdout bytes.Buffer
		if err := writeStopJobResult(&stdout, statusOutputJSON, job, state); err != nil {
			t.Fatal(err)
		}
		var receipt struct {
			SchemaVersion int    `json:"schema_version"`
			JobID         string `json:"job_id"`
			State         string `json:"state"`
		}
		if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil ||
			receipt.SchemaVersion != 1 || receipt.JobID != job || receipt.State != state {
			t.Fatalf("%s receipt: %q", state, &stdout)
		}
	}
}
