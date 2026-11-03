package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/failure"
)

func TestMachineCommandFailureBeforeParsing(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run(context.Background(), []string{"unknown-command", "--access-token", "private-token", "--output", "json"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected invalid command")
	}
	writeCommandError(&stderr, err)
	var result struct {
		SchemaVersion int    `json:"schema_version"`
		Type          string `json:"type"`
		Reason        string `json:"reason"`
	}
	if err := json.Unmarshal(stderr.Bytes(), &result); err != nil {
		t.Fatalf("failure is not one JSON object: %v", err)
	}
	if result.SchemaVersion != 1 || result.Type != "error" || result.Reason != string(failure.InvalidCommand) || stdout.Len() != 0 {
		t.Fatalf("unexpected command failure: %+v", result)
	}
	if strings.Contains(stderr.String(), "private-token") || strings.Contains(stderr.String(), "+--[") {
		t.Fatal("machine failure contains an argument or human frame")
	}
}

func TestCommandDiagnosticPreservesOwnedRetryDecision(t *testing.T) {
	err := failure.Wrap("recovery", failure.ServerResponseInvalid, clientcontrol.ErrUnavailable)
	result := commandDiagnosticFor(err)
	if result.Reason != string(failure.ServerResponseInvalid) || result.Retryable {
		t.Fatalf("cause replaced owned failure meaning: %+v", result)
	}
	err = failure.Wrap("request", failure.ServerUnavailable, errors.New("private upstream detail"))
	result = commandDiagnosticFor(err)
	if !result.Retryable || strings.Contains(result.Message, "private upstream") {
		t.Fatalf("unexpected authored diagnostic: %+v", result)
	}
}

func TestMachineOutputDoesNotConsumeChildArguments(t *testing.T) {
	if machineOutputRequested([]string{"dev", "--", "node", "--output=json"}) {
		t.Fatal("child arguments selected CLI machine output")
	}
}

type retainedSDKFailureTest struct {
	error
	retained bool
}

func (e *retainedSDKFailureTest) Unwrap() error          { return e.error }
func (e *retainedSDKFailureTest) RetainSDKFailure() bool { return e.retained }
func (e *retainedSDKFailureTest) SDKFailureHandle() string {
	return strings.Repeat("a", 64) + "." + strings.Repeat("1", 16)
}

func TestConnectionMachineRetainedFailureCarriesOnlyNativeCloseReference(t *testing.T) {
	for _, retained := range []bool{false, true} {
		err := failure.Wrap("prepare SDK connection", failure.ConnectionUnavailable, &retainedSDKFailureTest{error: errors.New("private-assertion"), retained: retained})
		var output bytes.Buffer
		writeMachineCommandError(&output, err)
		var result commandDiagnostic
		if err := json.Unmarshal(output.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.SDKRetainedStartFailure != retained || (result.SDKFailureHandle != "") != retained || strings.Contains(output.String(), "private-assertion") {
			t.Fatal("native failure observation was lost or exposed private input", output.String())
		}
	}
}
