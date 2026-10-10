package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/controlclient"
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
	err := failure.Wrap("recovery", failure.ServerResponseInvalid, controlclient.ErrUnavailable)
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
