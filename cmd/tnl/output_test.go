package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/serverclient"
)

func TestPublishOutputNDJSONLifecycle(t *testing.T) {
	var stdout, stderr bytes.Buffer
	output, err := newPublishOutput("ndjson", &stdout, &stderr, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := output.starting("tunnel_0123456789abcdef0123456789abcdef", "http://127.0.0.1:3000"); err != nil {
		t.Fatal(err)
	}
	if err := output.currentIP("192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	if err := output.ready("https://demo.example", 1); err != nil {
		t.Fatal(err)
	}
	if err := output.ready("https://demo.example", 2); err != nil {
		t.Fatal(err)
	}
	if err := output.failed(&serverclient.RateLimitError{RetryAfter: time.Second}); err != nil {
		t.Fatal(err)
	}
	if err := output.stopped(); err != nil {
		t.Fatal(err)
	}
	if encoded := stdout.String(); !strings.Contains(encoded, `"route_version":1`) || strings.Contains(encoded, `"version":`) {
		t.Fatalf("NDJSON route version fields = %q", encoded)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q", stderr.String())
	}
	decoder := json.NewDecoder(&stdout)
	wantTypes := []string{"starting", "current_ip", "ready", "ready", "error", "stopped"}
	for index, wantType := range wantTypes {
		var event publishEvent
		if err := decoder.Decode(&event); err != nil {
			t.Fatal(err)
		}
		if event.SchemaVersion != 1 || event.Cursor != uint64(index+1) || event.Type != wantType ||
			event.TunnelID != "tunnel_0123456789abcdef0123456789abcdef" {
			t.Fatalf("event %d = %#v", index, event)
		}
		if wantType == "current_ip" && event.IP != "192.0.2.1" {
			t.Fatalf("current IP event = %#v", event)
		}
		if wantType == "ready" && event.RouteVersion != uint64(index-1) {
			t.Fatalf("ready event = %#v", event)
		}
		if wantType == "error" && (event.Retryable == nil || !*event.Retryable || event.RetryAt == nil) {
			t.Fatalf("error event = %#v", event)
		}
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		t.Fatalf("trailing output: %v", err)
	}
}

func TestPublishOutputHumanPrintsURLOnce(t *testing.T) {
	var stdout, stderr bytes.Buffer
	var opened []string
	output, err := newPublishOutput("human", &stdout, &stderr, func(target string) error {
		opened = append(opened, target)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := output.ready("https://demo.example", 1); err != nil {
		t.Fatal(err)
	}
	if err := output.currentIP("2001:db8::1"); err != nil {
		t.Fatal(err)
	}
	if err := output.ready("https://demo.example", 2); err != nil {
		t.Fatal(err)
	}
	if err := output.failed(errors.New("failure")); err != nil {
		t.Fatal(err)
	}
	if stdout.Len() != 0 || stderr.String() != "https://demo.example\nCurrent IP: 2001:db8::1\n" {
		t.Fatalf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
	}
	if len(opened) != 1 || opened[0] != "https://demo.example" {
		t.Fatalf("opened = %#v", opened)
	}
}

func TestPublishOutputNDJSONIncludesDiagnosticFields(t *testing.T) {
	var stdout bytes.Buffer
	output, err := newPublishOutput("ndjson", &stdout, io.Discard, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := output.failed(diagnostic.Wrap(diagnostic.TargetUnavailable, errors.New("connection refused"))); err != nil {
		t.Fatal(err)
	}
	var event publishEvent
	if err := json.NewDecoder(&stdout).Decode(&event); err != nil {
		t.Fatal(err)
	}
	if event.Code != string(diagnostic.TargetUnavailable) || event.HelpURL != diagnostic.HelpURL(diagnostic.TargetUnavailable) ||
		event.Message != "connection refused" {
		t.Fatalf("event = %#v", event)
	}
}

func TestPublishOutputNDJSONWarnsWhenBrowserCannotOpen(t *testing.T) {
	var stdout, stderr bytes.Buffer
	openCount := 0
	output, err := newPublishOutput("ndjson", &stdout, &stderr, func(string) error {
		openCount++
		return errors.New("browser unavailable")
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := output.ready("https://demo.example", 1); err != nil {
		t.Fatal(err)
	}
	if err := output.ready("https://demo.example", 2); err != nil {
		t.Fatal(err)
	}
	if openCount != 1 {
		t.Fatalf("open count = %d", openCount)
	}
	if got := stderr.String(); got != "tnl: could not open https://demo.example: browser unavailable\n" {
		t.Fatalf("stderr = %q", got)
	}
	var first, second publishEvent
	decoder := json.NewDecoder(&stdout)
	if err := decoder.Decode(&first); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(&second); err != nil {
		t.Fatal(err)
	}
	if first.Type != "ready" || second.Type != "ready" {
		t.Fatalf("events = %#v, %#v", first, second)
	}
}

func TestBoundedOutputError(t *testing.T) {
	message := boundedOutputError(errors.New(strings.Repeat("x", 2048)))
	if len(message) != 1024 {
		t.Fatalf("message length = %d", len(message))
	}
}
