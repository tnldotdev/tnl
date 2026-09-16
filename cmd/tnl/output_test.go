package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/diagnostic"
)

func TestPublishOutputNDJSONLifecycle(t *testing.T) {
	var stdout, stderr bytes.Buffer
	output, err := newPublishOutput("ndjson", "tnl publish", &stdout, &stderr, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := output.starting("tunnel_0123456789abcdef0123456789abcdef", "http://127.0.0.1:3000"); err != nil {
		t.Fatal(err)
	}
	if err := output.currentIP("192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	if err := output.provisioning("demo.example", 1); err != nil {
		t.Fatal(err)
	}
	if err := output.blockedVisitors(1, 3); err != nil {
		t.Fatal(err)
	}
	if err := output.ready("https://demo.example", 1); err != nil {
		t.Fatal(err)
	}
	if err := output.ready("https://demo.example", 2); err != nil {
		t.Fatal(err)
	}
	if err := output.failed(&controlclient.RateLimitError{RetryAfter: time.Second}); err != nil {
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
	output, err := newPublishOutput("human", "tnl publish", &stdout, &stderr, func(target string) error {
		opened = append(opened, target)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := output.starting("tunnel_0123456789abcdef0123456789abcdef", "http://127.0.0.1:3000"); err != nil {
		t.Fatal(err)
	}
	if err := output.currentIP("2001:db8::1"); err != nil {
		t.Fatal(err)
	}
	if err := output.ready("https://demo.example", 1); err != nil {
		t.Fatal(err)
	}
	if err := output.ready("https://demo.example", 2); err != nil {
		t.Fatal(err)
	}
	if err := output.failed(errors.New("failure")); err != nil {
		t.Fatal(err)
	}
	if stdout.Len() != 0 || !strings.HasPrefix(stderr.String(), "+--[ tnl publish ]-- ready ") ||
		!strings.Contains(stderr.String(), "https://demo.example") ||
		!strings.Contains(stderr.String(), "IP policy") || !strings.Contains(stderr.String(), "2001:db8::1") ||
		!strings.Contains(stderr.String(), "+-- opened in browser; ctrl+c to stop ") {
		t.Fatalf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
	}
	if len(opened) != 1 || opened[0] != "https://demo.example" {
		t.Fatalf("opened = %#v", opened)
	}
}

func TestPublishOutputNDJSONIncludesDiagnosticFields(t *testing.T) {
	var stdout bytes.Buffer
	output, err := newPublishOutput("ndjson", "tnl publish", &stdout, io.Discard, nil)
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

func TestPublishOutputProvisioningStalledWarning(t *testing.T) {
	var stdout, stderr bytes.Buffer
	output, err := newPublishOutput("ndjson", "tnl publish", &stdout, &stderr, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := output.starting("tunnel_0123456789abcdef0123456789abcdef", "http://127.0.0.1:3000"); err != nil {
		t.Fatal(err)
	}
	if err := output.provisioning("demo.example", 2); err != nil {
		t.Fatal(err)
	}
	if err := output.provisioningStalled(1); err != nil {
		t.Fatal(err)
	}
	if err := output.provisioningStalled(2); err != nil {
		t.Fatal(err)
	}
	if err := output.provisioningStalled(2); err != nil {
		t.Fatal(err)
	}

	decoder := json.NewDecoder(&stdout)
	var starting, warning publishEvent
	if err := decoder.Decode(&starting); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(&warning); err != nil {
		t.Fatal(err)
	}
	if starting.Type != "starting" || warning.Type != "warning" || warning.RouteVersion != 2 ||
		warning.Code != string(diagnostic.ProvisioningStalled) ||
		warning.HelpURL != diagnostic.HelpURL(diagnostic.ProvisioningStalled) ||
		warning.Message != diagnostic.Summary(diagnostic.ProvisioningStalled) ||
		warning.Retryable == nil || !*warning.Retryable {
		t.Fatalf("events = %#v, %#v", starting, warning)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		t.Fatalf("trailing event: %v", err)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestPublishOutputHumanProvisioningWarningStopsAtReady(t *testing.T) {
	var stderr bytes.Buffer
	output, err := newPublishOutput("human", "tnl dev", io.Discard, &stderr, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := output.starting("tunnel_0123456789abcdef0123456789abcdef", "http://127.0.0.1:3000"); err != nil {
		t.Fatal(err)
	}
	if err := output.provisioning("demo.example", 1); err != nil {
		t.Fatal(err)
	}
	if err := output.provisioningStalled(1); err != nil {
		t.Fatal(err)
	}
	if err := output.provisioningStalled(1); err != nil {
		t.Fatal(err)
	}
	if err := output.provisioning("demo.example", 2); err != nil {
		t.Fatal(err)
	}
	if err := output.ready("https://demo.example", 2); err != nil {
		t.Fatal(err)
	}
	if err := output.provisioningStalled(2); err != nil {
		t.Fatal(err)
	}
	got := stderr.String()
	if strings.Count(got, string(diagnostic.ProvisioningStalled)) != 1 ||
		!strings.Contains(got, diagnostic.HelpURL(diagnostic.ProvisioningStalled)) ||
		strings.Count(got, "]-- provisioning stalled ") != 1 {
		t.Fatalf("human warning output = %q", got)
	}
}

func TestPublishOutputTransportFallbackWarning(t *testing.T) {
	var stdout bytes.Buffer
	output, err := newPublishOutput("ndjson", "tnl publish", &stdout, io.Discard, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := output.starting("tunnel_0123456789abcdef0123456789abcdef", "http://127.0.0.1:3000"); err != nil {
		t.Fatal(err)
	}
	if err := output.transportFallback(2, "tls-tcp"); err != nil {
		t.Fatal(err)
	}
	if err := output.transportFallback(2, "tls-tcp"); err != nil {
		t.Fatal(err)
	}
	if err := output.ready("https://demo.example", 2); err != nil {
		t.Fatal(err)
	}

	decoder := json.NewDecoder(&stdout)
	var starting, warning, ready publishEvent
	for _, event := range []*publishEvent{&starting, &warning, &ready} {
		if err := decoder.Decode(event); err != nil {
			t.Fatal(err)
		}
	}
	if starting.Type != "starting" || warning.Type != "warning" || warning.RouteVersion != 2 ||
		warning.Transport != "tls-tcp" || warning.Retryable == nil || *warning.Retryable ||
		!strings.Contains(warning.Message, "QUIC did not establish") || ready.Type != "ready" {
		t.Fatalf("events = %#v, %#v, %#v", starting, warning, ready)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		t.Fatalf("trailing event: %v", err)
	}
}

func TestPublishOutputHumanShowsTransportFallbackAtReady(t *testing.T) {
	var stderr bytes.Buffer
	output, err := newPublishOutput("human", "tnl dev", io.Discard, &stderr, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := output.transportFallback(3, "tls-tcp"); err != nil {
		t.Fatal(err)
	}
	if err := output.ready("https://demo.example", 3); err != nil {
		t.Fatal(err)
	}
	got := stderr.String()
	if strings.Count(got, "+--[ tnl dev ]-- transport fallback ") != 1 ||
		!strings.Contains(got, "tunnel continues over TLS/TCP") ||
		!strings.Contains(got, "transport      TLS/TCP fallback") {
		t.Fatalf("human output = %q", got)
	}
}

func TestPublishOutputNDJSONWarnsWhenBrowserCannotOpen(t *testing.T) {
	var stdout, stderr bytes.Buffer
	openCount := 0
	output, err := newPublishOutput("ndjson", "tnl publish", &stdout, &stderr, func(string) error {
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

func TestPublishOutputHumanFramesBrowserFailure(t *testing.T) {
	var stderr bytes.Buffer
	output, err := newPublishOutput("human", "tnl dev", io.Discard, &stderr, func(string) error {
		return errors.New("browser\x1b unavailable")
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := output.starting("tunnel_0123456789abcdef0123456789abcdef", "http://127.0.0.1:5173"); err != nil {
		t.Fatal(err)
	}
	if err := output.ready("https://demo.example", 1); err != nil {
		t.Fatal(err)
	}
	got := stderr.String()
	if strings.Count(got, "+--[ tnl dev ]-- ") != 2 ||
		!strings.Contains(got, "]-- ready ") || !strings.Contains(got, "]-- browser not opened ") ||
		!strings.Contains(got, `browser\x1b unavailable`) || strings.ContainsRune(got, '\x1b') {
		t.Fatalf("stderr = %q", got)
	}
}

func TestPublishOutputHumanFramesConnectionDisruption(t *testing.T) {
	var stderr bytes.Buffer
	output, err := newPublishOutput("human", "tnl publish", io.Discard, &stderr, nil)
	if err != nil {
		t.Fatal(err)
	}
	output.logf("connection %s", "lost")
	got := stderr.String()
	if !strings.HasPrefix(got, "+--[ tnl publish ]-- publisher connection disrupted ") ||
		!strings.Contains(got, "connection lost") || !strings.Contains(got, "+-- reconnecting ") {
		t.Fatalf("stderr = %q", got)
	}
}

func TestPublishOutputHumanProvisioningAndAggregateDenials(t *testing.T) {
	var stderr bytes.Buffer
	output, err := newPublishOutput("human", "tnl publish", io.Discard, &stderr, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := output.starting("tunnel_0123456789abcdef0123456789abcdef", "http://127.0.0.1:3000"); err != nil {
		t.Fatal(err)
	}
	for _, version := range []uint64{2, 2, 3} {
		if err := output.provisioning("demo.example", version); err != nil {
			t.Fatal(err)
		}
	}
	for _, total := range []uint64{2, 2, 5} {
		if err := output.blockedVisitors(3, total); err != nil {
			t.Fatal(err)
		}
	}
	got := stderr.String()
	if strings.Count(got, "]-- provisioning ") != 2 || strings.Count(got, "]-- visitors blocked ") != 2 ||
		!strings.Contains(got, "certificate and publisher connections") ||
		!strings.Contains(got, "newly blocked") || !strings.Contains(got, "total blocked") ||
		strings.Contains(got, "192.0.2") || strings.ContainsRune(got, '\x1b') {
		t.Fatalf("human lifecycle output = %q", got)
	}
	for _, line := range strings.Split(got, "\n") {
		if len(line) > 72 {
			t.Fatalf("line exceeds 72 columns: %q", line)
		}
	}
}

func TestBoundedOutputError(t *testing.T) {
	message := boundedOutputError(errors.New(strings.Repeat("x", 2048)))
	if len(message) != 1024 {
		t.Fatalf("message length = %d", len(message))
	}
}
