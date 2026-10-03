package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/authorityclient"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/demo"
	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/webhookips"
)

func TestPublishOutputNDJSONLifecycle(t *testing.T) {
	var stdout, stderr bytes.Buffer
	output, err := newPublishOutput("ndjson", "tnl publish", &stdout, &stderr, nil)
	if err != nil {
		t.Fatal(err)
	}
	output.setIPPolicy(resolvedIPPolicy{prefixes: []string{"192.0.2.1/32"}, sources: []webhookips.Source{{Name: "github", Prefixes: []string{"192.0.2.1/32"}}}})
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
	if encoded := stdout.String(); !strings.Contains(encoded, `"publish_run_number":1`) || strings.Contains(encoded, `"version":`) {
		t.Fatalf("NDJSON publish run number fields = %q", encoded)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q", stderr.String())
	}
	decoder := json.NewDecoder(&stdout)
	wantTypes := []publishEventType{publishEventStarting, publishEventCurrentIP, publishEventReady, publishEventReady, publishEventError, publishEventStopped}
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
		if wantType == "ready" && event.PublishRunNumber != uint64(index-1) {
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
		strings.Count(stderr.String(), "]-- ready ") != 1 ||
		strings.Count(stderr.String(), "https://demo.example") != 1 ||
		!strings.Contains(stderr.String(), "|    tnl ") ||
		strings.Contains(stderr.String(), "|  publisher ") ||
		!strings.Contains(stderr.String(), "automatically allowed IP") || !strings.Contains(stderr.String(), "2001:db8::1") ||
		strings.Contains(stderr.String(), "publish run number") ||
		!strings.Contains(stderr.String(), "+-- opened in browser; ctrl+c to stop ") {
		t.Fatalf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
	}
	if len(opened) != 1 || opened[0] != "https://demo.example" {
		t.Fatalf("opened = %#v", opened)
	}
}

func TestDemoOutputMatchesPageAndPrintsReadyBeforeOpening(t *testing.T) {
	var stdout, stderr bytes.Buffer
	output, err := newPublishOutput("human", "tnl publish", &stdout, &stderr, func(url string) error {
		if url != "https://real.generated.tnl.dev" || !strings.Contains(stderr.String(), "stamp") {
			t.Fatalf("browser opened before demo was ready: %q, %q", url, stderr.String())
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	output.setDemoStamp("a1b2c3d4")
	if err := output.starting("tunnel_1", "http://127.0.0.1:12345"); err != nil {
		t.Fatal(err)
	}
	if err := output.ready("https://real.generated.tnl.dev", 1); err != nil {
		t.Fatal(err)
	}
	if err := output.demoPing(demo.State{Stamp: "a1b2c3d4", RequestCount: 1}); err != nil {
		t.Fatal(err)
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "https://real.generated.tnl.dev") ||
		strings.Count(stderr.String(), "a1b2c3d4") != 2 ||
		!strings.Contains(stderr.String(), "|  count") || strings.Contains(stderr.String(), "request count") ||
		!strings.Contains(stderr.String(), "ping received") ||
		strings.ContainsRune(stderr.String(), '\x1b') {
		t.Fatalf("demo output = %q, stdout = %q", stderr.String(), stdout.String())
	}
}

func TestDemoPingKeepsNDJSONOnStdout(t *testing.T) {
	var stdout, stderr bytes.Buffer
	output, err := newPublishOutput("ndjson", "tnl publish", &stdout, &stderr, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := output.starting("tunnel_1", "http://127.0.0.1:12345"); err != nil {
		t.Fatal(err)
	}
	if err := output.demoPing(demo.State{Stamp: "a1b2c3d4", RequestCount: 1}); err != nil {
		t.Fatal(err)
	}
	var event publishEvent
	if err := json.NewDecoder(&stdout).Decode(&event); err != nil || event.Type != publishEventStarting {
		t.Fatalf("NDJSON event = %+v, error = %v", event, err)
	}
	if !strings.Contains(stderr.String(), "ping received") || strings.Contains(stdout.String(), "a1b2c3d4") {
		t.Fatalf("output = %q / %q", stdout.String(), stderr.String())
	}
}

func TestPublishOutputSummarizesLargeProviderPolicy(t *testing.T) {
	var stdout, stderr bytes.Buffer
	output, err := newPublishOutput("human", "tnl dev", &stdout, &stderr, nil)
	if err != nil {
		t.Fatal(err)
	}
	output.setIPPolicy(resolvedIPPolicy{
		prefixes: make([]string, 12345),
		sources: []webhookips.Source{
			{Name: "github", Prefixes: make([]string, 1024)},
			{Name: "stripe", Prefixes: make([]string, 15)},
		},
	})
	if err := output.starting("tunnel_123", "http://127.0.0.1:3000"); err != nil {
		t.Fatal(err)
	}
	if err := output.currentIP("192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	if err := output.ready("https://example.test", 1); err != nil {
		t.Fatal(err)
	}
	got := stderr.String()
	for _, value := range []string{"github webhook IPs", "1024 prefixes", "stripe webhook IPs", "15 prefixes", "allowed IP prefixes", "12345"} {
		if !strings.Contains(got, value) {
			t.Fatalf("ready frame omitted %q: %s", value, got)
		}
	}
	if len(strings.Split(got, "\n")) > 25 || stdout.Len() != 0 {
		t.Fatalf("provider summary was not compact: %s", got)
	}
	for _, line := range strings.Split(got, "\n") {
		if len(line) > 72 {
			t.Fatalf("ready frame line is %d columns: %q", len(line), line)
		}
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
		event.Message != diagnostic.Summary(diagnostic.TargetUnavailable) {
		t.Fatalf("event = %#v", event)
	}
}

func TestPublishOutputNDJSONOwnsSuccessfulErrorEvent(t *testing.T) {
	var stdout, stderr bytes.Buffer
	output, err := newPublishOutput("ndjson", "tnl publish", &stdout, &stderr, nil)
	if err != nil {
		t.Fatal(err)
	}
	failure := errors.New("publisher failed")
	result := output.finish(t.Context(), failure)
	if !errors.Is(result, failure) {
		t.Fatalf("finish error = %v", result)
	}
	if code, render := terminalResult(result); code != 1 || render != nil {
		t.Fatalf("terminal result = %d, %v", code, render)
	}
	decoder := json.NewDecoder(&stdout)
	var event publishEvent
	if err := decoder.Decode(&event); err != nil {
		t.Fatal(err)
	}
	if event.Type != "error" || event.Message != failure.Error() {
		t.Fatalf("event = %#v", event)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		t.Fatalf("duplicate event: %v", err)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRunPublishNDJSONFailureHasSingleOwner(t *testing.T) {
	var stdout, stderr bytes.Buffer
	result := runPublish(t.Context(), publishCommand{Target: "https://example.com", Output: "ndjson"}, &stdout, &stderr)
	if code, render := terminalResult(result); code != 1 || render != nil {
		t.Fatalf("terminal result = %d, %v", code, render)
	}
	decoder := json.NewDecoder(&stdout)
	var event publishEvent
	if err := decoder.Decode(&event); err != nil {
		t.Fatal(err)
	}
	if event.Type != "error" || event.Message == "" {
		t.Fatalf("event = %#v", event)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		t.Fatalf("duplicate event: %v", err)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestPublishOutputNDJSONRetainsFailedErrorEventWrite(t *testing.T) {
	writeErr := errors.New("output closed")
	output, err := newPublishOutput("ndjson", "tnl publish", errorWriter{writeErr}, io.Discard, nil)
	if err != nil {
		t.Fatal(err)
	}
	failure := errors.New("publisher failed")
	result := output.finish(t.Context(), failure)
	if !errors.Is(result, failure) || !errors.Is(result, writeErr) {
		t.Fatalf("finish error = %v", result)
	}
	if code, render := terminalResult(result); code != 1 || render == nil {
		t.Fatalf("terminal result = %d, %v", code, render)
	}
}

func TestPublishOutputNDJSONAuthorityRetryMetadata(t *testing.T) {
	for _, test := range []struct {
		name        string
		err         error
		wantRetryAt bool
	}{
		{name: "unavailable", err: authorityclient.ErrUnavailable},
		{name: "rate limited", err: &authorityclient.RateLimitError{RetryAfter: time.Second}, wantRetryAt: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout bytes.Buffer
			output, err := newPublishOutput("ndjson", "tnl dev", &stdout, io.Discard, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := output.failed(test.err); err != nil {
				t.Fatal(err)
			}
			var event publishEvent
			if err := json.NewDecoder(&stdout).Decode(&event); err != nil {
				t.Fatal(err)
			}
			if event.Retryable == nil || !*event.Retryable || (event.RetryAt != nil) != test.wantRetryAt {
				t.Fatalf("event = %#v", event)
			}
		})
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
	if starting.Type != "starting" || warning.Type != "warning" || warning.PublishRunNumber != 2 ||
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
	if starting.Type != "starting" || warning.Type != "warning" || warning.PublishRunNumber != 2 ||
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
		!strings.Contains(got, "transport") || !strings.Contains(got, "TLS/TCP fallback") {
		t.Fatalf("human output = %q", got)
	}
}

func TestPublishOutputNDJSONWarnsWhenBrowserCannotOpen(t *testing.T) {
	var stdout, stderr bytes.Buffer
	openCount := 0
	output, err := newPublishOutput("ndjson", "tnl publish", &stdout, &stderr, func(string) error {
		openCount++
		return errors.New("browser\x1b unavailable")
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
	if got := stderr.String(); !strings.HasPrefix(got, "+--[ tnl publish ]-- browser not opened ") ||
		!strings.Contains(got, `browser\x1b unavailable`) || strings.ContainsRune(got, '\x1b') {
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
		!strings.Contains(got, "+\n\n+--[ tnl dev ]-- browser not opened ") ||
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

func TestPublishOutputNDJSONFramesConnectionDisruption(t *testing.T) {
	var stderr bytes.Buffer
	output, err := newPublishOutput("ndjson", "tnl dev", io.Discard, &stderr, nil)
	if err != nil {
		t.Fatal(err)
	}
	output.logf("connection %s", "lost\x1b")
	got := stderr.String()
	if !strings.HasPrefix(got, "+--[ tnl dev ]-- publisher connection disrupted ") ||
		!strings.Contains(got, `connection lost\x1b`) || strings.ContainsRune(got, '\x1b') {
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
	if strings.Count(got, "]-- provisioning ") != 2 || strings.Count(got, "]-- ip address not allowed ") != 2 ||
		!strings.Contains(got, "certificate and publisher connections") ||
		!strings.Contains(got, "newly blocked") || !strings.Contains(got, "total blocked") ||
		!strings.Contains(got, "TNL_IP_POLICY_DENIED") || !strings.Contains(got, "https://tnl.dev/e/ip-policy-denied") ||
		strings.Contains(got, "192.0.2") || strings.ContainsRune(got, '\x1b') {
		t.Fatalf("human lifecycle output = %q", got)
	}
}

func TestPublishOutputWarnsWhenRunningLocalServiceFails(t *testing.T) {
	var stderr bytes.Buffer
	output, err := newPublishOutput("human", "tnl dev", io.Discard, &stderr, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := output.targetUnavailable(); err != nil {
		t.Fatal(err)
	}
	text := stderr.String()
	if !strings.Contains(text, "local service unavailable") || !strings.Contains(text, "TNL_TARGET_UNAVAILABLE") ||
		!strings.Contains(text, "https://tnl.dev/e/target") || strings.Contains(text, "localproxy:") {
		t.Fatalf("target warning = %q", text)
	}
}

func TestPublishNDJSONWireKeysAndOmissions(t *testing.T) {
	var stdout, stderr bytes.Buffer
	output, err := newPublishOutput("ndjson", "tnl publish", &stdout, &stderr, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := output.starting("tunnel_0123456789abcdef0123456789abcdef", "http://127.0.0.1:3000"); err != nil {
		t.Fatal(err)
	}
	if err := output.ready("https://demo.example", 7); err != nil {
		t.Fatal(err)
	}
	if err := output.failed(diagnostic.Wrap(diagnostic.TargetUnavailable, errors.New("connection refused"))); err != nil {
		t.Fatal(err)
	}
	if err := output.stopped(); err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(&stdout)
	for index, fields := range []map[string]any{
		{"type": "starting", "target": "http://127.0.0.1:3000"},
		{"type": "ready", "url": "https://demo.example", "publish_run_number": float64(7)},
		{"type": "error", "message": diagnostic.Summary(diagnostic.TargetUnavailable), "retryable": false, "code": string(diagnostic.TargetUnavailable), "help_url": diagnostic.HelpURL(diagnostic.TargetUnavailable)},
		{"type": "stopped", "reason": "canceled"},
	} {
		var wire map[string]any
		if err := decoder.Decode(&wire); err != nil {
			t.Fatal(err)
		}
		fields["schema_version"] = float64(1)
		fields["cursor"] = float64(index + 1)
		fields["tunnel_id"] = "tunnel_0123456789abcdef0123456789abcdef"
		if !reflect.DeepEqual(wire, fields) {
			t.Fatalf("event %d = %#v, want %#v", index, wire, fields)
		}
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		t.Fatalf("trailing output = %v, %v", extra, err)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestBoundedOutputError(t *testing.T) {
	message := boundedOutputError(errors.New(strings.Repeat("x", 2048)))
	if len(message) != 1024 {
		t.Fatalf("message length = %d", len(message))
	}
}

type errorWriter struct{ err error }

func (w errorWriter) Write([]byte) (int, error) { return 0, w.err }
