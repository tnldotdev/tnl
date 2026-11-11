package telemetryv1

import (
	"encoding/json"
	"strings"
	"testing"
)

const validEvent = `{"event_id":"tev_0123456789abcdefghijkl","event_version":1,"name":"command.outcome","payload":{"command":"publish","outcome":"succeeded"}}`

func TestTelemetryStrictContract(t *testing.T) {
	if ValidateEvent([]byte(validEvent)) != nil {
		t.Fatal("valid event rejected")
	}
	for _, invalid := range []string{
		strings.Replace(validEvent, `"payload":`, `"invocation_id":"ivk_0123456789abcdefghijkl","payload":`, 1),
		strings.Replace(validEvent, `"payload":`, `"occurred_at":"2026-01-01T00:00:00Z","payload":`, 1),
		strings.Replace(validEvent, `"command":"publish"`, `"command":"publish","target":"https://secret"`, 1),
		strings.Replace(validEvent, `"publish"`, `"secret-project"`, 1),
		strings.Replace(validEvent, `"succeeded"`, `"secret-error"`, 1),
		strings.Replace(validEvent, `"event_version":1`, `"event_version":2`, 1),
		strings.Replace(validEvent, `"command.outcome"`, `"command.started"`, 1),
		strings.Replace(validEvent, `"command.outcome"`, `"tunnel.ready"`, 1),
		`null`, `{}`, strings.Repeat(" ", MaximumEventBytes) + validEvent,
	} {
		if ValidateEvent([]byte(invalid)) == nil {
			t.Fatalf("accepted %s", invalid)
		}
	}
}

func TestTelemetryBatchBoundsAndDuplicateIDs(t *testing.T) {
	prefix := `{"schema_version":1,"installation_id":"inst_0123456789abcdefghijkl","client":{"version":"test","os":"darwin","arch":"arm64","ci":false},"events":[`
	if ValidateBatch([]byte(prefix+validEvent+`]:0}`)) == nil {
		t.Fatal("invalid JSON accepted")
	}
	if err := ValidateBatch([]byte(prefix + validEvent + `]} `)); err != nil {
		t.Fatal(err)
	}
	if ValidateBatch([]byte(prefix+validEvent+`,`+validEvent+`]} `)) == nil {
		t.Fatal("duplicate IDs accepted")
	}
	if ValidateBatch([]byte(prefix+`]} `)) == nil {
		t.Fatal("empty batch accepted")
	}
	for _, field := range []string{`"path":"secret",`, `"ip":"192.0.2.1",`, `"token":"secret",`} {
		if ValidateBatch([]byte(strings.Replace(prefix+validEvent+`]}`, `"ci":false`, field+`"ci":false`, 1))) == nil {
			t.Fatal("private metadata accepted")
		}
	}
}

func TestTelemetryTransportBounds(t *testing.T) {
	payload := TransportReport{Role: "connector"}
	for _, op := range []Operation{RelayConnect, DirectConnect, Fallback, Recovery} {
		for _, path := range []Path{Quic, TlsTcp, DirectUdp} {
			for _, outcome := range []Outcome{Succeeded, Failed, Canceled} {
				for _, duration := range []Duration{Lt1s, Lt10s, Lt1m, Longer} {
					payload.Measurements = append(payload.Measurements, Measurement{Operation: op, Path: path, Outcome: outcome, Duration: duration, Count: 1_000_000_000})
				}
			}
		}
	}
	var event Event
	_ = event.FromTransportEvent(TransportEvent{EventId: "tev_0123456789abcdefghijkl", EventVersion: 1, Name: "transport.report", Payload: payload})
	data, _ := json.Marshal(event)
	if err := ValidateEvent(data); err != nil {
		t.Fatalf("maximum report rejected (%d bytes): %v", len(data), err)
	}
	payload.Measurements[0].Count++
	_ = event.FromTransportEvent(TransportEvent{EventId: "tev_0123456789abcdefghijkl", EventVersion: 1, Name: "transport.report", Payload: payload})
	data, _ = json.Marshal(event)
	if ValidateEvent(data) == nil {
		t.Fatal("unbounded counter accepted")
	}
}
