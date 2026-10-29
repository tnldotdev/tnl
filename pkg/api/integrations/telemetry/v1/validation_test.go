package telemetryv1

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func TestTelemetryContractRejectsPrivateContextAndCrossPathMeasurements(t *testing.T) {
	fixture, err := os.ReadFile("../../../../../api/fixtures/telemetry/v1/batch.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateBatch(fixture); err != nil {
		t.Fatal("canonical v1 fixture rejected", err)
	}
	var batch Batch
	if err := json.Unmarshal(fixture, &batch); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(batch)
	if err != nil || ValidateBatch(encoded) != nil {
		t.Fatal("generated native models changed the v1 fixture", err)
	}
	for name, field := range map[string]string{
		"invocation": `"invocation_id":"ivk_AAAAAAAAAAAAAAAAAAAAAA",`,
		"timestamp":  `"occurred_at":"2026-10-26T12:00:00Z",`,
		"account":    `"account_id":"private",`,
		"service":    `"service_id":"private",`,
		"run":        `"run_id":"private",`,
		"hostname":   `"hostname":"private.example",`,
		"source":     `"source_ip":"192.0.2.1",`,
		"candidate":  `"candidate":"private",`,
		"target":     `"target":"private",`,
		"error":      `"raw_error":"private",`,
		"diagnostic": `"diagnostic_code":"TNL_AUTHENTICATION_REQUIRED",`,
	} {
		t.Run(name, func(t *testing.T) {
			invalid := bytes.Replace(fixture, []byte(`"event_version": 1,`), []byte(`"event_version": 1,`+field), 1)
			if err := ValidateBatch(invalid); !errors.Is(err, ErrInvalid) {
				t.Fatal("private event context was accepted", err)
			}
		})
	}
	for name, mutation := range map[string][2]string{
		"public_ice_attempts":   {`"kind": "public_ingress",`, `"kind": "public_ingress", "direct_setup_attempts": 1,`},
		"public_native_path":    {`"path": "public_udp"`, `"path": "native_direct"`},
		"native_public_path":    {`"path": "native_direct"`, `"path": "public_udp"`},
		"unbounded_count":       {`"count": 1`, `"count": 1000000001`},
		"negative_attempts":     {`"direct_setup_attempts": 2`, `"direct_setup_attempts": -1`},
		"unknown_reason":        {`"reason": "udp_blocked"`, `"reason": "private-error-message"`},
		"version_bump":          {`"schema_version": 1`, `"schema_version": 2`},
		"excess_success":        {`"direct_setup_successes": 1`, `"direct_setup_successes": 3`},
		"duplicate_path":        {`"path": "public_tcp"`, `"path": "public_udp"`},
		"duplicate_fallback":    {`"reason": "udp_blocked", "count": 1`, `"reason": "udp_blocked", "count": 1 }, { "reason": "udp_blocked", "count": 1`},
		"missing_attempts":      {`"direct_setup_attempts": 2,`, ``},
		"missing_failure_stage": {`"failure_stage": "authentication"`, `"action": "start"`},
		"excess_histogram":      {`"direct_establishment": [0, 0, 0, 0, 1,`, `"direct_establishment": [0, 0, 0, 0, 2,`},
	} {
		t.Run(name, func(t *testing.T) {
			invalid := bytes.Replace(fixture, []byte(mutation[0]), []byte(mutation[1]), 1)
			if bytes.Equal(invalid, fixture) {
				t.Fatal("invalid fixture mutation did not apply")
			}
			if err := ValidateBatch(invalid); !errors.Is(err, ErrInvalid) {
				t.Fatal("invalid report accepted", err)
			}
		})
	}
	duplicate := bytes.Replace(fixture, []byte(`"event_id": "tev_BBBBBBBBBBBBBBBBBBBBBB"`), []byte(`"event_id": "tev_AAAAAAAAAAAAAAAAAAAAAA"`), 1)
	if err := ValidateBatch(duplicate); !errors.Is(err, ErrInvalid) {
		t.Fatal("batch reused one event ID", err)
	}
}

func TestTelemetryValidatorFailsClosedOnNewSchemaKeywords(t *testing.T) {
	for _, document := range []string{
		`{"type":"string","minLength":2,"const":"secret"}`,
		`{"type":"array","items":{"type":"integer","exclusiveMinimum":0}}`,
		`{"type":"integer","format":"new-format"}`,
	} {
		if err := checkVocabulary(json.RawMessage(document)); !errors.Is(err, ErrInvalid) {
			t.Fatalf("new validation keyword was ignored: %s %v", document, err)
		}
	}
}
