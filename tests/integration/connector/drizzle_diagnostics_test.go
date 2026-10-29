package connector_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

type drizzleReport struct {
	Code        string `json:"code"`
	Stage       string `json:"stage"`
	Elapsed     *int64 `json:"elapsed_ms"`
	CauseStatus string `json:"cause_status"`
	ErrorCode   string `json:"error_code,omitempty"`
	ExitCode    *int   `json:"exit_code,omitempty"`
	Errno       *int   `json:"errno,omitempty"`
	Signal      string `json:"signal,omitempty"`
	Killed      *bool  `json:"killed,omitempty"`
}

// the fixture owns a flat, bounded report, not a node error or its child output.
// reject incomplete/unknown records rather than printing any raw bytes.
func drizzleFixtureFailure(output []byte) string {
	unknown := drizzleReport{Code: "fixture.installed_drizzle_failed", Stage: "unknown", CauseStatus: "unknown"}
	encode := func(report drizzleReport) string { data, _ := json.Marshal(report); return string(data) }
	if len(output) > 1024 {
		unknown.CauseStatus = "truncated"
		return encode(unknown)
	}
	lines := bytes.SplitN(bytes.TrimSpace(output), []byte("\n"), 3)
	if len(lines) == 1 {
		return encode(parseDrizzleFixtureReport(lines[0]))
	}
	if len(lines) != 2 {
		return encode(unknown)
	}
	primary, cleanup := parseDrizzleFixtureReport(lines[0]), parseDrizzleFixtureReport(lines[1])
	if primary.Stage == "unknown" || primary.Stage == "consumer cleanup" || cleanup.Stage != "consumer cleanup" {
		return encode(unknown)
	}
	return encode(primary) + "\n" + encode(cleanup)
}

func parseDrizzleFixtureReport(line []byte) drizzleReport {
	unknown := drizzleReport{Code: "fixture.installed_drizzle_failed", Stage: "unknown", CauseStatus: "unknown"}
	prefix := []byte("tnl-drizzle-fixture ")
	if !bytes.HasPrefix(line, prefix) {
		return unknown
	}
	data := bytes.TrimPrefix(line, prefix)
	fields, ok := flatDrizzleReport(data)
	if !ok {
		return unknown
	}
	var keys map[string]json.RawMessage
	if json.Unmarshal(data, &keys) != nil || len(keys) != fields {
		return unknown
	}
	for _, key := range []string{"code", "stage", "elapsed_ms", "cause_status"} {
		if _, present := keys[key]; !present {
			return unknown
		}
	}
	for key, value := range keys {
		// encoding/json accepts case-insensitive names; this record does not.
		switch key {
		case "code", "stage", "elapsed_ms", "cause_status", "error_code", "exit_code", "errno", "signal", "killed":
		default:
			return unknown
		}
		if key != "elapsed_ms" && bytes.Equal(value, []byte("null")) {
			return unknown
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var report drizzleReport
	if decoder.Decode(&report) != nil || !validDrizzleReport(report) {
		return unknown
	}
	return report
}

// reject arrays/nesting and more than nine fields before decoding any JSON.
func flatDrizzleReport(data []byte) (int, bool) {
	if len(data) < 2 || data[0] != '{' || data[len(data)-1] != '}' {
		return 0, false
	}
	quoted, escaped, fields := false, false, 0
	for _, character := range data[1 : len(data)-1] {
		if quoted {
			if escaped {
				escaped = false
			} else if character == '\\' {
				escaped = true
			} else if character == '"' {
				quoted = false
			}
			continue
		}
		switch character {
		case '"':
			quoted = true
		case '{', '}', '[', ']':
			return 0, false
		case ':':
			fields++
			if fields > 9 {
				return 0, false
			}
		}
	}
	return fields, !quoted
}

func validDrizzleReport(report drizzleReport) bool {
	allowed := func(value string, choices ...string) bool {
		for _, choice := range choices {
			if value == choice {
				return true
			}
		}
		return false
	}
	return report.Code == "fixture.installed_drizzle_failed" &&
		allowed(report.Stage, "fixture preparation", "native packaging", "sdk packaging", "dependency installation", "filesystem preparation", "installed settings verifier", "drizzle migration", "post-migration preparation", "post-migration query", "database drivers", "native runtime", "consumer cleanup") &&
		allowed(report.CauseStatus, "reported", "unknown", "truncated") &&
		(report.Elapsed == nil || *report.Elapsed >= 0 && *report.Elapsed <= 9007199254740991) &&
		(report.ExitCode == nil || *report.ExitCode >= 0 && *report.ExitCode <= 255) &&
		(report.Errno == nil || *report.Errno >= -4095 && *report.Errno <= 0) &&
		allowed(report.Signal, "", "SIGABRT", "SIGHUP", "SIGINT", "SIGKILL", "SIGPIPE", "SIGQUIT", "SIGSEGV", "SIGTERM") &&
		allowed(report.ErrorCode, "", "sdk.authentication_required", "sdk.configuration_invalid", "sdk.connection_unavailable", "sdk.connection_unprepared", "sdk.native_invalid", "sdk.native_missing", "sdk.native_unsupported", "sdk.response_invalid", "ERR_ASSERTION", "08001", "08006", "23505", "28P01", "3D000", "42501", "42601", "42710", "42P01", "53300", "57P01") &&
		(report.CauseStatus != "reported" || report.ErrorCode != "")
}

func TestDrizzleFixtureFailureReporting(t *testing.T) {
	const valid = `{"code":"fixture.installed_drizzle_failed","stage":"installed settings verifier","elapsed_ms":7,"cause_status":"reported","error_code":"sdk.response_invalid","exit_code":1,"errno":-2,"signal":"SIGTERM","killed":true}`
	const prefix = "tnl-drizzle-fixture "
	if got := drizzleFixtureFailure([]byte(prefix + valid + "\n")); got != valid {
		t.Fatalf("safe report changed: %s", got)
	}
	const secret = "synthetic-private-value"
	cases := map[string]string{
		"raw error":         "Error: " + secret,
		"message":           strings.TrimSuffix(valid, "}") + `,"message":"` + secret + `"}`,
		"stack":             strings.TrimSuffix(valid, "}") + `,"stack":"` + secret + `"}`,
		"stdout":            strings.TrimSuffix(valid, "}") + `,"stdout":"` + secret + `"}`,
		"stderr":            strings.TrimSuffix(valid, "}") + `,"stderr":"` + secret + `"}`,
		"args":              strings.TrimSuffix(valid, "}") + `,"args":["` + secret + `"]}`,
		"env":               strings.TrimSuffix(valid, "}") + `,"env":{"key":"` + secret + `"}}`,
		"cause":             strings.TrimSuffix(valid, "}") + `,"cause":{"message":"` + secret + `"}}`,
		"unknown field":     strings.TrimSuffix(valid, "}") + `,"future":"` + secret + `"}`,
		"invalid code":      strings.Replace(valid, "sdk.response_invalid", secret, 1),
		"invalid stage":     strings.Replace(valid, "installed settings verifier", secret, 1),
		"invalid signal":    strings.Replace(valid, "SIGTERM", secret, 1),
		"invalid exit":      strings.Replace(valid, `"exit_code":1`, `"exit_code":1.5`, 1),
		"invalid elapsed":   strings.Replace(valid, `"elapsed_ms":7`, `"elapsed_ms":-1`, 1),
		"missing elapsed":   strings.Replace(valid, `"elapsed_ms":7,`, "", 1),
		"missing stage":     strings.Replace(valid, `"stage":"installed settings verifier",`, "", 1),
		"null code":         strings.Replace(valid, `"error_code":"sdk.response_invalid"`, `"error_code":null`, 1),
		"invalid status":    strings.Replace(valid, "reported", secret, 1),
		"duplicate":         strings.Replace(valid, `"code":`, `"code":"`+secret+`","code":`, 1),
		"extra output":      valid + "\n" + secret,
		"multiple records":  valid + "\n" + prefix + valid,
		"malformed":         `{`,
		"deep before parse": `{"cause":` + strings.Repeat("[", 200) + `"` + secret + `"` + strings.Repeat("]", 200) + `}`,
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			got := drizzleFixtureFailure([]byte(prefix + input))
			if strings.Contains(got, secret) || !strings.Contains(got, `"cause_status":"unknown"`) || !strings.Contains(got, `"stage":"unknown"`) {
				t.Fatalf("unsafe or invented report: %s", got)
			}
		})
	}
	got := drizzleFixtureFailure([]byte(strings.Repeat(secret, 200)))
	if strings.Contains(got, secret) || !strings.Contains(got, `"cause_status":"truncated"`) {
		t.Fatalf("oversized output was not explicitly unknown: %s", got)
	}
}

func TestDrizzleFixtureFailureWithCleanup(t *testing.T) {
	const prefix = "tnl-drizzle-fixture "
	const primary = `{"code":"fixture.installed_drizzle_failed","stage":"drizzle migration","elapsed_ms":7,"cause_status":"reported","error_code":"sdk.response_invalid"}`
	const cleanup = `{"code":"fixture.installed_drizzle_failed","stage":"consumer cleanup","elapsed_ms":1,"cause_status":"unknown","errno":-13}`
	if got := drizzleFixtureFailure([]byte(prefix + primary + "\n" + prefix + cleanup + "\n")); got != primary+"\n"+cleanup {
		t.Fatal("verification and cleanup must retain both safe reports in order")
	}
	if got := drizzleFixtureFailure([]byte(prefix + cleanup + "\n")); got != cleanup {
		t.Fatal("cleanup failure after successful verification must retain its report")
	}
	const secret = "synthetic-private-cleanup"
	for name, output := range map[string]string{
		"reversed":           prefix + cleanup + "\n" + prefix + primary,
		"duplicate cleanup":  prefix + cleanup + "\n" + prefix + cleanup,
		"third record":       prefix + primary + "\n" + prefix + cleanup + "\n" + prefix + cleanup,
		"raw cleanup":        prefix + primary + "\n" + secret,
		"raw primary":        secret + "\n" + prefix + cleanup,
		"extra cleanup data": prefix + primary + "\n" + prefix + strings.TrimSuffix(cleanup, "}") + `,"cause":"` + secret + `"}`,
		"cleanup alias":      prefix + primary + "\n" + prefix + strings.Replace(cleanup, `"errno":`, `"Errno":`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			const unknown = `{"code":"fixture.installed_drizzle_failed","stage":"unknown","elapsed_ms":null,"cause_status":"unknown"}`
			if got := drizzleFixtureFailure([]byte(output)); got != unknown {
				t.Fatal("invalid cleanup evidence must yield only the authored unknown report")
			}
		})
	}
}
