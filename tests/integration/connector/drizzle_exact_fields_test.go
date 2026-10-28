package connector_test

import (
	"strings"
	"testing"
)

func TestReviewDrizzleExactKeys(t *testing.T) {
	const base = `{"code":"fixture.installed_drizzle_failed","stage":"installed settings verifier","elapsed_ms":7,"cause_status":"unknown"`
	for _, suffix := range []string{
		`,"STAGE":"drizzle migration"}`,
		`,"ERROR_CODE":"sdk.response_invalid","CAUSE_STATUS":"reported"}`,
	} {
		t.Run(suffix, func(t *testing.T) {
			got := drizzleFixtureFailure([]byte("tnl-drizzle-fixture " + base + suffix))
			t.Logf("actual: %s", got)
			if !strings.Contains(got, `"stage":"unknown"`) || !strings.Contains(got, `"cause_status":"unknown"`) {
				t.Error("case-variant unknown keys must be rejected, not decoded as known fields")
			}
		})
	}
}

func TestDrizzleFixtureExactFieldNames(t *testing.T) {
	const prefix = "tnl-drizzle-fixture "
	const minimum = `{"code":"fixture.installed_drizzle_failed","stage":"installed settings verifier","elapsed_ms":7,"cause_status":"unknown"}`
	const unknown = `{"code":"fixture.installed_drizzle_failed","stage":"unknown","elapsed_ms":null,"cause_status":"unknown"}`
	assertUnknown := func(t *testing.T, record string) {
		t.Helper()
		if got := drizzleFixtureFailure([]byte(prefix + record)); got != unknown {
			t.Fatal("invalid field names must yield only the authored unknown report")
		}
	}

	t.Run("normal minimum", func(t *testing.T) {
		if got := drizzleFixtureFailure([]byte(prefix + minimum)); got != minimum {
			t.Fatal("valid lowercase report changed")
		}
	})
	t.Run("escaped exact lowercase", func(t *testing.T) {
		record := strings.Replace(minimum, `"stage":`, `"\u0073tage":`, 1)
		if got := drizzleFixtureFailure([]byte(prefix + record)); got != minimum {
			t.Fatal("decoded exact lowercase key changed")
		}
	})

	fields := []struct {
		wire, upper, mixed, goField, escaped, value string
	}{
		{"code", "CODE", "cOdE", "Code", `\u0043ODE`, `"fixture.installed_drizzle_failed"`},
		{"stage", "STAGE", "sTaGe", "Stage", `\u0053TAGE`, `"installed settings verifier"`},
		{"elapsed_ms", "ELAPSED_MS", "eLaPsEd_mS", "Elapsed", `\u0045LAPSED_MS`, `7`},
		{"cause_status", "CAUSE_STATUS", "cAuSe_sTaTuS", "CauseStatus", `\u0043AUSE_STATUS`, `"unknown"`},
		{"error_code", "ERROR_CODE", "eRrOr_cOdE", "ErrorCode", `\u0045RROR_CODE`, `"sdk.response_invalid"`},
		{"exit_code", "EXIT_CODE", "eXiT_cOdE", "ExitCode", `\u0045XIT_CODE`, `1`},
		{"errno", "ERRNO", "eRrNo", "Errno", `\u0045RRNO`, `-2`},
		{"signal", "SIGNAL", "sIgNaL", "Signal", `\u0053IGNAL`, `"SIGTERM"`},
		{"killed", "KILLED", "kIlLeD", "Killed", `\u004bILLED`, `true`},
	}
	for _, field := range fields {
		t.Run(field.wire, func(t *testing.T) {
			canonical := minimum
			if !strings.Contains(canonical, `"`+field.wire+`":`) {
				canonical = strings.TrimSuffix(canonical, "}") + `,"` + field.wire + `":` + field.value + `}`
			}
			aliases := []struct{ name, key string }{
				{"uppercase", field.upper},
				{"mixedcase", field.mixed},
				{"go field", field.goField},
				{"escaped case", field.escaped},
			}
			for _, alias := range aliases {
				t.Run(alias.name, func(t *testing.T) {
					entry := `"` + alias.key + `":` + field.value
					t.Run("variant only", func(t *testing.T) {
						assertUnknown(t, strings.Replace(canonical, `"`+field.wire+`":`, `"`+alias.key+`":`, 1))
					})
					t.Run("lower then alias", func(t *testing.T) {
						assertUnknown(t, strings.TrimSuffix(canonical, "}")+`,`+entry+`}`)
					})
					t.Run("alias then lower", func(t *testing.T) {
						assertUnknown(t, `{`+entry+`,`+canonical[1:])
					})
				})
			}
		})
	}

	const secret = "synthetic-private-exact-fields https://user:password@example.test PRIVATE KEY /private/handle"
	for name, suffix := range map[string]string{
		"trailing underscore": `,"stage_":"drizzle migration"}`,
		"trailing space":      `,"stage ":"drizzle migration"}`,
		"nul suffix":          `,"stage\u0000":"drizzle migration"}`,
		"zero width suffix":   `,"stage\u200b":"drizzle migration"}`,
		"cyrillic lookalike":  `,"st\u0430ge":"drizzle migration"}`,
		"long s lookalike":    `,"\u017Ftage":"drizzle migration"}`,
		"kelvin k lookalike":  `,"\u212Ailled":true}`,
		"escaped duplicate":   `,"\u0073tage":"drizzle migration"}`,
		"secret alias value":  `,"STAGE":"` + secret + `"}`,
		"secret unknown key":  `,"` + secret + `":"drizzle migration"}`,
		"secret nested cause": `,"cause":{"message":"` + secret + `"}}`,
		"getter shaped field": `,"stage":{"get":"` + secret + `"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			assertUnknown(t, strings.TrimSuffix(minimum, "}")+suffix)
		})
	}
}
