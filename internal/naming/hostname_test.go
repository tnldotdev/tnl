package naming

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestErrorCodeOfWrappedValidationError(t *testing.T) {
	code, ok := ErrorCodeOf(fmt.Errorf("canonicalize hostname: %w", invalid(ErrorInvalidSyntax)))
	if !ok || code != ErrorInvalidSyntax {
		t.Fatalf("wrapped validation error = %q, %v", code, ok)
	}
}

type conformanceFixture struct {
	Version int               `json:"version"`
	Cases   []conformanceCase `json:"cases"`
}

type conformanceCase struct {
	Name      string `json:"name"`
	Context   string `json:"context"`
	Input     string `json:"input"`
	Canonical string `json:"canonical"`
	Error     string `json:"error"`
}

func TestHostnameConformance(t *testing.T) {
	contents, err := os.ReadFile("../../api/fixtures/hostname/v1.json")
	if err != nil {
		t.Fatal(err)
	}

	var fixture conformanceFixture
	if err := json.Unmarshal(contents, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Version != 1 {
		t.Fatalf("unsupported fixture version %d", fixture.Version)
	}

	names := make(map[string]struct{}, len(fixture.Cases))
	for _, testCase := range fixture.Cases {
		t.Run(testCase.Name, func(t *testing.T) {
			if _, exists := names[testCase.Name]; exists {
				t.Fatalf("duplicate case name %q", testCase.Name)
			}
			names[testCase.Name] = struct{}{}

			var actual string
			var err error
			switch testCase.Context {
			case "hostname":
				actual, err = CanonicalizeHostname(testCase.Input)
			case "authority":
				actual, err = CanonicalizeAuthority(testCase.Input)
			default:
				t.Fatalf("unknown context %q", testCase.Context)
			}

			if testCase.Error == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if actual != testCase.Canonical {
					t.Fatalf("got %q, want %q", actual, testCase.Canonical)
				}
				return
			}

			code, ok := ErrorCodeOf(err)
			if !ok {
				t.Fatalf("got error %v, want %s", err, testCase.Error)
			}
			if string(code) != testCase.Error {
				t.Fatalf("got error %s, want %s", code, testCase.Error)
			}
		})
	}
}

func FuzzCanonicalize(f *testing.F) {
	contents, err := os.ReadFile("../../api/fixtures/hostname/v1.json")
	if err != nil {
		f.Fatal(err)
	}
	var fixture conformanceFixture
	if err := json.Unmarshal(contents, &fixture); err != nil {
		f.Fatal(err)
	}
	for _, testCase := range fixture.Cases {
		f.Add(testCase.Input)
	}

	f.Fuzz(func(t *testing.T, input string) {
		hostname, hostnameErr := CanonicalizeHostname(input)
		if hostnameErr != nil {
			if _, ok := ErrorCodeOf(hostnameErr); !ok {
				t.Fatalf("hostname returned an unclassified error: %v", hostnameErr)
			}
		} else {
			assertCanonicalHostname(t, hostname)
			authority, err := CanonicalizeAuthority(hostname + ":443")
			if err != nil || authority != hostname {
				t.Fatalf("canonical hostname failed authority conversion: %q, %v", authority, err)
			}
		}

		authority, authorityErr := CanonicalizeAuthority(input)
		if authorityErr != nil {
			if _, ok := ErrorCodeOf(authorityErr); !ok {
				t.Fatalf("authority returned an unclassified error: %v", authorityErr)
			}
			return
		}
		assertCanonicalHostname(t, authority)
		roundTrip, err := CanonicalizeAuthority(authority)
		if err != nil || roundTrip != authority {
			t.Fatalf("canonical authority is not idempotent: %q, %v", roundTrip, err)
		}
	})
}

func assertCanonicalHostname(t *testing.T, hostname string) {
	t.Helper()
	if hostname == "" || len(hostname) > MaxHostnameBytes || hostname != strings.ToLower(hostname) ||
		strings.HasSuffix(hostname, ".") {
		t.Fatalf("invalid canonical hostname %q", hostname)
	}
	for index := range len(hostname) {
		if hostname[index] > 0x7f {
			t.Fatalf("canonical hostname is not ASCII: %q", hostname)
		}
	}
	roundTrip, err := CanonicalizeHostname(hostname)
	if err != nil || roundTrip != hostname {
		t.Fatalf("canonical hostname is not idempotent: %q, %v", roundTrip, err)
	}
}
