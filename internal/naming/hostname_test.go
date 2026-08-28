package naming

import (
	"encoding/json"
	"os"
	"testing"
)

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
