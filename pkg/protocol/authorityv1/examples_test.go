package authorityv1

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestExamplesMatchGeneratedModels(t *testing.T) {
	tests := []struct {
		name  string
		path  string
		model any
	}{
		{name: "capabilities", path: "../../../api/fixtures/authorization-authority/v1/capabilities.json", model: &Capabilities{}},
		{name: "hostname", path: "../../../api/fixtures/authorization-authority/v1/hostname.json", model: &Hostname{}},
		{name: "domain verification", path: "../../../api/fixtures/authorization-authority/v1/domain-verification.json", model: &DomainVerification{}},
		{name: "authorization envelope", path: "../../../api/fixtures/authorization-authority/v1/authorization-envelope.json", model: &AuthorizationEnvelope{}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			expected, err := os.ReadFile(test.path)
			if err != nil {
				t.Fatal(err)
			}
			decoder := json.NewDecoder(bytes.NewReader(expected))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(test.model); err != nil {
				t.Fatal(err)
			}
			actual, err := json.Marshal(test.model)
			if err != nil {
				t.Fatal(err)
			}
			var left, right any
			if json.Unmarshal(expected, &left) != nil || json.Unmarshal(actual, &right) != nil || !reflect.DeepEqual(left, right) {
				t.Fatalf("generated model changed fixture: %s", actual)
			}
		})
	}
}
