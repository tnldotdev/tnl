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
		{name: "authorization envelope", path: "../../../api/fixtures/authority/v1/authorization-envelope.json", model: &AuthorizationEnvelope{}},
		{name: "token exchange request", path: "../../../api/fixtures/authority/v1/token-exchange-request.json", model: &LoginTokenExchangeRequest{}},
		{name: "token exchange response", path: "../../../api/fixtures/authority/v1/token-exchange-response.json", model: &ControlSessionResponse{}},
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
