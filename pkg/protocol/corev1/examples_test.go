package corev1

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
		{name: "capabilities", path: "../../../api/fixtures/core/v1/capabilities.json", model: &Capabilities{}},
		{name: "problem", path: "../../../api/fixtures/core/v1/problem.json", model: &Problem{}},
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
			if !equalJSON(expected, actual) {
				t.Fatalf("generated model changed fixture: %s", actual)
			}
		})
	}
}

func equalJSON(left, right []byte) bool {
	var leftValue, rightValue any
	if json.Unmarshal(left, &leftValue) != nil || json.Unmarshal(right, &rightValue) != nil {
		return false
	}
	return reflect.DeepEqual(leftValue, rightValue)
}
