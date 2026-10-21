package controlstate

import (
	"bytes"
	"encoding/json"
	"testing"
)

// compare every stored response field, including timestamp precision, without
// comparing time.Time's process-local location pointers after JSON replay.
func sameStoredResponse(t *testing.T, got, want any) bool {
	t.Helper()
	actual, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Equal(actual, expected)
}
