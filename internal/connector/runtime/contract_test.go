package runtime

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestConnectionTransportIdentityIsRequired(t *testing.T) {
	for _, test := range []struct {
		name  string
		value any
	}{
		{"missing", nil},
		{"empty", ""},
		{"wrong type", 1},
		{"short", "ctg_" + strings.Repeat("a", 21)},
		{"long", "ctg_" + strings.Repeat("a", 23)},
		{"wrong prefix", "old_" + strings.Repeat("a", 22)},
		{"punctuation", "ctg_" + strings.Repeat("a", 21) + "_"},
		{"non-ascii", "ctg_" + strings.Repeat("a", 21) + "é"},
		{"trailing newline", "ctg_" + strings.Repeat("a", 22) + "\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := map[string]any{"schema": Schema, "expires_at": time.Now().Add(time.Hour)}
			if test.name != "missing" {
				value["transport_id"] = test.value
			}
			data, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			var connection Connection
			err = ReadJSON(bytes.NewReader(data), &connection)
			if err == nil {
				err = connection.Validate()
			}
			if !errors.Is(err, ErrInvalid) {
				t.Fatal("invalid transport identity was accepted", err)
			}
			if err := (Prepared{Schema: Schema, Connection: connection}).Validate(); !errors.Is(err, ErrInvalid) {
				t.Fatal("prepared snapshot accepted an invalid transport identity", err)
			}
		})
	}
	connection := Connection{Schema: Schema, ExpiresAt: time.Now().Add(time.Hour), TransportID: "ctg_0123456789ABCDEFGHIJaz"}
	if err := (Prepared{Schema: Schema, Connection: connection}).Validate(); err != nil {
		t.Fatal("valid transport identity was rejected", err)
	}
	data, err := json.Marshal(Connection{})
	if err != nil || !bytes.Contains(data, []byte(`"transport_id":""`)) {
		t.Fatal("native output omitted the required transport field", err)
	}
}
