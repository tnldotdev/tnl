// Package relayslots declares the exact processes authorized by a test topology.
package relayslots

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const Forwarding = "test-private-forwarding-credential-0123456789"

func Token(id string) string { return "test-private-relay-slot-credential-" + id }

type Slot struct {
	Service    string `json:"service_id"`
	ID         string `json:"relay_id"`
	Hostname   string `json:"hostname"`
	Public     string `json:"relay_address"`
	Internal   string `json:"internal_address"`
	Credential string `json:"credential"`
}

func New(service, id, hostname, public, internal string) Slot {
	return Slot{service, id, hostname, public, internal, Token(id)}
}

func Data(t *testing.T, slots ...Slot) []byte {
	t.Helper()
	b, err := json.Marshal(slots)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func File(t *testing.T, slots ...Slot) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "relay-slots.json")
	if err := os.WriteFile(path, Data(t, slots...), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
