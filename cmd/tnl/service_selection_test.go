package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/failure"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestInventoryAddressSelectsExactEndpoint(t *testing.T) {
	const db = "svc_0123456789abcdefghijkl"
	const app = "svc_abcdefghijkl0123456789"
	items := []controlv1.ServiceSummary{
		{Id: db, Name: "orders", Protocol: "postgres", Endpoint: &controlv1.ServiceEndpoint{Hostname: "shared.example.test", Port: 15432}},
		{Id: app, Name: "web", Protocol: "http", Endpoint: &controlv1.ServiceEndpoint{Hostname: "shared.example.test", Port: 443}},
	}
	for _, tc := range []struct{ input, want string }{
		{"postgresql://SHARED.EXAMPLE.test:15432/", db},
		{"shared.example.test:15432", db},
		{"https://Shared.example.test:443/", app},
		{app, app},
		{"orders", db},
		{"postgres://shared.example.test", ""},
		{"postgres://shared.example.test:443", ""},
		{"shared.example.test:15433", ""},
	} {
		input, err := parseWholeService(tc.input, failure.InvalidCommand)
		if err != nil {
			t.Fatal(err)
		}
		item, err := matchInventory(input, items, failure.InvalidCommand)
		if tc.want == "" && !errors.Is(err, clientcontrol.ErrNotFound) || tc.want != "" && (item.Id != tc.want || err != nil) {
			t.Errorf("%q: got %q %v, want %q", tc.input, item.Id, err, tc.want)
		}
	}
	input, err := parseWholeService("shared.example.test", failure.InvalidCommand)
	if err != nil {
		t.Fatal(err)
	}
	_, err = matchInventory(input, items, failure.InvalidCommand)
	msg := commandDiagnosticFor(err).Message
	if err == nil || !strings.Contains(msg, db) || !strings.Contains(msg, app) {
		t.Fatalf("ambiguous hostname lacks choices: %q", msg)
	}
}

func TestDeleteRejectsResourceURLBeforeOpeningState(t *testing.T) {
	root := filepath.Join(t.TempDir(), "never-opened")
	var out, diag bytes.Buffer
	err := run(t.Context(), []string{"--no-config", "url", "delete", "--state-dir", root, "https://API.example.test:443/billing?secret=hidden"}, &out, &diag)
	if err == nil || out.Len() != 0 {
		t.Fatalf("err=%v, stdout=%q", err, &out)
	}
	d := commandDiagnosticFor(err)
	encoded, jsonErr := json.Marshal(d)
	if jsonErr != nil || !strings.Contains(d.Message, "https://api.example.test:443") || strings.Contains(string(encoded), "hidden") {
		t.Fatalf("unsafe or unhelpful diagnostic: %s", encoded)
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("an invalid service selector reached local state: %v", err)
	}
}
