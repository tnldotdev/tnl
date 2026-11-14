package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/tnldotdev/tnl/internal/failure"
)

func TestPortablePublisherCommandFlags(t *testing.T) {
	for _, tc := range []struct {
		args    []string
		command string
	}{
		{[]string{"publisher", "setup", "--namespace"}, "publisher setup"},
		{[]string{"publisher", "setup", "--url", "url_selected"}, "publisher setup"},
		{[]string{"publisher", "provision", "--namespace", "--output-file", "/tmp/publisher.json"}, "publisher provision"},
		{[]string{"publisher", "provision", "--url", "url_selected", "--output-file", "/tmp/publisher.json"}, "publisher provision"},
		{[]string{"publish", "3000", "--publisher-credential-file", "/tmp/publisher.json"}, "publish <service-or-target>"},
	} {
		var flags cli
		parser, err := kong.New(&flags, kong.Name("tnl"), kong.Writers(io.Discard, io.Discard))
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := parser.Parse(tc.args)
		if err != nil {
			t.Fatalf("%v: %v", tc.args, err)
		}
		if command := canonicalParsedCommand(parsed.Command()); command != tc.command {
			t.Fatalf("%v: command %s, want %s", tc.args, command, tc.command)
		}
		if tc.command == "publish <service-or-target>" && flags.Publish.PublisherCredentialFile != "/tmp/publisher.json" {
			t.Fatal("file flag was lost")
		}
	}
}

func TestPublisherProvisionRejectsServiceWithoutDeploymentBeforeState(t *testing.T) {
	for _, scope := range [][]string{
		nil, {"--namespace"}, {"--url", "url_selected"}, {"--service-id", "svc_selected"}, {"--domain", "example.test"},
	} {
		t.Run(strings.Join(scope, " "), func(t *testing.T) {
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests++
				w.WriteHeader(http.StatusInternalServerError)
			}))
			defer server.Close()
			root := t.TempDir()
			state, file := filepath.Join(root, "state"), filepath.Join(root, "publisher.json")
			args := []string{"--no-config", "publisher", "provision", "--service", "db", "--service", "api", "--output-file", file, "--state-dir", state, "--server", server.URL}
			args = append(args, scope...)
			var output, diagnostics bytes.Buffer
			err := run(t.Context(), args, &output, &diagnostics)
			if reason, ok := failure.ReasonOf(err); !ok || reason != failure.InvalidTunnelFlags || !strings.Contains(err.Error(), "--service requires --deployment") {
				t.Fatal("service selection reached standalone provisioning", err)
			}
			if requests != 0 || output.Len() != 0 || diagnostics.Len() != 0 {
				t.Fatal("invalid selection reached authentication or control")
			}
			for _, path := range []string{state, file} {
				if _, err := os.Lstat(path); !os.IsNotExist(err) {
					t.Fatal("invalid selection opened state or wrote a credential", err)
				}
			}
		})
	}
}
