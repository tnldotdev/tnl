package main

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/tnldotdev/tnl/internal/publisherjob"
)

func TestSystemServiceCommandWiring(t *testing.T) {
	for _, command := range []string{"install", "start", "stop", "list", "serve"} {
		t.Run(command, func(t *testing.T) {
			var root struct {
				Service serviceCommand `cmd:""`
			}
			parser, err := kong.New(&root, kong.Name("tnl"), kong.Writers(io.Discard, io.Discard))
			if err != nil {
				t.Fatal(err)
			}
			args := []string{"service", command}
			if command == "start" || command == "stop" {
				args = append(args, "database")
			}
			args = append(args, "--system-state-dir", "/private/system-publisher")
			parsed, err := parser.Parse(args)
			if err != nil {
				t.Fatal(err)
			}
			want := "service " + command
			if command == "start" || command == "stop" {
				want += " <job>"
			}
			if parsed.Command() != want {
				t.Fatalf("parent dispatch path: %s, want %s", parsed.Command(), want)
			}
			if command == "start" && root.Service.Start.Job != "database" || command == "stop" && root.Service.Stop.Job != "database" {
				t.Fatal("job selection was lost")
			}
			if command == "serve" && root.Service.Serve.root() != "/private/system-publisher" {
				t.Fatal("unit's state path was lost")
			}
		})
	}
}

func TestSystemServiceNativeStateOutput(t *testing.T) {
	job := publisherjob.Job{ID: "database", Server: "https://control.example", PublisherID: "pub_selected", PublicURLID: "url_selected", Target: "private-target-secret", Protocol: "postgres", TargetCAPEM: []byte("trust-secret"), Enabled: true, Status: publisherjob.Status{State: "ready", PublishRunNumber: 42}}
	var output bytes.Buffer
	if err := renderSystemJobs(&output, "tnl service list", []publisherjob.Job{job}, ""); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"database", "postgres", "ready", "42", "url_selected", "pub_selected"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("publication field missing: %s", expected)
		}
	}
	if strings.Contains(output.String(), "secret") {
		t.Fatal("private state escaped the renderer")
	}
	for _, line := range strings.Split(output.String(), "\n") {
		if len(line) > 72 {
			t.Fatalf("frame wider than 72 columns: %q", line)
		}
		for _, c := range line {
			if c > 127 || c == 27 {
				t.Fatal("non-ASCII output")
			}
		}
	}
}
