package main

import (
	"io"
	"testing"

	"github.com/alecthomas/kong"
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
		{[]string{"publish", "3000", "--publisher-file", "/tmp/publisher.json"}, "publish <service-or-target>"},
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
		if tc.command == "publish <service-or-target>" && flags.Publish.PublisherFile != "/tmp/publisher.json" {
			t.Fatal("file flag was lost")
		}
	}
}
