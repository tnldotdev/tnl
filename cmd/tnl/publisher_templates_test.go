package main

import (
	"testing"

	"github.com/alecthomas/kong"
)

func TestPublisherTemplateCommandsAreRetired(t *testing.T) {
	for _, args := range [][]string{
		{"publisher", "create", "tractor-042", "--from", "tractor"},
		{"publisher", "connection", "tractor-042"},
		{"publisher", "remove", "tractor-042"},
		{"publisher", "rename", "tractor-042", "live"},
		{"publisher", "namespace", "rename", "tractor-042", "live"},
		{"publisher", "serve", "--group", "tractor-042"},
		{"publisher", "enroll", "--group", "tractor-042"},
		{"publisher", "provision", "--group", "tractor-042", "--output-file", "publisher.json"},
	} {
		t.Run(args[1], func(t *testing.T) {
			var flags cli
			parser, err := kong.New(&flags)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parser.Parse(args); err == nil {
				t.Fatal("retired publisher-group workflow remains public")
			}
		})
	}
}
