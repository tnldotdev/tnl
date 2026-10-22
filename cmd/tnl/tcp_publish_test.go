package main

import (
	"testing"

	"github.com/alecthomas/kong"
	targetplan "github.com/tnldotdev/tnl/internal/publisher/target"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestPrivatePublishTargetAndPublicBoundary(t *testing.T) {
	requests, excessiveConcurrency := 1, 4097
	for _, value := range []string{"tcp", "mysql", "postgres"} {
		protocol, err := publishProtocol(value)
		if err != nil || string(protocol) != value {
			t.Fatalf("protocol %q: %v", value, err)
		}
		for input, want := range map[string]string{"5432": "127.0.0.1:5432", "db.internal:5432": "db.internal:5432"} {
			if got, err := targetplan.NormalizePublicAddress(input, protocol); err != nil || got != want {
				t.Fatalf("%s target %q = %q, %v", value, input, got, err)
			}
		}
		for _, target := range []string{"http://db.internal:5432", "db.internal", "db.internal:0", "db.internal:65536"} {
			if _, err := targetplan.NormalizePublicAddress(target, protocol); err == nil {
				t.Fatalf("invalid target %q accepted", target)
			}
		}
		if _, err := savedPublicAddress(controlv1.PublicURL{ServiceProtocol: protocol}); err == nil {
			t.Fatal("service accepted as a public URL")
		}
		for _, flags := range []publishCommand{
			{openOptions: openOptions{Open: true}},
			{tunnelFlags: tunnelFlags{Ephemeral: true}},
			{tunnelFlags: tunnelFlags{PublicURL: "db.example"}},
			{tunnelFlags: tunnelFlags{Anonymous: true}},
			{tunnelFlags: tunnelFlags{Requests: &requests}},
			{tunnelFlags: tunnelFlags{Concurrency: &excessiveConcurrency}},
		} {
			if err := validateTCPPublishOptions(flags, protocol); err == nil {
				t.Fatalf("private %s accepted HTTP/target TLS flags", value)
			}
		}
	}
	for _, value := range []string{"ssh", "redis", "other"} {
		if _, err := publishProtocol(value); err == nil {
			t.Fatalf("unsupported protocol %q accepted", value)
		}
	}
	if address, err := savedPublicAddress(controlv1.PublicURL{ServiceProtocol: controlv1.Http, CanonicalHostname: "web.example"}); err != nil || address != "https://web.example" {
		t.Fatalf("HTTP public address = %q, %v", address, err)
	}
}

func TestRemovedSSHAndPublicDatabaseCommandsAreRejected(t *testing.T) {
	for _, args := range [][]string{
		{"ssh", "enable"}, {"share", "team", "create", "web.example", "--ssh-user", "deploy"},
		{"publish", "3000", "--credential", "secret"}, {"publish", "3000", "--ephemeral-credential", "secret"},
		{"publish", "db:5432", "--visitor-tls-passthrough"}, {"url", "credential", "create"},
		{"url", "certificate", "db.example", "--directory", "/tmp/visitor"},
	} {
		var flags cli
		parser, err := kong.New(&flags)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parser.Parse(args); err == nil {
			t.Fatalf("removed command accepted: %v", args)
		}
	}
}
