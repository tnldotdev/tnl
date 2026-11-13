package main

import (
	"testing"
	"time"

	"github.com/alecthomas/kong"
)

func TestDeploymentCredentialFlagsKeepCapabilitiesAndOriginalKeyExplicit(t *testing.T) {
	var flags cli
	parser, err := kong.New(&flags)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parser.Parse([]string{"auth", "credential", "create", "backend", "--project-key", "shop", "--manage", "db", "--connect", "db", "--publish", "web", "--temporary", "restricted", "--all-deployments", "--expires-in", "24h", "--idempotency-key", "original", "--team", "acme"})
	if err != nil {
		t.Fatal(err)
	}
	value := flags.Auth.Credential.Create
	if parsed.Command() != "auth credential create <name>" || len(value.Manage) != 1 || len(value.Connect) != 1 || len(value.Publish) != 1 || value.Temporary != "restricted" || !value.AllDeployments || value.ExpiresIn != 24*time.Hour || value.IdempotencyKey != "original" || value.Team != "acme" {
		t.Fatal("credential setup lost explicit intent")
	}
}
