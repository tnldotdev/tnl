package main

import (
	"io"
	"testing"
	"time"
)

func TestDeploymentCredentialFlagsKeepCapabilitiesAndOriginalKeyExplicit(t *testing.T) {
	var flags cli
	parser := commandForTest(&flags, io.Discard)
	parsed, err := parser([]string{"auth", "credential", "create", "backend", "--project-key", "shop", "--manage", "db", "--connect", "db", "--all-deployments", "--expires-in", "24h", "--idempotency-key", "original", "--team", "acme"})
	if err != nil {
		t.Fatal(err)
	}
	value := flags.Auth.Credential.Create
	if commandID(parsed) != "auth credential create <name>" || len(value.Manage) != 1 || len(value.Connect) != 1 || !value.AllDeployments || value.ExpiresIn != 24*time.Hour || value.IdempotencyKey != "original" || value.Team != "acme" {
		t.Fatal("credential setup lost explicit intent")
	}
}
