package main

import (
	"testing"
	"time"

	"github.com/alecthomas/kong"
	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
)

func TestAuthApprovalParsingAndEnvironmentServer(t *testing.T) {
	args := []string{"auth", "approve", "--environment", "staging", "--workload", "tests", "--intent", "approve-1", "--expires-at", "2026-12-01T00:00:00Z", "--output", "json"}
	var flags cli
	parser, err := kong.New(&flags)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parser.Parse(args)
	if err != nil || parsed.Command() != "auth approve" || flags.Auth.Approve.Intent != "approve-1" || !flags.Auth.Approve.ExpiresAt.Equal(time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatal("approval parser", parsed, err)
	}
	project := projectConfiguration{Project: clientproject.Project{Config: config.TNL{Server: new("https://default.example"), Team: new("default"), Environments: map[string]config.Environment{"staging": {Server: new("https://staging.example")}}}}}
	if err := applyProjectCommandContext("auth approve", project, &flags); err != nil || flags.Auth.Approve.ServerURL != "https://staging.example" {
		t.Fatal("approval used another environment server", flags.Auth.Approve.ServerURL, err)
	}
	for _, missing := range []string{"--intent", "--expires-at"} {
		var f cli
		p, err := kong.New(&f)
		if err != nil {
			t.Fatal(err)
		}
		var incomplete []string
		for i := 0; i < len(args); i++ {
			if args[i] == missing {
				i++
				continue
			}
			incomplete = append(incomplete, args[i])
		}
		if _, err := p.Parse(incomplete); err == nil {
			t.Fatal("approval accepted missing recovery input", missing)
		}
	}
}
