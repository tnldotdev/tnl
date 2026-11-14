package main

import (
	"io"
	"testing"

	"github.com/alecthomas/kong"
	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
)

func TestEndpointReleaseCommandUsesExactPortAndProjectContext(t *testing.T) {
	var flags cli
	parser, err := kong.New(&flags, kong.Writers(io.Discard, io.Discard))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parser.Parse([]string{"endpoint", "release", "svc_aaaaaaaaaaaaaaaaaaaaaa", "--port", "25443", "--team", "operators"})
	if err != nil || parsed.Command() != "endpoint release <service-id>" || flags.Endpoint.Release.Port != 25443 {
		t.Fatal("release lost its exact service and port", parsed, err)
	}
	server, team := "https://project.example", "project-team"
	project := projectConfiguration{Project: clientproject.Project{Config: config.TNL{Server: &server, Team: &team}}}
	if !projectSensitiveCommand(parsed.Command()) || applyProjectCommandContext(parsed.Command(), project, &flags) != nil {
		t.Fatal("release ignored project context")
	}
	selection := flags.Endpoint.Release.selection()
	if selection.ServerURL != server || selection.ProjectTeam != team || selection.SelectedTeam != "operators" {
		t.Fatal("release lost team or server selection", selection)
	}
	flags.Endpoint.Release.ServerURL = "https://explicit.example"
	if err := applyProjectCommandContext(parsed.Command(), project, &flags); err != nil || flags.Endpoint.Release.ProjectTeam != "" {
		t.Fatal("cross-server release inherited a project team", err)
	}
}

func TestEndpointReleaseRejectsImplicitPortAndInvalidService(t *testing.T) {
	var flags cli
	parser, err := kong.New(&flags, kong.Writers(io.Discard, io.Discard))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parser.Parse([]string{"endpoint", "release", "svc_aaaaaaaaaaaaaaaaaaaaaa"}); err == nil {
		t.Fatal("release did not require explicit reservation intent")
	}
	for _, flags := range []endpointReleaseCommand{
		{ServiceID: "app", Port: 25443},
		{ServiceID: "svc_aaaaaaaaaaaaaaaaaaaaaa", Port: 0},
		{ServiceID: "svc_aaaaaaaaaaaaaaaaaaaaaa", Port: 443},
		{ServiceID: "svc_aaaaaaaaaaaaaaaaaaaaaa", Port: 65536},
	} {
		err := runEndpointRelease(t.Context(), flags, io.Discard, io.Discard)
		if reason, ok := failure.ReasonOf(err); !ok || reason != failure.InvalidTunnelFlags {
			t.Fatal("invalid release reached authentication or local state", err)
		}
	}
}
