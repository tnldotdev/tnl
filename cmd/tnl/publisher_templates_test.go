package main

import (
	"testing"

	"github.com/alecthomas/kong"
	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestPublisherTemplateCommandContext(t *testing.T) {
	project := projectConfiguration{Project: clientproject.Project{Config: config.TNL{Server: new("https://control.example"), Team: new("tractorco")}}}
	for _, action := range []string{"create", "connection", "remove"} {
		t.Run(action, func(t *testing.T) {
			var flags cli
			parser, err := kong.New(&flags)
			if err != nil {
				t.Fatal(err)
			}
			args := []string{"publisher", action, "tractor-042"}
			if action == "create" {
				args = append(args, "--from", "tractor")
			}
			parsed, err := parser.Parse(args)
			if err != nil {
				t.Fatal(err)
			}
			if err := applyProjectCommandContext(parsed.Command(), project, &flags); err != nil {
				t.Fatal(err)
			}
			var selected publisherGroupCommand
			switch action {
			case "create":
				selected = flags.Publisher.Create.publisherGroupCommand
			case "connection":
				selected = flags.Publisher.Connection
			case "remove":
				selected = flags.Publisher.Remove
			}
			if selected.ServerURL != "https://control.example" || selected.ProjectTeam != "tractorco" || selected.Name != "tractor-042" {
				t.Fatalf("lost project scope: %+v", selected)
			}
		})
	}
}

func TestPublisherTemplateStatusSelectsExactGroup(t *testing.T) {
	groups := []controlv1.AppliedPublisherGroup{{Id: "a", Name: "tractor-a", GroupNames: []string{"tractor-a", "old-a"}}, {Id: "b", Name: "tractor-b", GroupNames: []string{"tractor-b"}}}
	for _, selector := range []string{"a", "tractor-a", "old-a"} {
		applied := controlv1.AppliedProjectConfiguration{Groups: &groups, Services: []controlv1.AppliedProjectService{{Service: "api", PublisherGroup: "tractor-a"}, {Service: "api", PublisherGroup: "tractor-b"}}, Members: []controlv1.PublisherGroupMemberStatus{{GroupId: "a"}, {GroupId: "b"}}}
		if err := selectAppliedPublisherGroup(&applied, selector); err != nil {
			t.Fatal(err)
		}
		if len(applied.Services) != 1 || applied.Services[0].PublisherGroup != "tractor-a" || len(applied.Members) != 1 || applied.Members[0].GroupId != "a" {
			t.Fatal("status mixed groups")
		}
	}
	if err := selectAppliedPublisherGroup(&controlv1.AppliedProjectConfiguration{Groups: &groups}, "missing"); err == nil {
		t.Fatal("missing group fell back to another")
	}
}
