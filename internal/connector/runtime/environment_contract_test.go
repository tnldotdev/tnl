package runtime

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"path/filepath"
	"strings"
	"testing"

	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func environmentSelectionFixture() EnvironmentSelection {
	return EnvironmentSelection{Environment: controlv1.EnvironmentReference{Server: "https://control.example", ProjectKey: "project", EnvironmentId: "env_0123456789ABCDEFGHIJKL"}, PermissionID: "mwp_0123456789ABCDEFGHIJKL", Services: map[string]string{"api": "http", "db": "postgres"}}
}

func TestEnvironmentSelectionBounds(t *testing.T) {
	for _, protocol := range []string{"http", "tcp", "mysql", "postgres", "kubernetes"} {
		selection := environmentSelectionFixture()
		selection.Services = map[string]string{"service": protocol}
		if err := selection.Validate(); err != nil { t.Fatal("supported explicit protocol rejected", protocol, err) }
	}
	for _, test := range []struct {
		name string
		change func(*EnvironmentSelection)
	}{
		{"noncanonical server", func(s *EnvironmentSelection) { s.Environment.Server += "/" }},
		{"insecure server", func(s *EnvironmentSelection) { s.Environment.Server = "http://control.example" }},
		{"missing project", func(s *EnvironmentSelection) { s.Environment.ProjectKey = "" }},
		{"invalid project", func(s *EnvironmentSelection) { s.Environment.ProjectKey = "../project" }},
		{"missing environment", func(s *EnvironmentSelection) { s.Environment.EnvironmentId = "" }},
		{"collection is not an environment", func(s *EnvironmentSelection) { s.Environment.EnvironmentId = "col_0123456789ABCDEFGHIJKL" }},
		{"missing permission", func(s *EnvironmentSelection) { s.PermissionID = "" }},
		{"machine is not a permission", func(s *EnvironmentSelection) { s.PermissionID = "mci_0123456789ABCDEFGHIJKL" }},
		{"no services", func(s *EnvironmentSelection) { s.Services = nil }},
		{"invalid name", func(s *EnvironmentSelection) { s.Services["../other"] = "http" }},
		{"unknown protocol", func(s *EnvironmentSelection) { s.Services["other"] = "unknown" }},
		{"missing protocol", func(s *EnvironmentSelection) { s.Services["other"] = "" }},
		{"too many services", func(s *EnvironmentSelection) { for i := range 33 { s.Services[fmt.Sprintf("service-%d", i)] = "tcp" } }},
	} {
		t.Run(test.name, func(t *testing.T) {
			selection := environmentSelectionFixture()
			test.change(&selection)
			if selection.Validate() == nil { t.Fatal("invalid explicit selection accepted") }
		})
	}
	selection := environmentSelectionFixture()
	selection.Services = map[string]string{}
	for i := range 32 { selection.Services[fmt.Sprintf("service-%d", i)] = "tcp" }
	if err := selection.Validate(); err != nil { t.Fatal("maximum requested subset rejected", err) }
}

func TestEnvironmentContextHasExactlyOneSelection(t *testing.T) {
	selection := environmentSelectionFixture()
	root := t.TempDir()
	valid := Context{Schema: Schema, Directory: root, ConfigDigest: strings.Repeat("a", 64), Server: selection.Environment.Server, Audience: selection.Environment.Server, ProjectKey: selection.Environment.ProjectKey, Services: []string{"api", "db"}, Environment: &selection}
	if err := valid.Validate(); err != nil { t.Fatal(err) }
	for _, test := range []struct {
		name string
		change func(*Context)
	}{
		{"duplicate service masks omitted sibling", func(c *Context) { c.Services = []string{"api", "api"} }},
		{"broader services", func(c *Context) { c.Services = []string{"api", "db", "other"} }},
		{"other service", func(c *Context) { c.Services = []string{"api", "other"} }},
		{"other server", func(c *Context) { c.Server = "https://other.example" }},
		{"other audience", func(c *Context) { c.Audience = "https://other.example" }},
		{"other project", func(c *Context) { c.ProjectKey = "other" }},
		{"team alias", func(c *Context) { c.TeamID = "tm_0123456789ABCDEFGHIJKL" }},
		{"environment as source alias", func(c *Context) { c.SourceID = selection.Environment.EnvironmentId }},
		{"relative directory", func(c *Context) { c.Directory = "project" }},
		{"oversized directory", func(c *Context) { c.Directory = filepath.Join(root, strings.Repeat("a", 4096)) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			scope := valid
			test.change(&scope)
			if scope.Validate() == nil { t.Fatal("conflicting environment context accepted") }
		})
	}
}

func TestEnvironmentStartupRejectsAlternateAndSecretShapes(t *testing.T) {
	start := EnvironmentStart{Schema: Schema, Selection: environmentSelectionFixture(), Source: authorityv1.IdentitySourceSelection{Kind: "oidc", MachineId: "mci_0123456789ABCDEFGHIJKL"}}
	encoded, err := json.Marshal(start)
	if err != nil { t.Fatal(err) }
	var valid EnvironmentStart
	if err := ReadJSON(bytes.NewReader(encoded), &valid); err != nil || !maps.Equal(valid.Selection.Services, start.Selection.Services) { t.Fatal("defining startup shape rejected", err) }
	for _, field := range []string{
		`"schema":1`, `"assertion":"must-not-be-in-selection"`, `"publisher_group_id":"pgrp_0123456789ABCDEFGHIJKL"`,
		`"workload":"job"`, `"workloads":{}`, `"manifest":"workloads.json"`, `"saved_provider":"fly"`,
	} {
		input := append(bytes.Clone(encoded[:len(encoded)-1]), []byte(","+field+"}")...)
		if ReadJSON(bytes.NewReader(input), new(EnvironmentStart)) == nil { t.Fatal("duplicate, retired or fabricated startup field accepted", field) }
	}
	for _, input := range [][]byte{
		append(bytes.Clone(encoded), []byte(` {}`)...),
		append(bytes.Clone(encoded), bytes.Repeat([]byte(" "), MaxBytes)...),
		bytes.Replace(encoded, []byte("project"), []byte{'p', 0xff}, 1),
	} {
		if ReadJSON(bytes.NewReader(input), new(EnvironmentStart)) == nil { t.Fatal("trailing, oversized or invalid UTF-8 input accepted") }
	}
}
