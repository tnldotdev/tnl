package main

import (
	"encoding/json"
	"io"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/tnldotdev/tnl/internal/cliflags"
	"github.com/tnldotdev/tnl/internal/failure"
)

const helpSchemaVersion = 1

type helpIndex struct {
	SchemaVersion int             `json:"schema_version"`
	Kind          string          `json:"kind"`
	Commands      []helpIndexItem `json:"commands"`
}

type helpIndexItem struct {
	Path    []string `json:"path"` // command words after tnl
	Summary string   `json:"summary"`
	Group   string   `json:"group,omitempty"`
}

type helpReference struct {
	SchemaVersion int    `json:"schema_version"`
	Kind          string `json:"kind"`
	helpIndexItem
	Description    string          `json:"description,omitempty"`
	Aliases        []string        `json:"aliases,omitempty"`
	DefaultCommand string          `json:"default_command,omitempty"`
	Subcommands    []helpIndexItem `json:"subcommands"`
	Usage          []string        `json:"usage"`
	Arguments      []helpInput     `json:"arguments"`
	Flags          []helpInput     `json:"flags"`
	ChildArgs      bool            `json:"child_args,omitempty"`
	Examples       []helpExample   `json:"examples"`
	Results        []helpResult    `json:"results"`
	Constraints    []string        `json:"constraints,omitempty"`
}

type helpInput struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Description string   `json:"description"`
	Required    bool     `json:"required"`
	Repeatable  bool     `json:"repeatable,omitempty"`
	Choices     []string `json:"choices,omitempty"`
	Default     string   `json:"default,omitempty"`
	Scope       string   `json:"scope,omitempty"`
	Shorthand   string   `json:"shorthand,omitempty"`
	AliasFor    string   `json:"alias_for,omitempty"`
	Completion  string   `json:"completion,omitempty"`
}

type helpExample struct {
	Argv    []string `json:"argv"` // includes tnl; $NAME means substitute one argument
	Caption string   `json:"caption"`
}

type helpResult struct {
	Mode   string   `json:"mode"`
	Format string   `json:"format"`
	Stdout string   `json:"stdout,omitempty"`
	Stderr string   `json:"stderr,omitempty"`
	Ends   string   `json:"ends"`
	Proves string   `json:"proves"`
	Fields []string `json:"fields,omitempty"`
	Events []string `json:"events,omitempty"`
}

func writeHelpJSON(w io.Writer, document any) error {
	return failure.Wrap("write help", failure.OutputUnavailable, json.NewEncoder(w).Encode(document))
}

func clientHelpIndex(root *cobra.Command) helpIndex {
	index := helpIndex{SchemaVersion: helpSchemaVersion, Kind: "index", Commands: []helpIndexItem{}}
	var visit func(*cobra.Command)
	visit = func(parent *cobra.Command) {
		for _, child := range parent.Commands() {
			if publicHelpCommand(child) {
				index.Commands = append(index.Commands, helpItem(child))
				visit(child)
			}
		}
	}
	visit(root)
	slices.SortFunc(index.Commands, func(a, b helpIndexItem) int { return slices.Compare(a.Path, b.Path) })
	return index
}

func helpItem(cmd *cobra.Command) helpIndexItem {
	item := helpIndexItem{Path: strings.Fields(cmd.CommandPath())[1:], Summary: cmd.Short}
	for parent := cmd; parent != nil; parent = parent.Parent() {
		if parent.GroupID != "" {
			item.Group = parent.GroupID
			break
		}
	}
	return item
}

func clientHelpReference(cmd *cobra.Command) helpReference {
	cmd.InitDefaultHelpFlag()
	cmd.InitDefaultVersionFlag()
	reference := helpReference{
		SchemaVersion: helpSchemaVersion, Kind: "command", helpIndexItem: helpItem(cmd), Description: cmd.Long,
		Aliases: cmd.Aliases, Subcommands: []helpIndexItem{}, Usage: []string{}, Arguments: []helpInput{},
		Flags: []helpInput{}, Examples: []helpExample{}, Results: []helpResult{},
	}
	argCmd := cmd
	defaultName := cmd.Annotations["default"]
	for _, child := range cmd.Commands() {
		if child.Name() == defaultName {
			argCmd = child
		}
		if !publicHelpCommand(child) {
			continue
		}
		reference.Subcommands = append(reference.Subcommands, helpItem(child))
		if child.Name() == defaultName {
			reference.DefaultCommand = child.Name()
		}
	}
	if len(reference.Subcommands) == 0 || defaultName != "" {
		usage := cmd.UseLine()
		if selectedPath(cmd) == "connect start" {
			reference.ChildArgs = true
			usage += " [-- client-args...]"
		}
		reference.Usage = append(reference.Usage, usage)
	}
	if len(reference.Subcommands) != 0 {
		reference.Usage = append(reference.Usage, cmd.CommandPath()+" <command>")
	}
	argRole, flagRoles := completionRoles(cmd)
	for _, arg := range cliflags.Positionals(argCmd) {
		reference.Arguments = append(reference.Arguments, helpInput{
			Name: arg.Name, Type: helpInputType(arg.Type), Description: arg.Usage,
			Required: !arg.Optional, Repeatable: arg.Repeatable, Choices: arg.Choices, Completion: string(argRole),
		})
	}
	reference.Flags = append(reference.Flags, helpFlags(cmd, cmd.LocalFlags(), "local")...)
	reference.Flags = append(reference.Flags, helpFlags(cmd, cmd.InheritedFlags(), "inherited")...)
	for i := range reference.Flags {
		reference.Flags[i].Completion = string(flagRoles[reference.Flags[i].Name])
	}
	slices.SortFunc(reference.Flags, func(a, b helpInput) int { return strings.Compare(a.Name, b.Name) })

	for _, example := range clientHelpExamples[cmd.CommandPath()] {
		reference.Examples = append(reference.Examples, helpExample{
			Argv: append([]string{"tnl"}, example.argv()...), Caption: example.caption,
		})
	}
	reference.Results = append(reference.Results, commandResultHelp(cmd)...)
	reference.Constraints = commandHelpConstraints(cmd)
	return reference
}

func helpFlags(cmd *cobra.Command, flags *pflag.FlagSet, scope string) []helpInput {
	var result []helpInput
	flags.VisitAll(func(f *pflag.Flag) {
		if f.Hidden {
			return
		}
		meta := cliflags.FlagHelp(f)
		input := helpInput{
			Name: f.Name, Type: helpInputType(f.Value.Type()), Description: meta.Usage, Required: meta.Required,
			Choices: meta.Choices, Default: meta.Default, Scope: scope,
		}
		if meta.Path {
			input.Type = "path"
		}
		input.Repeatable = f.Value.Type() == "slice" || f.Value.Type() == "map"
		if f.ShorthandDeprecated == "" {
			input.Shorthand = f.Shorthand
		}
		if input.Description == "" {
			input.Description = missingInputHelp[f.Name]
		}
		if f.Name == "help" && f.Shorthand == "h" {
			input.Description = "Show help for this command."
		}
		if f.Name == "background" {
			if bg := cmd.Flags().Lookup("bg"); bg != nil && !bg.Hidden && bg.Value == f.Value {
				input.AliasFor = bg.Name
			}
		}
		result = append(result, input)
	})
	return result
}

func helpInputType(kind string) string {
	switch kind {
	case "bool":
		return "boolean"
	case "int", "int64", "uint64":
		return "integer"
	case "map":
		return "key-value"
	case "slice":
		return "string"
	default:
		return kind
	}
}
