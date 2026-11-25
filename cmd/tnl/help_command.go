package main

import (
	"errors"
	"strings"

	"github.com/spf13/cobra"
	"github.com/tnldotdev/tnl/internal/cliflags"
	"github.com/tnldotdev/tnl/internal/failure"
)

func (a *commandApp) newClientHelpCommand() *cobra.Command {
	var options struct {
		Audience helpAudience `name:"audience" enum:"human,agent" help:"Choose who the examples are for. Overrides environment hints."`
		Output   string       `name:"output" enum:"human,json" default:"human" help:"Write text help or a JSON command index or reference."`
	}
	cmd := &cobra.Command{
		Use: "help [command...]", Short: "Show help for a command.", GroupID: "tools",
		Annotations: map[string]string{"cliflags:arg:command...": "Command and any nested subcommands."},
	}
	cliflags.Bind(cmd, &options, false)
	cmd.Args = cobra.ArbitraryArgs
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		// discovery selects its output without entering the operation path.
		if err := a.selectOutput(cmd); err != nil {
			return err
		}
		if options.Output == "json" {
			if len(args) == 0 {
				return writeHelpJSON(cmd.OutOrStdout(), clientHelpIndex(cmd.Root()))
			}
			target, rest := matchHelpTopic(cmd.Root(), args, publicHelpCommand)
			if len(rest) != 0 {
				return invalidHelpTopic(target, rest[0])
			}
			return writeHelpJSON(cmd.OutOrStdout(), clientHelpReference(target))
		}
		target, rest := findHelpTopic(cmd.Root(), args)
		if len(rest) != 0 {
			return invalidHelpTopic(target, rest[0])
		}
		target.InitDefaultHelpFlag()
		target.InitDefaultVersionFlag()
		return writeClientHelp(target, helpView{audience: currentHelpAudience(options.Audience), reference: true})
	}
	cmd.ValidArgsFunction = completeHelpTopic
	return cmd
}

// help accepts command names and aliases, not the target command's arguments.
func findHelpTopic(parent *cobra.Command, args []string) (*cobra.Command, []string) {
	return matchHelpTopic(parent, args, func(*cobra.Command) bool { return true })
}

func matchHelpTopic(parent *cobra.Command, args []string, visible func(*cobra.Command) bool) (*cobra.Command, []string) {
	for len(args) != 0 {
		var match *cobra.Command
		for _, child := range parent.Commands() {
			if (child.Name() == args[0] || child.HasAlias(args[0])) && visible(child) {
				match = child
				break
			}
		}
		if match == nil {
			break
		}
		parent, args = match, args[1:]
	}
	return parent, args
}

// callers walk only public ancestors. Cobra excludes help itself from its
// available commands, even though it is part of discovery.
func publicHelpCommand(cmd *cobra.Command) bool {
	return cmd.IsAvailableCommand() || cmd.Name() == "help" && !cmd.Hidden
}

func completeHelpTopic(cmd *cobra.Command, args []string, prefix string) ([]cobra.Completion, cobra.ShellCompDirective) {
	target, rest := findHelpTopic(cmd.Root(), args)
	var choices []cobra.Completion
	if len(rest) == 0 && publicCommandPath(target) {
		for _, child := range target.Commands() {
			if (child.IsAvailableCommand() || child.Name() == "help" && !child.Hidden) && strings.HasPrefix(child.Name(), prefix) {
				choices = append(choices, cobra.CompletionWithDesc(child.Name(), child.Short))
			}
		}
	}
	return choices, cobra.ShellCompDirectiveNoFileComp
}

func publicCommandPath(cmd *cobra.Command) bool {
	for ; cmd != nil; cmd = cmd.Parent() {
		if cmd.Hidden {
			return false
		}
	}
	return true
}

func invalidHelpTopic(parent *cobra.Command, word string) error {
	path := strings.Fields(parent.CommandPath())
	command := append([]string{"tnl", "help"}, path[1:]...)
	message := "Unknown help topic."
	if parent.HasParent() {
		message = "Unknown help topic under " + parent.CommandPath() + "."
	}
	if suggestion := commandSuggestion(parent, word); suggestion != "" {
		command = append(command, suggestion)
	}
	return failure.Wrap("select help topic", failure.InvalidCommand, &commandGuidance{errors.New("unknown help topic"), message, command})
}

func commandSuggestion(parent *cobra.Command, word string) string {
	if word == "" || len(word) > 64 || !publicCommandPath(parent) {
		return ""
	}
	// Cobra filters unavailable commands and matches close spellings and prefixes.
	parent.SuggestionsMinimumDistance = 2
	if suggestions := parent.SuggestionsFor(word); len(suggestions) != 0 {
		return suggestions[0]
	}
	return ""
}
