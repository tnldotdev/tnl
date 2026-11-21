package main

import (
	"context"
	"errors"
	"io"
	"strings"

	"github.com/spf13/cobra"
	"github.com/tnldotdev/tnl/internal/cliflags"
)

type commandApp struct {
	flags       *cli
	out, errOut io.Writer
	argv        []string
	factories   []telemetryFactory
}

type commandCall struct {
	command *cobra.Command
	started func()
	ctx     context.Context
	project projectConfiguration
}

func (a *commandApp) root() *cobra.Command {
	root := &cobra.Command{
		Use: "tnl", Short: "take a shortcut through the internet.",
		Long:          "take a shortcut through the internet.\n\nPublish local services at stable public URLs. Start your app normally with its tnl integration, try tnl publish --demo, or run tnl publish 3000 for an already-running service. By default, visitors need a current sign-in, link, or token.",
		SilenceErrors: true, SilenceUsage: true,
	}
	root.SetOut(a.out)
	root.SetErr(a.errOut)
	root.SetHelpCommandGroupID("operate")
	root.SetCompletionCommandGroupID("operate")
	root.AddGroup(&cobra.Group{ID: "start", Title: "Start here:"}, &cobra.Group{ID: "manage", Title: "Manage:"}, &cobra.Group{ID: "operate", Title: "Operate:"})
	cliflags.Bind(root, a.flags, true)
	root.AddCommand(a.newInitCommand(), a.newApplyCommand(), a.newDeploymentCommand(), a.newGenerateCommand(), a.newCheckCommand(), a.newAuditCommand(), a.newRuntimeCommand(), a.newWaitCommand(), a.newWatchCommand(), a.newPublishCommand(), a.newConnectCommand(), a.newPublisherCommand(), a.newServiceCommand(), a.newEndpointCommand(), a.newDetachedCommand(), a.newStatusCommand(), a.newPingCommand(), a.newInspectCommand(), a.newTelemetryCommand(), a.newAuthCommand(), a.newTeamCommand(), a.newDomainCommand(), a.newURLCommand(), a.newShareCommand(), a.newFeedbackCommand(), a.newWebhookCommand(), a.newAliasCommand(), a.newAdminCommand(), a.newVersionCommand())
	var requireCommand func(*cobra.Command)
	requireCommand = func(cmd *cobra.Command) {
		if cmd.RunE == nil {
			cmd.Args = cobra.NoArgs
			cmd.RunE = func(*cobra.Command, []string) error { return errors.New("command is required") }
		}
		for _, sub := range cmd.Commands() {
			requireCommand(sub)
		}
	}
	requireCommand(root)
	return root
}

func (a *commandApp) leaf(cmd *cobra.Command, options any, handle func(commandCall) error) {
	cliflags.Bind(cmd, options, false)
	cmd.RunE = func(cmd *cobra.Command, _ []string) error { return a.execute(cmd, handle) }
}

// shorthand and explicit commands share their pflag values, argument
// validation and handler. sibling commands do not inherit the shorthand flags.
func (a *commandApp) useDefault(parent, child *cobra.Command) {
	parent.Args, parent.RunE = child.Args, child.RunE
	parent.Flags().AddFlagSet(child.Flags())
	parent.Use += strings.TrimPrefix(child.Use, child.Name())
	parent.Annotations = map[string]string{"default": child.Name()}
}

func selectedPath(cmd *cobra.Command) string {
	path := strings.TrimPrefix(cmd.CommandPath(), "tnl ")
	if sub := cmd.Annotations["default"]; sub != "" {
		path += " " + sub
	}
	return path
}

func commandID(cmd *cobra.Command) string {
	path := selectedPath(cmd)
	for _, arg := range strings.Fields(cmd.Use)[1:] {
		path += " <" + strings.Trim(arg, "[]<>") + ">"
	}
	return canonicalParsedCommand(path)
}
