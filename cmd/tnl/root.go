package main

import (
	"context"
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
	const tagline = "tunnels for local apps and private services."
	root := &cobra.Command{
		Use: "tnl", Short: tagline,
		Long:          tagline + "\n\nGive your local app an HTTPS URL you can share, or connect to a service on a private network.",
		SilenceErrors: true, SilenceUsage: true,
	}
	root.SetOut(a.out)
	root.SetErr(a.errOut)
	root.SetHelpCommandGroupID("tools")
	root.SetCompletionCommandGroupID("tools")
	root.AddGroup(
		&cobra.Group{ID: "start", Title: "Start here:"},
		&cobra.Group{ID: "project", Title: "Projects and worktrees:"},
		&cobra.Group{ID: "access", Title: "Sharing and access:"},
		&cobra.Group{ID: "deploy", Title: "Deployments and publishers:"},
		&cobra.Group{ID: "observe", Title: "Diagnostics:"},
		&cobra.Group{ID: "tools", Title: "Tools:"},
	)
	cliflags.Bind(root, a.flags, true)
	root.AddCommand(a.newInitCommand(), a.newApplyCommand(), a.newDeploymentCommand(), a.newGenerateCommand(), a.newCheckCommand(), a.newAuditCommand(), a.newRuntimeCommand(), a.newWaitCommand(), a.newWatchCommand(), a.newPublishCommand(), a.newConnectCommand(), a.newPublisherCommand(), a.newServiceCommand(), a.newEndpointCommand(), a.newDetachedCommand(), a.newStatusCommand(), a.newPingCommand(), a.newInspectCommand(), a.newTelemetryCommand(), a.newAuthCommand(), a.newTeamCommand(), a.newDomainCommand(), a.newURLCommand(), a.newShareCommand(), a.newFeedbackCommand(), a.newWebhookCommand(), a.newAliasCommand(), a.newAdminCommand(), a.newVersionCommand())
	root.AddCommand(a.newAgentGuideCommand())
	root.InitDefaultHelpCmd()
	root.InitDefaultCompletionCmd()
	addClientHelpContent(root)
	configureClientHelp(root)
	registerProjectCompletions(root)
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
