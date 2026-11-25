package main

import (
	"context"
	"errors"
	"io"
	"strings"

	"github.com/spf13/cobra"
	"github.com/tnldotdev/tnl/internal/cliflags"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
)

type commandApp struct {
	flags                         *cli
	out, errOut                   io.Writer
	factories                     []telemetryFactory
	outputSelected, machineOutput bool
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
	root.AddCommand(a.newInitCommand(), a.newApplyCommand(), a.newDeploymentCommand(), a.newGenerateCommand(), a.newCheckCommand(), a.newAuditCommand(), a.newRuntimeCommand(), a.newWaitCommand(), a.newWatchCommand(), a.newPublishCommand(), a.newConnectCommand(), a.newPublisherCommand(), a.newServiceCommand(), a.newEndpointCommand(), a.newStatusCommand(), a.newPingCommand(), a.newInspectCommand(), a.newTelemetryCommand(), a.newAuthCommand(), a.newTeamCommand(), a.newDomainCommand(), a.newURLCommand(), a.newShareCommand(), a.newFeedbackCommand(), a.newWebhookCommand(), a.newAliasCommand(), a.newAdminCommand(), a.newVersionCommand())
	root.AddCommand(a.newAgentGuideCommand())
	root.AddCommand(a.newStopCommand())
	root.SetHelpCommand(a.newClientHelpCommand())
	root.InitDefaultHelpCmd()
	root.InitDefaultCompletionCmd()
	addClientHelpContent(root)
	classifyInputErrors(root)
	configureClientHelp(root)
	registerProjectCompletions(root, &a.flags.Wait.Service)
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

func useProjectServiceArgument(cmd *cobra.Command, argument, service *string, reason failure.Reason) {
	parse := cmd.Args
	cmd.Args = func(cmd *cobra.Command, args []string) error {
		if err := parse(cmd, args); err != nil {
			return err
		}
		invalid := func(message string) error {
			help := append(strings.Fields(cmd.CommandPath()), "--help")
			return failure.Wrap("select project service", reason, &commandGuidance{errors.New(message), message, help})
		}
		flag := cmd.Flags().Changed("service")
		if len(args) == 0 && !flag {
			return nil
		}
		selected := *service
		if len(args) != 0 {
			if flag {
				return invalid("Pass a service name or --service, not both.")
			}
			selected = *argument
		}
		if !naming.ValidServiceName(selected) {
			return invalid("Specify a valid project service name.")
		}
		*service = selected
		return nil
	}
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
