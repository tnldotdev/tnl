package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/tnldotdev/tnl/internal/client/detached"
	"github.com/tnldotdev/tnl/internal/client/project/resolve"
	clienttelemetry "github.com/tnldotdev/tnl/internal/client/telemetry"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/connector"
	installedjobs "github.com/tnldotdev/tnl/internal/installed"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type connectCommand struct {
	Start          connectStartCommand
	Available      connectAvailableCommand
	List           connectListCommand
	Stop           connectJobCommand
	Remove         connectJobCommand
	KubeCredential kubeCredentialCommand
}

type connectStartCommand struct {
	telemetry         *clienttelemetry.Collector
	telemetryDisabled bool
	scopedTeamFlags   `embed:""`
	Name              string           `arg:"" name:"name" help:"Configured service name or exact service ID."`
	Deployment        string           `name:"deployment" help:"Select this configured deployment; defaults to local."`
	Listen            string           `name:"listen" help:"Loopback IP and port; defaults to 127.0.0.1 and the allocated service port."`
	Protocol          string           `name:"protocol" help:"Require an exact match: http, tcp, mysql, postgres, or kubernetes."`
	Kubeconfig        string           `name:"kubeconfig" type:"path" help:"Kubeconfig to register the owned Kubernetes context; defaults to KUBECONFIG or ~/.kube/config."`
	Namespace         string           `name:"namespace" help:"Default Kubernetes namespace for this context."`
	KubeUserConfig    string           `name:"kube-user-config" type:"path" help:"Existing kubeconfig containing the explicitly selected bearer-token user."`
	KubeUser          string           `name:"kube-user" help:"Exact existing Kubernetes user; explicitly permits that user's noninteractive exec plugin."`
	KubeTokenFile     string           `name:"kube-token-file" type:"path" help:"Private file containing the cluster bearer token."`
	Foreground        bool             `name:"foreground" help:"Run in this terminal (the default)."`
	Detach            bool             `name:"detach" help:"Run independently of this terminal without automatic restart."`
	Install           bool             `name:"install" help:"Keep this connector running with the installed user supervisor."`
	System            bool             `name:"system" hidden:""`
	SystemStateDir    string           `name:"system-state-dir" type:"path" help:"Private user supervisor state directory."`
	DetachedChild     string           `name:"detached-child" hidden:""`
	Stdio             bool             `name:"stdio" help:"Carry one opaque TCP stream on stdin/stdout; sign in explicitly before use."`
	Output            statusOutputMode `name:"output" enum:"human,json" default:"human" help:"Ready local connection address and native client instructions."`
	project           projectConfiguration
	detach            func() error
}

type connectListCommand struct {
	SystemStateDir string           `name:"system-state-dir" type:"path" help:"Private user supervisor state directory."`
	Output         statusOutputMode `name:"output" enum:"human,json" default:"human"`
}
type connectJobCommand struct {
	connectListCommand `embed:""`
	Name               string `arg:"" name:"name" help:"Installed connector name or job ID."`
}
type connectAvailableCommand struct {
	remoteFlags `embed:""`
	Output      statusOutputMode `name:"output" enum:"human,json" default:"human"`
}
type kubeCredentialCommand struct {
	Profile string `name:"profile" required:"" type:"path"`
}

func connectorOperations() connector.Operations {
	return connector.Operations{OpenSession: func(ctx context.Context, options connector.SessionOptions, command string, diagnostics io.Writer) (*connector.Session, error) {
		session, err := openTeamSession(ctx, remoteFlags{ServerURL: options.ServerURL, StateDir: options.StateDir, AccessToken: options.AccessToken, ProjectTeam: options.ProjectTeam, SelectedTeam: options.SelectedTeam}, command, diagnostics)
		if err != nil {
			return nil, err
		}
		return connector.NewSession(session.Database(), session.Store(), session.Authenticated(), session.Identity(), session.CurrentMembership), nil
	}}
}

func (flags connectStartCommand) options() connector.StartOptions {
	remote := flags.selection()
	return connector.StartOptions{SessionOptions: connector.SessionOptions{ServerURL: remote.ServerURL, StateDir: remote.StateDir, AccessToken: remote.AccessToken, ProjectTeam: remote.ProjectTeam, SelectedTeam: remote.SelectedTeam}, Team: flags.Team, Project: flags.project.Project,
		Name: flags.Name, Listen: flags.Listen, Protocol: flags.Protocol, Kubeconfig: flags.Kubeconfig, Namespace: flags.Namespace, KubeUserConfig: flags.KubeUserConfig, KubeUser: flags.KubeUser, KubeTokenFile: flags.KubeTokenFile,
		Foreground: flags.Foreground, Detach: flags.Detach, Install: flags.Install, System: flags.System, SystemStateDir: flags.SystemStateDir, DetachedChild: flags.DetachedChild, Stdio: flags.Stdio, Output: string(flags.Output), DetachLaunch: flags.detach,
		Ready: func(destination io.Writer, profile connector.Profile, listen string) error {
			return writeNativeConnection(destination, profile, flags.Output, listen)
		}, Starting: detached.Starting, PublicationReady: detached.Ready, Prepared: func(ctx context.Context, profile connector.Profile) { detached.SetConnection(ctx, profile) }}
}

func runConnectStart(ctx context.Context, flags connectStartCommand, output, diagnostics io.Writer) error {
	options := flags.options()
	options.TelemetryDisabled = flags.telemetryDisabled
	if err := connector.ValidateMode(options); err != nil {
		return err
	}
	if flags.Install {
		var err error
		options.ServiceOptions, err = (systemStateFlags{SystemStateDir: flags.SystemStateDir}).options()
		if err != nil {
			return err
		}
		if err := requireInstalledService(ctx, options.ServiceOptions, nil); err != nil {
			return err
		}
	}
	operations := connectorOperations()
	operations.Telemetry = flags.telemetry
	return operations.Start(ctx, options, os.Stdin, output, diagnostics)
}

func validateConnectMode(flags connectStartCommand) error {
	return connector.ValidateMode(flags.options())
}

func runInstalledConnector(ctx context.Context, job installedjobs.Job, telemetry *clienttelemetry.Collector, ready func() error, deadline func() time.Time, shutdown context.Context) error {
	operations := connectorOperations()
	operations.Telemetry = telemetry
	operations.ShutdownDeadline = deadline
	operations.ShutdownContext = shutdown
	return operations.RunInstalled(ctx, job, ready)
}
func runKubeCredential(ctx context.Context, flags kubeCredentialCommand, output io.Writer) error {
	return connector.WriteKubeCredential(ctx, flags.Profile, output)
}

func (project projectConfiguration) applyConnect(flags *connectStartCommand) error {
	remote, err := project.connectScope(flags.Name, flags.scopedTeamFlags)
	if err != nil {
		return err
	}
	flags.project, flags.scopedTeamFlags = project, remote
	return nil
}

func (project projectConfiguration) connectScope(name string, remote scopedTeamFlags) (scopedTeamFlags, error) {
	key, err := connector.ConfiguredService(project.Project, name)
	if err != nil {
		return remote, err
	}
	effective, err := project.EffectiveService(key)
	if err != nil {
		return remote, err
	}
	remote.ServerURL, _, err = resolve.Server(remote.ServerURL, effective.Server, remote.AccessToken)
	if err != nil {
		return remote, err
	}
	remote.ProjectTeam, err = resolve.TeamForServer(remote.ServerURL, effective.Server, effective.Team)
	return remote, err
}

func runConnectJobs(ctx context.Context, flags connectListCommand, name, action string, output io.Writer) error {
	options, err := (systemStateFlags{SystemStateDir: flags.SystemStateDir}).options()
	if err != nil {
		return err
	}
	if err := requireConfiguredService(ctx, options, nil); err != nil {
		return err
	}
	jobs, err := connector.Jobs(ctx, options, name, action)
	if err != nil {
		return err
	}
	if name != "" && action == "remove" {
		return writeHumanFrame(output, "tnl connect remove", "removed", "", clioutput.Fields(clioutput.Field{Label: "name", Value: jobs[0].Name}))
	}
	if name != "" {
		if len(jobs) == 0 {
			return installedjobs.ErrJobNotFound
		}
		return renderSystemJobs(output, "tnl connect stop", jobs, jobs[0].ID)
	}
	if flags.Output == statusOutputJSON {
		return json.NewEncoder(output).Encode(jobs)
	}
	return renderSystemJobs(output, "tnl connect "+strings.TrimSpace(action), jobs, "")
}

func runConnectAvailable(ctx context.Context, command connectAvailableCommand, output, diagnostics io.Writer) error {
	session, err := openTeamSession(ctx, command.remoteFlags, "tnl connect available", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	services, err := session.Authenticated().Control.ListAvailableServices(ctx, controlv1.ServiceAccessPathConnector)
	if err != nil {
		return err
	}
	if command.Output == statusOutputJSON {
		if services == nil {
			services = []controlv1.ServiceSummary{}
		}
		return json.NewEncoder(output).Encode(services)
	}
	blocks := make([]clioutput.Block, 0, len(services))
	for _, service := range services {
		state := "offline"
		if service.Enabled && service.ServiceRunId != nil && service.RunNumber != nil {
			state = "ready"
		}
		blocks = append(blocks, clioutput.Section(service.Name, clioutput.Fields(clioutput.Field{Label: "service ID", Value: service.Id}, clioutput.Field{Label: "team ID", Value: service.TeamId}, clioutput.Field{Label: "state", Value: state})))
	}
	return writeHumanFrame(output, "tnl connect available", countState(len(services), "service", "services"), "", blocks...)
}

func (a *commandApp) newConnectCommand() *cobra.Command {
	f := a.flags
	cConnect := &cobra.Command{Use: "connect", Short: "Make an approved service available locally using the current identity.", GroupID: "start"}
	cConnectStart := &cobra.Command{Use: "start", Short: "Make an approved service available locally until stopped; start is optional and disambiguates command names."}
	a.leaf(cConnectStart, &f.Connect.Start, func(call commandCall) error {
		return a.startConnector(call)
	})
	cConnect.AddCommand(cConnectStart)
	a.useDefault(cConnect, cConnectStart)
	cConnectAvailable := &cobra.Command{Use: "available", Short: "List services this identity can visit."}
	a.leaf(cConnectAvailable, &f.Connect.Available, func(call commandCall) error {
		return runConnectAvailable(call.ctx, f.Connect.Available, a.out, a.errOut)
	})
	cConnect.AddCommand(cConnectAvailable)
	cConnectList := &cobra.Command{Use: "list", Short: "List installed local connectors."}
	a.leaf(cConnectList, &f.Connect.List, func(call commandCall) error {
		return runConnectJobs(call.ctx, f.Connect.List, "", "list", a.out)
	})
	cConnect.AddCommand(cConnectList)
	cConnectStop := &cobra.Command{Use: "stop", Short: "Stop an installed connector without revoking access."}
	a.leaf(cConnectStop, &f.Connect.Stop, func(call commandCall) error {
		return runConnectJobs(call.ctx, f.Connect.Stop.connectListCommand, f.Connect.Stop.Name, "stop", a.out)
	})
	cConnect.AddCommand(cConnectStop)
	cConnectRemove := &cobra.Command{Use: "remove", Short: "Remove an installed connector and its remembered port."}
	a.leaf(cConnectRemove, &f.Connect.Remove, func(call commandCall) error {
		return runConnectJobs(call.ctx, f.Connect.Remove.connectListCommand, f.Connect.Remove.Name, "remove", a.out)
	})
	cConnect.AddCommand(cConnectRemove)
	cConnectKubeCredential := &cobra.Command{Use: "kube-credential", Short: "", Hidden: true}
	a.leaf(cConnectKubeCredential, &f.Connect.KubeCredential, func(call commandCall) error {
		return runKubeCredential(call.ctx, f.Connect.KubeCredential, a.out)
	})
	cConnect.AddCommand(cConnectKubeCredential)
	return cConnect
}

func (a *commandApp) startConnector(call commandCall) error {
	ctx, flags := call.ctx, a.flags
	connect := &flags.Connect.Start
	if err := validateConnectMode(*connect); err != nil {
		return err
	}
	if connect.Install {
		options, err := (systemStateFlags{SystemStateDir: connect.SystemStateDir}).options()
		if err != nil {
			return err
		}
		if err := requireInstalledService(ctx, options, nil); err != nil {
			return err
		}
	}
	if connect.Detach {
		// resolve and validate the service mode before creating a child.
		connect.detach = func() error { return detachPublish(ctx, a.argv, connect.StateDir, a.out, "tnl connect") }
	}
	root, err := clientStateRoot(connect.StateDir)
	if err != nil {
		return err
	}
	if connect.DetachedChild != "" {
		var cleanup func()
		ctx, cleanup, err = detached.Serve(ctx, root, connect.DetachedChild)
		if err != nil {
			return err
		}
		defer cleanup()
	}
	project, err := loadProjectConfiguration(ctx, *flags, root)
	if err != nil {
		return err
	}
	if err := project.applyConnect(connect); err != nil {
		return err
	}
	call.started()
	return runConnectStart(ctx, *connect, a.out, a.errOut)
}
