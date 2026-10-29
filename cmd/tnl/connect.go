package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"

	"github.com/tnldotdev/tnl/internal/client/project/resolve"
	"github.com/tnldotdev/tnl/internal/client/supervisor"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/connector"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type connectCommand struct {
	Start          connectStartCommand     `cmd:"" default:"withargs" help:"Make an approved service available locally until stopped; start is optional and disambiguates command names."`
	Available      connectAvailableCommand `cmd:"" help:"List services this identity can visit."`
	List           connectListCommand      `cmd:"" help:"List installed local connectors."`
	Stop           connectJobCommand       `cmd:"" help:"Stop an installed connector without revoking access."`
	Remove         connectJobCommand       `cmd:"" help:"Remove an installed connector and its remembered port."`
	KubeCredential kubeCredentialCommand   `cmd:"" hidden:""`
}

type connectStartCommand struct {
	scopedTeamFlags   `embed:""`
	Name              string           `arg:"" name:"name" help:"Configured service name or exact service ID."`
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
	telemetryDisabled bool
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
		Foreground: flags.Foreground, Detach: flags.Detach, Install: flags.Install, System: flags.System, SystemStateDir: flags.SystemStateDir, DetachedChild: flags.DetachedChild, Stdio: flags.Stdio, Output: string(flags.Output), DetachLaunch: flags.detach, TelemetryDisabled: flags.telemetryDisabled,
		Ready: func(destination io.Writer, profile connector.Profile, listen string) error {
			return writeNativeConnection(destination, profile, flags.Output, listen)
		}, Starting: detachedPublicationStarting, PublicationReady: detachedPublicationReady, Prepared: detachedConnectorPrepared}
}

func runConnectStart(ctx context.Context, flags connectStartCommand, output, diagnostics io.Writer) error {
	options := flags.options()
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
	return connectorOperations().Start(ctx, options, os.Stdin, output, diagnostics)
}

func validateConnectMode(flags connectStartCommand) error {
	return connector.ValidateMode(flags.options())
}

func runInstalledConnector(ctx context.Context, job supervisor.Job, ready func() error) error {
	return connectorOperations().RunInstalled(ctx, job, ready)
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
			return supervisor.ErrJobNotFound
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
	services, err := session.Authenticated().Control.ListAvailableServices(ctx)
	if err != nil {
		return err
	}
	if command.Output == statusOutputJSON {
		if services == nil {
			services = []controlv1.Service{}
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
