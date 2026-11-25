package main

import (
	"context"
	"errors"
	"io"
	"os"
	"runtime"
	"time"

	"github.com/spf13/cobra"

	clienttelemetry "github.com/tnldotdev/tnl/internal/client/telemetry"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
	installedjobs "github.com/tnldotdev/tnl/internal/installed"
)

type serviceCommand struct {
	Install  serviceInstallCommand
	Start    serviceJobCommand
	Stop     serviceJobCommand
	Remove   serviceJobCommand
	List     serviceListCommand
	Status   serviceJobCommand
	Serve    serviceServeCommand
	Register serviceRegisterCommand
}

type systemStateFlags struct {
	System         bool   `name:"system" help:"Use the unattended system supervisor instead of the user-login supervisor."`
	SystemStateDir string `name:"system-state-dir" type:"path" help:"Private supervisor state directory."`
	User           bool   `name:"user" hidden:"" help:"Run the installed user supervisor."`
}
type serviceInstallCommand struct {
	systemStateFlags `embed:""`
	Binary           string `type:"path" help:"Binary to install; defaults to the running tnl executable."`
}
type serviceJobCommand struct {
	systemStateFlags `embed:""`
	Job              string `arg:"" name:"job" help:"Installed publication name or job ID."`
}
type serviceListCommand struct {
	systemStateFlags `embed:""`
}
type serviceServeCommand struct {
	telemetry        *clienttelemetry.Collector
	systemStateFlags `embed:""`
}
type serviceRegisterCommand struct {
	systemStateFlags `embed:""`
	PrivateResult    bool `name:"private-result" hidden:""`
}

var serviceUserRoot = installedjobs.DefaultUserRoot

func (flags systemStateFlags) root() (string, error) {
	if flags.SystemStateDir != "" {
		return flags.SystemStateDir, nil
	}
	if flags.System {
		return installedjobs.DefaultRoot(runtime.GOOS), nil
	}
	root, err := serviceUserRoot(runtime.GOOS)
	if err != nil {
		return "", failure.Wrap("locate user service state", failure.ClientStateUnavailable, err)
	}
	if root == "" {
		return "", failure.Wrap("locate user service state", failure.ClientStateUnavailable, errors.New("user home directory is unavailable"))
	}
	return root, nil
}

func (flags systemStateFlags) options() (installedjobs.ServiceOptions, error) {
	root, err := flags.root()
	return installedjobs.ServiceOptions{Root: root, User: !flags.System}, err
}

func requireInstalledService(ctx context.Context, options installedjobs.ServiceOptions, executor installedjobs.Executor) error {
	if executor == nil {
		executor = installedjobs.HostExecutor{}
	}
	return installedServiceError(ctx, installedjobs.CheckActiveService(ctx, options, executor))
}

func requireConfiguredService(ctx context.Context, options installedjobs.ServiceOptions, executor installedjobs.Executor) error {
	if executor == nil {
		executor = installedjobs.HostExecutor{}
	}
	return installedServiceError(ctx, installedjobs.CheckService(ctx, options, executor))
}

func installedServiceError(ctx context.Context, err error) error {
	if err == nil || ctx.Err() != nil || err == installedjobs.ErrUnsafeState {
		return err
	}
	return failure.Wrap("check installed service", failure.ServiceNotInstalled, err)
}

func runServiceInstall(ctx context.Context, flags serviceInstallCommand, output io.Writer, executor installedjobs.Executor) error {
	if executor == nil {
		executor = installedjobs.HostExecutor{}
	}
	binary := flags.Binary
	if binary == "" {
		var err error
		binary, err = os.Executable()
		if err != nil {
			return err
		}
	}
	options, err := flags.options()
	if err != nil {
		return err
	}
	options.BinarySource = binary
	if err := installedjobs.InstallService(ctx, options, executor); err != nil {
		return err
	}
	if options.User {
		return writeResult(output, clioutput.Text("Installed the tnl user supervisor."))
	}
	return writeResult(output, clioutput.Text("Installed the tnl system supervisor."))
}

func runServiceStart(ctx context.Context, flags serviceJobCommand, output io.Writer, executor installedjobs.Executor) error {
	options, err := flags.options()
	if err != nil {
		return err
	}
	if executor == nil {
		executor = installedjobs.HostExecutor{}
	}
	if err := requireConfiguredService(ctx, options, executor); err != nil {
		return err
	}
	registry, err := installedjobs.Open(ctx, installedjobs.OpenOptions{Root: options.Root, User: options.User})
	if err != nil {
		return err
	}
	defer registry.Close()
	job, err := registry.ResolveJob(ctx, flags.Job)
	if err != nil {
		return err
	}
	if err := registry.Start(ctx, job.ID); err != nil {
		return err
	}
	if err := installedjobs.StartService(ctx, options, executor); err != nil {
		return err
	}
	return writeSystemJobs(ctx, registry, output, "tnl service start", job.ID)
}

func runServiceStop(ctx context.Context, flags serviceJobCommand, output io.Writer) error {
	options, err := flags.options()
	if err != nil {
		return err
	}
	if err := requireConfiguredService(ctx, options, nil); err != nil {
		return err
	}
	registry, err := installedjobs.Open(ctx, installedjobs.OpenOptions{Root: options.Root, User: options.User})
	if err != nil {
		return err
	}
	defer registry.Close()
	job, err := registry.ResolveJob(ctx, flags.Job)
	if err != nil {
		return err
	}
	if err := registry.Stop(ctx, job.ID); err != nil {
		return err
	}
	return writeSystemJobs(ctx, registry, output, "tnl service stop", job.ID)
}

func runServiceRemove(ctx context.Context, flags serviceJobCommand, output io.Writer) error {
	options, err := flags.options()
	if err != nil {
		return err
	}
	if err := requireConfiguredService(ctx, options, nil); err != nil {
		return err
	}
	registry, err := installedjobs.Open(ctx, installedjobs.OpenOptions{Root: options.Root, User: options.User})
	if err != nil {
		return err
	}
	defer registry.Close()
	job, err := registry.ResolveJob(ctx, flags.Job)
	if err != nil {
		return err
	}
	if err := registry.Stop(ctx, job.ID); err != nil {
		return err
	}
	waitCtx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	if err := registry.WaitStopped(waitCtx, job.ID); err != nil {
		return err
	}
	if err := registry.Remove(ctx, job.ID); err != nil {
		return err
	}
	return writeResult(output, clioutput.Line("Removed "+displayJobName(job)+"."))
}

func runServiceList(ctx context.Context, flags serviceListCommand, output io.Writer) error {
	options, err := flags.options()
	if err != nil {
		return err
	}
	if err := requireConfiguredService(ctx, options, nil); err != nil {
		return err
	}
	registry, err := installedjobs.Open(ctx, installedjobs.OpenOptions{Root: options.Root, User: options.User})
	if err != nil {
		return err
	}
	defer registry.Close()
	return writeSystemJobs(ctx, registry, output, "tnl service list", "")
}

func runServiceStatus(ctx context.Context, flags serviceJobCommand, output io.Writer) error {
	options, err := flags.options()
	if err != nil {
		return err
	}
	if err := requireConfiguredService(ctx, options, nil); err != nil {
		return err
	}
	registry, err := installedjobs.Open(ctx, installedjobs.OpenOptions{Root: options.Root, User: options.User})
	if err != nil {
		return err
	}
	defer registry.Close()
	job, err := registry.ResolveJob(ctx, flags.Job)
	if err != nil {
		return err
	}
	return writeSystemJobs(ctx, registry, output, "tnl service status", job.ID)
}

func runServiceServe(ctx context.Context, flags serviceServeCommand) error {
	return runServiceServeWithUserJobs(ctx, flags, nil)
}

// user publications and connectors share one supervisor and joined shutdown.
func runServiceServeWithUserJobs(ctx context.Context, flags serviceServeCommand, runners []installedjobs.UserJobRunner) error {
	if flags.User && flags.System {
		return installedjobs.ErrScope
	}
	if flags.System && len(runners) != 0 {
		return installedjobs.ErrScope
	}
	options, err := flags.options()
	if err != nil {
		return err
	}
	registry, err := installedjobs.Open(ctx, installedjobs.OpenOptions{Root: options.Root, User: options.User})
	if err != nil {
		return err
	}
	defer registry.Close()
	engine := installedjobs.Engine{Registry: registry, UserJobs: runners, Telemetry: flags.telemetry}
	if options.User {
		engine.Connect = runInstalledConnector
		engine.Deployment = func(ctx context.Context, job installedjobs.Job, telemetry *clienttelemetry.Collector, observe func(int64, bool) error, deadline func() time.Time, shutdown context.Context) error {
			_, private, profile, err := registry.DeploymentIdentity(ctx, job)
			if err != nil {
				return err
			}
			return serveDeploymentPublisherWithDiscovery(ctx, job, profile, private, telemetry, observe, nil, deadline, shutdown)
		}
	}
	return engine.Serve(ctx)
}

func writeSystemJobs(ctx context.Context, registry *installedjobs.Registry, output io.Writer, command, selected string) error {
	jobs, err := registry.List(ctx)
	if err != nil {
		return err
	}
	for i := range jobs {
		if jobs[i].Kind != installedjobs.KindDeployment {
			continue
		}
		member, _, _, err := registry.DeploymentIdentity(ctx, jobs[i])
		if err != nil {
			return err
		}
		jobs[i].DeploymentMember = &member
		jobs[i].Name = member.DeploymentName + "-" + jobs[i].DeploymentInstance
	}
	return renderSystemJobs(output, command, jobs, selected)
}

func renderSystemJobs(output io.Writer, command string, jobs []installedjobs.Job, selected string) error {
	var rows [][]string
	for _, job := range jobs {
		if selected != "" && selected != job.ID {
			continue
		}
		if command == "tnl service stop" {
			return writeJobStopResult(output, job)
		}
		if command == "tnl service start" {
			blocks := []clioutput.Block{clioutput.Line("Requested start for " + displayJobName(job) + "."), clioutput.Line("State: " + string(job.Status.State))}
			if job.Status.Failure != "" {
				blocks = append(blocks, clioutput.Text(job.Status.Failure))
			}
			return writeResult(output, blocks...)
		}
		state := string(job.Status.State)
		detail := job.Status.Address
		if job.Kind == installedjobs.KindConnector {
			detail = job.Target
		}
		if job.Status.Failure != "" {
			detail = job.Status.Failure
		}
		if !job.Enabled && state != "stopped" {
			state += " (stop requested)"
		}
		if command == "tnl service status" {
			fields := []clioutput.Field{{Label: "state", Value: state}, {Label: "job ID", Value: job.ID}}
			if job.ServiceID != "" {
				fields = append(fields, clioutput.Field{Label: "service ID", Value: job.ServiceID}, clioutput.Field{Label: "protocol", Value: string(job.Protocol)})
			}
			if detail != "" {
				label := "address"
				if job.Status.Failure != "" {
					label = "failure"
				} else if job.Kind == installedjobs.KindConnector {
					label = "local address"
				}
				fields = append(fields, clioutput.Field{Label: label, Value: detail, Prose: job.Status.Failure != ""})
			}
			return writeResult(output, clioutput.Section(displayJobName(job), clioutput.Fields(fields...)))
		}
		rows = append(rows, []string{displayJobName(job), job.ID, state, detail})
	}
	if selected != "" && len(rows) == 0 {
		return installedjobs.ErrJobNotFound
	}
	empty := "No installed jobs."
	if command == "tnl connect list" {
		empty = "No installed connectors."
	}
	return writeResult(output, clioutput.Table([]string{"NAME", "JOB ID", "STATE", "DETAIL"}, rows, empty))
}

func writeJobStopResult(output io.Writer, job installedjobs.Job) error {
	if job.Status.State == installedjobs.JobStopped {
		return writeResult(output, clioutput.Line("Stopped "+displayJobName(job)+"."))
	}
	return writeResult(output, clioutput.Line("Requested stop for "+displayJobName(job)+"."))
}

func displayJobName(job installedjobs.Job) string {
	if job.Name != "" {
		return job.Name
	}
	return job.ID
}

func (a *commandApp) newServiceCommand() *cobra.Command {
	f := a.flags
	cService := &cobra.Command{
		Use: "service", Short: "Manage publications installed on this machine.", GroupID: "deploy",
		Long: "Manage background jobs created with --install. Use tnl detached for publications started with --detach, or tnl connect list for installed connectors.",
	}
	cServiceInstall := &cobra.Command{Use: "install", Short: "Install or refresh the supervisor that runs local jobs."}
	a.leaf(cServiceInstall, &f.Service.Install, func(call commandCall) error {
		return runServiceInstall(call.ctx, f.Service.Install, a.out, nil)
	})
	cService.AddCommand(cServiceInstall)
	cServiceStart := &cobra.Command{Use: "start", Short: "Start one installed publication."}
	a.leaf(cServiceStart, &f.Service.Start, func(call commandCall) error {
		return runServiceStart(call.ctx, f.Service.Start, a.out, nil)
	})
	cService.AddCommand(cServiceStart)
	cServiceStop := &cobra.Command{Use: "stop", Short: "Stop one local job without revoking its grant."}
	a.leaf(cServiceStop, &f.Service.Stop, func(call commandCall) error {
		return runServiceStop(call.ctx, f.Service.Stop, a.out)
	})
	cService.AddCommand(cServiceStop)
	cServiceRemove := &cobra.Command{Use: "remove", Short: "Remove a stopped publication and its local job identity."}
	a.leaf(cServiceRemove, &f.Service.Remove, func(call commandCall) error {
		return runServiceRemove(call.ctx, f.Service.Remove, a.out)
	})
	cService.AddCommand(cServiceRemove)
	cServiceList := &cobra.Command{Use: "list", Short: "List installed publications and their run state."}
	a.leaf(cServiceList, &f.Service.List, func(call commandCall) error {
		return runServiceList(call.ctx, f.Service.List, a.out)
	})
	cService.AddCommand(cServiceList)
	cServiceStatus := &cobra.Command{Use: "status", Short: "Show one installed publication and its run state."}
	a.leaf(cServiceStatus, &f.Service.Status, func(call commandCall) error {
		return runServiceStatus(call.ctx, f.Service.Status, a.out)
	})
	cService.AddCommand(cServiceStatus)
	cServiceServe := &cobra.Command{Use: "serve", Short: "Run the enrolled system publisher service.", Hidden: true}
	a.leaf(cServiceServe, &f.Service.Serve, func(call commandCall) error {
		return runServiceServe(call.ctx, f.Service.Serve)
	})
	cService.AddCommand(cServiceServe)
	cServiceRegister := &cobra.Command{Use: "register", Short: "Receive a private publication installation on stdin.", Hidden: true}
	a.leaf(cServiceRegister, &f.Service.Register, func(call commandCall) error {
		return runPublicationRegister(call.ctx, f.Service.Register, os.Stdin, a.out, nil)
	})
	cService.AddCommand(cServiceRegister)
	return cService
}
