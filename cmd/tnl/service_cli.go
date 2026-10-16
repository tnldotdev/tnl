package main

import (
	"context"
	"errors"
	"io"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/publisherjob"
)

// parent wiring: add Service serviceCommand to the root CLI and dispatch each
// command to its matching runService* handler. main owns SIGINT/SIGTERM context.
type serviceCommand struct {
	Install serviceInstallCommand `cmd:"" help:"Install or refresh the user-login publisher supervisor (or system publisher supervisor with --system)."`
	Start   serviceJobCommand     `cmd:"" help:"Start one installed publication."`
	Stop    serviceJobCommand     `cmd:"" help:"Stop one local job without revoking its grant."`
	Remove  serviceJobCommand     `cmd:"" help:"Remove a stopped publication and its local job identity."`
	List    serviceListCommand    `cmd:"" help:"List installed publications and their run state."`
	Serve   serviceServeCommand   `cmd:"" hidden:"" help:"Run the enrolled system publisher service."`
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
	systemStateFlags `embed:""`
}

var serviceUserRoot = publisherjob.DefaultUserRoot

func (flags systemStateFlags) root() (string, error) {
	if flags.SystemStateDir != "" {
		return flags.SystemStateDir, nil
	}
	if flags.System {
		return publisherjob.DefaultRoot(runtime.GOOS), nil
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

func (flags systemStateFlags) options() (publisherjob.ServiceOptions, error) {
	root, err := flags.root()
	return publisherjob.ServiceOptions{Root: root, User: !flags.System}, err
}

func requireInstalledService(ctx context.Context, options publisherjob.ServiceOptions, executor publisherjob.Executor) error {
	if executor == nil {
		executor = publisherjob.HostExecutor{}
	}
	return installedServiceError(ctx, publisherjob.CheckActiveService(ctx, options, executor))
}

func requireConfiguredService(ctx context.Context, options publisherjob.ServiceOptions, executor publisherjob.Executor) error {
	if executor == nil {
		executor = publisherjob.HostExecutor{}
	}
	return installedServiceError(ctx, publisherjob.CheckService(ctx, options, executor))
}

func installedServiceError(ctx context.Context, err error) error {
	if err == nil || ctx.Err() != nil || err == publisherjob.ErrUnsafeState {
		return err
	}
	return failure.Wrap("check installed service", failure.ServiceNotInstalled, err)
}

func runServiceInstall(ctx context.Context, flags serviceInstallCommand, output io.Writer, executor publisherjob.Executor) error {
	if executor == nil {
		executor = publisherjob.HostExecutor{}
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
	if err := publisherjob.InstallService(ctx, options, executor); err != nil {
		return err
	}
	return writeHumanFrame(output, "tnl service install", "installed", "", clioutput.Fields(clioutput.Field{Label: "state directory", Value: options.Root}))
}

func runServiceStart(ctx context.Context, flags serviceJobCommand, output io.Writer, executor publisherjob.Executor) error {
	options, err := flags.options()
	if err != nil {
		return err
	}
	if executor == nil {
		executor = publisherjob.HostExecutor{}
	}
	if err := requireConfiguredService(ctx, options, executor); err != nil {
		return err
	}
	registry, err := publisherjob.Open(ctx, publisherjob.OpenOptions{Root: options.Root, User: options.User})
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
	if err := publisherjob.StartService(ctx, options, executor); err != nil {
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
	registry, err := publisherjob.Open(ctx, publisherjob.OpenOptions{Root: options.Root, User: options.User})
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
	registry, err := publisherjob.Open(ctx, publisherjob.OpenOptions{Root: options.Root, User: options.User})
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
	waitCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := registry.WaitStopped(waitCtx, job.ID); err != nil {
		return err
	}
	if err := registry.Remove(ctx, job.ID); err != nil {
		return err
	}
	return writeHumanFrame(output, "tnl service remove", "removed", "", clioutput.Fields(clioutput.Field{Label: "name", Value: displayJobName(job)}, clioutput.Field{Label: "job ID", Value: job.ID}))
}

func runServiceList(ctx context.Context, flags serviceListCommand, output io.Writer) error {
	options, err := flags.options()
	if err != nil {
		return err
	}
	if err := requireConfiguredService(ctx, options, nil); err != nil {
		return err
	}
	registry, err := publisherjob.Open(ctx, publisherjob.OpenOptions{Root: options.Root, User: options.User})
	if err != nil {
		return err
	}
	defer registry.Close()
	return writeSystemJobs(ctx, registry, output, "tnl service list", "")
}

func runServiceServe(ctx context.Context, flags serviceServeCommand) error {
	return runServiceServeWithUserJobs(ctx, flags, nil)
}

// #386 can attach a user connector runner here when its own registry and
// credentials exist. no connector CLI installation is exposed until then.
func runServiceServeWithUserJobs(ctx context.Context, flags serviceServeCommand, runners []publisherjob.UserJobRunner) error {
	if flags.User && flags.System {
		return publisherjob.ErrScope
	}
	if flags.System && len(runners) != 0 {
		return publisherjob.ErrScope
	}
	options, err := flags.options()
	if err != nil {
		return err
	}
	registry, err := publisherjob.Open(ctx, publisherjob.OpenOptions{Root: options.Root, User: options.User})
	if err != nil {
		return err
	}
	defer registry.Close()
	return (publisherjob.Engine{Registry: registry, UserJobs: runners}).Serve(ctx)
}

func writeSystemJobs(ctx context.Context, registry *publisherjob.Registry, output io.Writer, command, selected string) error {
	jobs, err := registry.List(ctx)
	if err != nil {
		return err
	}
	return renderSystemJobs(output, command, jobs, selected)
}

func renderSystemJobs(output io.Writer, command string, jobs []publisherjob.Job, selected string) error {
	blocks := []clioutput.Block{}
	state := "no jobs"
	for _, job := range jobs {
		if selected != "" && selected != job.ID {
			continue
		}
		state = "installed"
		if selected != "" {
			state = job.Status.State
		}
		desired := "stopped"
		if job.Enabled {
			desired = "running"
		}
		fields := []clioutput.Field{{Label: "name", Value: displayJobName(job)}, {Label: "job ID", Value: job.ID}, {Label: "server", Value: job.Server}, {Label: "public URL", Value: job.PublicURLID}, {Label: "publisher", Value: job.PublisherID}, {Label: "protocol", Value: string(job.Protocol)}, {Label: "desired", Value: desired}, {Label: "state", Value: job.Status.State}}
		if job.Status.PublishRunNumber != 0 {
			fields = append(fields, clioutput.Field{Label: "publish run", Value: strconv.FormatUint(job.Status.PublishRunNumber, 10)})
		}
		if job.Status.Failure != "" {
			fields = append(fields, clioutput.Field{Label: "failure", Value: job.Status.Failure})
		}
		blocks = append(blocks, clioutput.Section(displayJobName(job), clioutput.Fields(fields...)))
	}
	return writeHumanFrame(output, command, state, "", blocks...)
}

func displayJobName(job publisherjob.Job) string {
	if job.Name != "" {
		return job.Name
	}
	return job.ID
}
