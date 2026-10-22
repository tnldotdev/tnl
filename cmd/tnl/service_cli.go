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

type serviceCommand struct {
	Install  serviceInstallCommand  `cmd:"" help:"Install or refresh the user-login publisher supervisor (or system publisher supervisor with --system)."`
	Start    serviceJobCommand      `cmd:"" help:"Start one installed publication."`
	Stop     serviceJobCommand      `cmd:"" help:"Stop one local job without revoking its grant."`
	Remove   serviceJobCommand      `cmd:"" help:"Remove a stopped publication and its local job identity."`
	List     serviceListCommand     `cmd:"" help:"List installed publications and their run state."`
	Status   serviceJobCommand      `cmd:"" help:"Show one installed publication and its run state."`
	Serve    serviceServeCommand    `cmd:"" hidden:"" help:"Run the enrolled system publisher service."`
	Register serviceRegisterCommand `cmd:"" hidden:"" help:"Receive a private publication installation on stdin."`
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
type serviceRegisterCommand struct {
	systemStateFlags `embed:""`
	PrivateResult    bool `name:"private-result" hidden:""`
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
	waitCtx, cancel := context.WithTimeout(ctx, time.Minute)
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

func runServiceStatus(ctx context.Context, flags serviceJobCommand, output io.Writer) error {
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
	return writeSystemJobs(ctx, registry, output, "tnl service status", job.ID)
}

func runServiceServe(ctx context.Context, flags serviceServeCommand) error {
	return runServiceServeWithUserJobs(ctx, flags, nil)
}

// user publications and connectors share one supervisor and joined shutdown.
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
	engine := publisherjob.Engine{Registry: registry, UserJobs: runners}
	if options.User {
		engine.Connect = runInstalledConnector
		engine.Group = func(ctx context.Context, job publisherjob.Job, observe func(int64, bool) error) error {
			_, private, profile, err := registry.GroupIdentity(ctx, job)
			if err != nil {
				return err
			}
			return servePublisherGroup(ctx, job, profile, private, observe)
		}
	}
	return engine.Serve(ctx)
}

func writeSystemJobs(ctx context.Context, registry *publisherjob.Registry, output io.Writer, command, selected string) error {
	jobs, err := registry.List(ctx)
	if err != nil {
		return err
	}
	for i := range jobs {
		if jobs[i].Kind != publisherjob.KindGroup {
			continue
		}
		member, _, _, err := registry.GroupIdentity(ctx, jobs[i])
		if err != nil {
			return err
		}
		jobs[i].GroupMember = &member
		jobs[i].Name = member.GroupName + "-" + jobs[i].GroupInstance
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
			state = string(job.Status.State)
		}
		desired := "stopped"
		if job.Enabled {
			desired = "running"
		}
		fields := []clioutput.Field{{Label: "name", Value: displayJobName(job)}, {Label: "job ID", Value: job.ID}, {Label: "server", Value: job.Server}, {Label: "protocol", Value: string(job.Protocol)}, {Label: "desired", Value: desired}, {Label: "state", Value: string(job.Status.State)}}
		if job.Kind == "group" && job.GroupMember != nil {
			fields = append(fields, clioutput.Field{Label: "group", Value: job.GroupMember.GroupName}, clioutput.Field{Label: "project key", Value: job.GroupMember.ProjectKey}, clioutput.Field{Label: "observed revision", Value: strconv.FormatInt(job.Status.ObservedRevision, 10)})
		} else if job.Kind == "private" || job.Kind == "connector" {
			fields = append(fields, clioutput.Field{Label: "private service ID", Value: job.PrivateServiceID})
		} else {
			fields = append(fields, clioutput.Field{Label: "public URL ID", Value: job.PublicURLID})
			if job.Status.PublicURL != "" {
				fields = append(fields, clioutput.Field{Label: "public URL", Value: job.Status.PublicURL})
			}
		}
		if job.Kind == "connector" {
			fields = append(fields, clioutput.Field{Label: "listen", Value: job.Target})
		} else {
			fields = append(fields, clioutput.Field{Label: "publisher", Value: job.PublisherID})
		}
		if job.Status.PublishRunNumber != 0 {
			fields = append(fields, clioutput.Field{Label: "publish run", Value: strconv.FormatUint(job.Status.PublishRunNumber, 10)})
		}
		if job.Status.Failure != "" {
			fields = append(fields, clioutput.Field{Label: "failure", Value: job.Status.Failure})
		}
		blocks = append(blocks, clioutput.Section(displayJobName(job), clioutput.Fields(fields...)))
	}
	if selected != "" && len(blocks) == 0 {
		return publisherjob.ErrJobNotFound
	}
	return writeHumanFrame(output, command, state, "", blocks...)
}

func displayJobName(job publisherjob.Job) string {
	if job.Name != "" {
		return job.Name
	}
	return job.ID
}
