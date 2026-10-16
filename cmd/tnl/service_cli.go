package main

import (
	"context"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/publisherjob"
)

type serviceCommand struct {
	Install serviceInstallCommand `cmd:"" help:"Install or refresh the system publisher binary and boot service."`
	Start   serviceJobCommand     `cmd:"" help:"Start one installed system publication."`
	Stop    serviceJobCommand     `cmd:"" help:"Stop one local job without revoking its grant."`
	List    serviceListCommand    `cmd:"" help:"List installed system publications and their native run state."`
	Status  serviceJobCommand     `cmd:"" help:"Show one installed system publication and its run state."`
	Serve   serviceServeCommand   `cmd:"" hidden:"" help:"Run the enrolled system publisher service."`
}

type systemStateFlags struct {
	SystemStateDir string `name:"system-state-dir" type:"path" help:"Private root-owned system publisher state directory."`
}
type serviceInstallCommand struct {
	systemStateFlags `embed:""`
	Binary           string `type:"path" help:"Binary to install; defaults to the running tnl executable."`
}
type serviceJobCommand struct {
	systemStateFlags `embed:""`
	Job              string `arg:"" name:"job" help:"Installed system publisher job name."`
}
type serviceListCommand struct {
	systemStateFlags `embed:""`
}
type serviceServeCommand struct {
	systemStateFlags `embed:""`
}

func (flags systemStateFlags) root() string {
	if flags.SystemStateDir != "" {
		return flags.SystemStateDir
	}
	return publisherjob.DefaultRoot(runtime.GOOS)
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
	if err := publisherjob.InstallService(ctx, publisherjob.ServiceOptions{Root: flags.root(), BinarySource: binary}, executor); err != nil {
		return err
	}
	return writeHumanFrame(output, "tnl service install", "installed", "", clioutput.Fields(clioutput.Field{Label: "state directory", Value: flags.root()}))
}

func runServiceStart(ctx context.Context, flags serviceJobCommand, output io.Writer, executor publisherjob.Executor) error {
	registry, err := publisherjob.Open(ctx, publisherjob.OpenOptions{Root: flags.root()})
	if err != nil {
		return err
	}
	defer registry.Close()
	if err := registry.Start(ctx, flags.Job); err != nil {
		return err
	}
	if executor == nil {
		executor = publisherjob.HostExecutor{}
	}
	if err := publisherjob.StartService(ctx, publisherjob.ServiceOptions{Root: flags.root()}, executor); err != nil {
		return err
	}
	return writeSystemJobs(ctx, registry, output, "tnl service start", flags.Job)
}

func runServiceStop(ctx context.Context, flags serviceJobCommand, output io.Writer) error {
	registry, err := publisherjob.Open(ctx, publisherjob.OpenOptions{Root: flags.root()})
	if err != nil {
		return err
	}
	defer registry.Close()
	if err := registry.Stop(ctx, flags.Job); err != nil {
		return err
	}
	return writeSystemJobs(ctx, registry, output, "tnl service stop", flags.Job)
}

func runServiceList(ctx context.Context, flags serviceListCommand, output io.Writer) error {
	registry, err := publisherjob.Open(ctx, publisherjob.OpenOptions{Root: flags.root()})
	if err != nil {
		return err
	}
	defer registry.Close()
	return writeSystemJobs(ctx, registry, output, "tnl service list", "")
}

func runServiceStatus(ctx context.Context, flags serviceJobCommand, output io.Writer) error {
	registry, err := publisherjob.Open(ctx, publisherjob.OpenOptions{Root: flags.root()})
	if err != nil {
		return err
	}
	defer registry.Close()
	return writeSystemJobs(ctx, registry, output, "tnl service status", flags.Job)
}

func runServiceServe(ctx context.Context, flags serviceServeCommand) error {
	registry, err := publisherjob.Open(ctx, publisherjob.OpenOptions{Root: flags.root()})
	if err != nil {
		return err
	}
	defer registry.Close()
	return (publisherjob.Engine{Registry: registry}).Serve(ctx)
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
		fields := []clioutput.Field{{Label: "job", Value: job.ID}, {Label: "server", Value: job.Server}, {Label: "public URL", Value: job.PublicURLID}, {Label: "publisher", Value: job.PublisherID}, {Label: "protocol", Value: string(job.Protocol)}, {Label: "desired", Value: desired}, {Label: "state", Value: job.Status.State}}
		if len(job.SSHUsers) != 0 {
			fields = append(fields, clioutput.Field{Label: "accounts", Value: strings.Join(job.SSHUsers, ", ")})
		}
		if job.Status.PublishRunNumber != 0 {
			fields = append(fields, clioutput.Field{Label: "publish run", Value: strconv.FormatUint(job.Status.PublishRunNumber, 10)})
		}
		if job.Status.Failure != "" {
			fields = append(fields, clioutput.Field{Label: "failure", Value: job.Status.Failure})
		}
		blocks = append(blocks, clioutput.Section(job.ID, clioutput.Fields(fields...)))
	}
	if selected != "" && len(blocks) == 0 {
		return publisherjob.ErrJobNotFound
	}
	return writeHumanFrame(output, command, state, "", blocks...)
}
