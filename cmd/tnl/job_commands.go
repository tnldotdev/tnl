package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"

	"github.com/spf13/cobra"
	"github.com/tnldotdev/tnl/internal/client/background"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
	installedjobs "github.com/tnldotdev/tnl/internal/installed"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

type stopCommand struct {
	JobID          string           `arg:"" name:"job-id" help:"Exact job ID from tnl status --bg."`
	StateDir       string           `name:"state-dir" env:"TNL_STATE_DIR" type:"path" help:"Client state directory."`
	System         bool             `name:"system" help:"Select the installed system supervisor instead of user jobs."`
	SystemStateDir string           `name:"system-state-dir" type:"path" help:"Private supervisor state directory."`
	Output         statusOutputMode `name:"output" enum:"human,json" default:"human" help:"Output format: ${enum}."`
}

type jobStatusOptions struct {
	JobID          string
	StateDir       string
	System         bool
	SystemStateDir string
	Output         statusOutputMode
}

// jobStatus is the public observation, not an installed definition or a child
// startup receipt. Neither credentials nor target configuration belong in it.
type jobStatus struct {
	JobID        string `json:"job_id"`
	Name         string `json:"name,omitempty"`
	Mode         string `json:"mode"`
	Kind         string `json:"kind"`
	State        string `json:"state"`
	Scope        string `json:"scope"`
	Enabled      *bool  `json:"enabled,omitempty"`
	ServiceID    string `json:"service_id,omitempty"`
	Protocol     string `json:"protocol,omitempty"`
	Target       string `json:"target,omitempty"`
	TunnelID     string `json:"tunnel_id,omitempty"`
	Address      string `json:"address,omitempty"`
	LocalAddress string `json:"local_address,omitempty"`
	Failure      string `json:"failure,omitempty"`
}

func validJobID(id string) bool { return opaqueid.Valid(id, opaqueid.JobPrefix) }

func bindExactJobID(command *cobra.Command, id func() string) {
	bind := command.Args
	command.Args = func(cmd *cobra.Command, args []string) error {
		if err := bind(cmd, args); err != nil {
			return err
		}
		if !validJobID(id()) {
			return requireJobID()
		}
		return nil
	}
}

func requireJobID() error {
	const message = "Pass an exact job ID."
	return &commandGuidance{error: failure.Wrap("select job", failure.InvalidCommand, errors.New(message)), message: message,
		help: []string{"tnl", "status", "--bg"}}
}

func (a *commandApp) newStopCommand() *cobra.Command {
	flags := &a.flags.Stop
	command := &cobra.Command{
		Use: "stop", Short: "Stop a background or installed job.", GroupID: "start",
		Long: "Stop the job with this exact ID. An installed job stays available for tnl service start and keeps its local credentials or port assignment.",
	}
	a.leaf(command, flags, func(call commandCall) error {
		return runStopJob(call.ctx, *flags, a.out)
	})
	bindExactJobID(command, func() string { return flags.JobID })
	return command
}

func runJobStatus(ctx context.Context, options jobStatusOptions, output io.Writer) error {
	if options.JobID != "" {
		if !validJobID(options.JobID) {
			return requireJobID()
		}
		if !options.System {
			root, err := clientStateRoot(options.StateDir)
			if err != nil {
				return err
			}
			entry, err := background.Status(ctx, root, options.JobID)
			if err == nil {
				return writeSelectedJobStatus(output, options.Output, backgroundJobStatus(entry))
			}
			if !errors.Is(err, background.ErrNotFound) {
				return err
			}
		}
		registry, err := options.openInstalled(ctx)
		if err != nil {
			return options.lookupError(err)
		}
		defer registry.Close()
		job, err := registry.ResolveJob(ctx, options.JobID)
		if err != nil {
			return options.lookupError(err)
		}
		return writeInstalledJobStatus(ctx, registry, options.Output, options.System, output, job)
	}

	jobs := []jobStatus{}
	if !options.System {
		root, err := clientStateRoot(options.StateDir)
		if err != nil {
			return err
		}
		entries, err := background.List(ctx, root)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			jobs = append(jobs, backgroundJobStatus(entry))
		}
	}
	registry, err := options.openInstalled(ctx)
	switch {
	case err == nil:
		defer registry.Close()
		entries, err := registry.List(ctx)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			job, err := readInstalledJobStatus(ctx, registry, entry, options.System)
			if err != nil {
				return err
			}
			jobs = append(jobs, job)
		}
	case !errors.Is(err, installedjobs.ErrRegistryMissing):
		return err
	}
	slices.SortFunc(jobs, func(a, b jobStatus) int { return cmp.Compare(a.JobID, b.JobID) })
	return writeJobList(output, options.Output, jobs)
}

func (options jobStatusOptions) openInstalled(ctx context.Context) (*installedjobs.Registry, error) {
	service, err := (systemStateFlags{System: options.System, SystemStateDir: options.SystemStateDir}).options()
	if err != nil {
		return nil, err
	}
	return installedjobs.OpenExisting(ctx, installedjobs.OpenOptions{Root: service.Root, User: service.User})
}

func (options jobStatusOptions) lookupError(err error) error {
	if !errors.Is(err, installedjobs.ErrRegistryMissing) && !errors.Is(err, installedjobs.ErrJobNotFound) {
		return err
	}
	help := []string{"tnl", "status", "--bg"}
	if options.System {
		help = append(help, "--system")
	} else if options.StateDir != "" {
		help = append(help, "--state-dir", options.StateDir)
	}
	if options.SystemStateDir != "" {
		help = append(help, "--system-state-dir", options.SystemStateDir)
	}
	return &commandGuidance{error: installedjobs.ErrJobNotFound, message: "No job with that ID in the selected scope.", help: help}
}

func runStopJob(ctx context.Context, flags stopCommand, output io.Writer) error {
	if !validJobID(flags.JobID) {
		return requireJobID()
	}
	if !flags.System {
		root, err := clientStateRoot(flags.StateDir)
		if err != nil {
			return err
		}
		entry, err := background.Stop(ctx, root, flags.JobID)
		if err == nil {
			return writeStopJobResult(output, flags.Output, entry.JobID, string(entry.State))
		}
		if !errors.Is(err, background.ErrNotFound) {
			return err
		}
	}
	options := jobStatusOptions{StateDir: flags.StateDir, System: flags.System, SystemStateDir: flags.SystemStateDir}
	registry, err := options.openInstalled(ctx)
	if err != nil {
		return options.lookupError(err)
	}
	defer registry.Close()
	job, err := registry.StopJob(ctx, flags.JobID)
	if err != nil {
		return options.lookupError(err)
	}
	return writeStopJobResult(output, flags.Output, job.ID, string(job.Status.State))
}

func backgroundJobStatus(entry background.Entry) jobStatus {
	job := jobStatus{JobID: entry.JobID, Mode: "background", Scope: "user", Kind: string(entry.Kind), State: string(entry.State), TunnelID: entry.TunnelID, ServiceID: entry.ServiceID, Target: entry.Target}
	if entry.Kind == background.KindConnect {
		job.LocalAddress = entry.Address
	} else {
		job.Address = entry.Address
	}
	return job
}

func readInstalledJobStatus(ctx context.Context, registry *installedjobs.Registry, entry installedjobs.Job, system bool) (jobStatus, error) {
	if entry.Kind == installedjobs.KindDeployment {
		member, _, _, err := registry.DeploymentIdentity(ctx, entry)
		if err != nil {
			return jobStatus{}, err
		}
		entry.Name = member.DeploymentName + "-" + entry.DeploymentInstance
	}
	return installedJobStatus(entry, system), nil
}

func installedJobStatus(entry installedjobs.Job, system bool) jobStatus {
	scope := "user"
	if system {
		scope = "system"
	}
	state := string(entry.Status.State)
	if state == "" {
		state = "unobserved"
	}
	job := jobStatus{JobID: entry.ID, Name: entry.Name, Mode: "installed", Scope: scope, Kind: string(entry.Kind),
		State: state, Enabled: &entry.Enabled, ServiceID: entry.ServiceID, Protocol: string(entry.Protocol), Failure: entry.Status.Failure}
	if entry.Kind == installedjobs.KindConnector {
		job.LocalAddress = entry.Target
	} else {
		job.Address = entry.Status.Address
	}
	return job
}

func writeInstalledJobStatus(ctx context.Context, registry *installedjobs.Registry, mode statusOutputMode, system bool, output io.Writer, entry installedjobs.Job) error {
	job, err := readInstalledJobStatus(ctx, registry, entry, system)
	if err != nil {
		return err
	}
	return writeSelectedJobStatus(output, mode, job)
}

func (job jobStatus) displayState() string {
	if job.Enabled != nil && !*job.Enabled && job.State != "stopped" && job.State != "stopping" {
		return job.State + " (stop requested)"
	}
	return job.State
}

func (job jobStatus) detail() (label, value string) {
	switch {
	case job.Failure != "":
		return "failure", job.Failure
	case job.LocalAddress != "":
		return "local address", job.LocalAddress
	default:
		return "address", job.Address
	}
}

func writeJobList(output io.Writer, mode statusOutputMode, jobs []jobStatus) error {
	if mode == statusOutputJSON {
		return json.NewEncoder(output).Encode(struct {
			SchemaVersion int         `json:"schema_version"`
			Jobs          []jobStatus `json:"jobs"`
		}{1, jobs})
	}
	rows := make([][]string, 0, len(jobs))
	for _, job := range jobs {
		_, detail := job.detail()
		rows = append(rows, []string{job.JobID, cmp.Or(job.Name, job.Target, job.ServiceID), job.Kind, job.Mode, job.displayState(), detail})
	}
	return writeResult(output, clioutput.Table([]string{"JOB ID", "SERVICE OR TARGET", "KIND", "MODE", "STATE", "DETAIL"}, rows, "No background or installed jobs."))
}

func writeSelectedJobStatus(output io.Writer, mode statusOutputMode, job jobStatus) error {
	if mode == statusOutputJSON {
		return json.NewEncoder(output).Encode(struct {
			SchemaVersion int `json:"schema_version"`
			jobStatus
		}{1, job})
	}
	stateLabel := "state"
	if job.Mode == "installed" {
		stateLabel = "last observed state"
	}
	fields := []clioutput.Field{{Label: stateLabel, Value: job.displayState()}, {Label: "job ID", Value: job.JobID},
		{Label: "kind", Value: job.Kind}, {Label: "mode", Value: job.Mode}, {Label: "scope", Value: job.Scope}}
	if job.Name != "" {
		fields = append(fields, clioutput.Field{Label: "name", Value: job.Name})
	}
	if job.Target != "" {
		fields = append(fields, clioutput.Field{Label: "target", Value: job.Target})
	}
	if job.ServiceID != "" {
		fields = append(fields, clioutput.Field{Label: "service ID", Value: job.ServiceID})
	}
	if job.Protocol != "" {
		fields = append(fields, clioutput.Field{Label: "protocol", Value: job.Protocol})
	}
	if label, detail := job.detail(); detail != "" {
		fields = append(fields, clioutput.Field{Label: label, Value: detail, Prose: label == "failure"})
	}
	return writeResult(output, clioutput.Fields(fields...))
}

func writeStopJobResult(output io.Writer, mode statusOutputMode, id, state string) error {
	if mode == statusOutputJSON {
		return json.NewEncoder(output).Encode(struct {
			SchemaVersion int    `json:"schema_version"`
			JobID         string `json:"job_id"`
			State         string `json:"state"`
		}{1, id, state})
	}
	if state == "stopped" {
		return writeResult(output, clioutput.Line("Stopped "+id+"."))
	}
	return writeResult(output, clioutput.Line("Requested stop for "+id+"."))
}
