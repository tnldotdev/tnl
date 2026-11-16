package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	clienttelemetry "github.com/tnldotdev/tnl/internal/client/telemetry"
	"github.com/tnldotdev/tnl/internal/clioutput"
	installedjobs "github.com/tnldotdev/tnl/internal/installed"
	"github.com/tnldotdev/tnl/internal/publisher/identity/credentialfile"
)

func (f publisherServeCommand) fixedList() bool {
	return len(f.IdentityFile) > 1 || len(f.BindingFile) > 0 || len(f.IdentityFile) == 1 && f.Deployment == ""
}

func validateFixedDeploymentRuntime(f publisherServeCommand) error {
	if len(f.IdentityFile) < 1 || len(f.IdentityFile) > 256 || len(f.BindingFile) > len(f.IdentityFile) {
		return publisherCLIError("select from 1 to 256 --identity-file inputs and at most one --binding-file per identity")
	}
	if f.Deployment != "" || f.ProjectKey != "" || f.ServerURL != "" || f.Team != "" || f.AccessToken != "" || f.EnrollmentKey != "" || f.Instance != "" && f.Instance != "default" {
		return publisherCLIError("fixed-list publishers use each identity's server, team, deployment, project, and instance; omit selection and enrollment overrides")
	}
	if f.Detach || f.Install || f.System || f.SystemStateDir != "" || f.DetachedChild != "" {
		return publisherCLIError("run fixed-list publishers in the foreground under your process supervisor")
	}
	if _, present := os.LookupEnv("TNL_DEPLOYMENT_IDENTITY"); present {
		return publisherCLIError("fixed-list publishers require --identity-file inputs; remove TNL_DEPLOYMENT_IDENTITY")
	}
	if f.StateDir == "" || f.IdentityDir == "" {
		return publisherCLIError("fixed-list publishers require --state-dir and --identity-dir")
	}
	return nil
}

type fixedDeploymentInput struct {
	value  credentialfile.DeploymentFile
	runner installedjobs.DeploymentRunner
	job    installedjobs.Job
}

// all local input and duplicate ownership checks finish before the engine can
// contact control. a remote failure thereafter belongs to its individual job.
func readFixedDeploymentRuntime(f publisherServeCommand) ([]fixedDeploymentInput, error) {
	if err := validateFixedDeploymentRuntime(f); err != nil {
		return nil, err
	}
	bindings := map[installedjobs.DeploymentScope]installedjobs.DeploymentBinding{}
	for _, path := range f.BindingFile {
		binding, err := installedjobs.ReadDeploymentBinding(path)
		if err != nil {
			return nil, err
		}
		if _, duplicate := bindings[binding.Scope]; duplicate {
			return nil, installedjobs.ErrJobExists
		}
		bindings[binding.Scope] = binding
	}
	startup, providers := installedjobs.NewOperationLimiter(4), installedjobs.NewOperationLimiter(8)
	seenPublishers, seenReplicas := map[string]bool{}, map[string]bool{}
	inputs := make([]fixedDeploymentInput, 0, len(f.IdentityFile))
	for _, path := range f.IdentityFile {
		value, err := credentialfile.ReadDeployment(path)
		if err != nil {
			return nil, err
		}
		publisherKey := installedjobs.JobKey(value.ControlURL, "publisher", value.Member.PublisherIdentityId)
		replicaKey := installedjobs.JobKey(value.ControlURL, "deployment", value.Member.DeploymentId+":"+value.Instance)
		if seenPublishers[publisherKey] || seenReplicas[replicaKey] {
			return nil, installedjobs.ErrJobExists
		}
		seenPublishers[publisherKey], seenReplicas[replicaKey] = true, true
		scope := installedjobs.ScopeForDeployment(value)
		var selected *installedjobs.DeploymentBinding
		if binding, found := bindings[scope]; found {
			selected = &binding
			delete(bindings, scope)
		}
		runner, trust, err := installedjobs.ScopedDeploymentRunner(value, selected, startup, providers)
		if err != nil {
			return nil, err
		}
		job := installedjobs.Job{Kind: installedjobs.KindDeployment, ID: replicaKey, Name: value.Member.DeploymentName + "-" + value.Instance, Server: value.ControlURL, PublisherIdentityID: value.Member.PublisherIdentityId, DeploymentMember: &value.Member, DeploymentInstance: value.Instance, ServerCAPEM: trust}
		inputs = append(inputs, fixedDeploymentInput{value, runner, job})
	}
	if len(bindings) != 0 {
		return nil, installedjobs.ErrScope
	}
	return inputs, nil
}

func runFixedDeploymentRuntime(ctx context.Context, flags publisherServeCommand, diagnostics io.Writer) error {
	inputs, err := readFixedDeploymentRuntime(flags)
	if err != nil {
		return err
	}
	root, err := filepath.Abs(flags.StateDir)
	if err != nil {
		return err
	}
	registry, err := installedjobs.Open(ctx, installedjobs.OpenOptions{Root: root, StandaloneDeployments: true})
	if err != nil {
		return err
	}
	defer registry.Close()
	runners := map[string]installedjobs.DeploymentRunner{}
	var jobs []installedjobs.DeploymentInstall
	for _, input := range inputs {
		private, err := input.value.Validate(input.value.ControlURL, input.value.Member.ProjectKey, input.value.Member.DeploymentName, input.value.Instance)
		if err != nil {
			return err
		}
		profile, err := registry.Profile(ctx, input.job.Server)
		if err != nil {
			return err
		}
		profile, err = profile.WithIdentityDirectory(flags.IdentityDir)
		if err != nil {
			return err
		}
		input.job.IdentityDir = profile.IdentityDirectory()
		input.job.TelemetryDisabled = flags.telemetryDisabled
		jobs = append(jobs, installedjobs.DeploymentInstall{Job: input.job, Private: private})
		runners[input.job.ID] = input.runner
	}
	var outputMu sync.Mutex
	engine := installedjobs.Engine{Telemetry: flags.telemetry, Registry: registry, Initialize: func(ctx context.Context) error { return registry.ReplaceDeployments(ctx, jobs) }, Deployment: func(ctx context.Context, job installedjobs.Job, telemetry *clienttelemetry.Collector, observe func(int64, bool) error) error {
		_, private, profile, err := registry.DeploymentIdentity(ctx, job)
		if err != nil {
			return err
		}
		runner := runners[job.ID]
		runner.Telemetry = telemetry
		return runner.Serve(ctx, job, profile, private, observe)
	}, Observe: func(job installedjobs.Job, status installedjobs.Status) error {
		outputMu.Lock()
		defer outputMu.Unlock()
		fields := []clioutput.Field{{Label: "job ID", Value: job.ID}, {Label: "server", Value: job.Server}, {Label: "team ID", Value: job.DeploymentMember.TeamId}, {Label: "deployment ID", Value: job.DeploymentMember.DeploymentId}, {Label: "publisher", Value: job.PublisherIdentityID}, {Label: "instance", Value: job.DeploymentInstance}, {Label: "observed revision", Value: strconv.FormatInt(status.ObservedRevision, 10)}}
		if status.Failure != "" {
			fields = append(fields, clioutput.Field{Label: "failure", Value: status.Failure})
		}
		return writeHumanFrame(diagnostics, "tnl publisher serve", string(status.State), "", clioutput.Fields(fields...))
	}}
	return engine.Serve(ctx)
}
