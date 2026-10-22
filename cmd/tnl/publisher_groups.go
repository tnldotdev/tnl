package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/tnldotdev/tnl/internal/client/supervisor"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/publisher/identity/credentialfile"
)

func (f publisherServeCommand) fixedList() bool {
	return len(f.IdentityFile) > 1 || len(f.BindingFile) > 0 || len(f.IdentityFile) == 1 && f.Group == ""
}

func validateFixedPublisherGroups(f publisherServeCommand) error {
	if len(f.IdentityFile) < 1 || len(f.IdentityFile) > 256 || len(f.BindingFile) > len(f.IdentityFile) {
		return publisherCLIError("select from 1 to 256 --identity-file inputs and at most one --binding-file per identity")
	}
	if f.Group != "" || f.ProjectKey != "" || f.ServerURL != "" || f.Team != "" || f.AccessToken != "" || f.EnrollmentKey != "" || f.Instance != "" && f.Instance != "default" {
		return publisherCLIError("fixed-list publishers use each identity's server, team, group, project, and instance; omit selection and enrollment overrides")
	}
	if f.Detach || f.Install || f.System || f.SystemStateDir != "" || f.DetachedChild != "" {
		return publisherCLIError("run fixed-list publishers in the foreground under your process supervisor")
	}
	if _, present := os.LookupEnv("TNL_GROUP_IDENTITY"); present {
		return publisherCLIError("fixed-list publishers require --identity-file inputs; remove TNL_GROUP_IDENTITY")
	}
	if f.StateDir == "" || f.IdentityDir == "" {
		return publisherCLIError("fixed-list publishers require --state-dir and --identity-dir")
	}
	return nil
}

type fixedGroupInput struct {
	value  credentialfile.GroupFile
	runner supervisor.GroupRunner
	job    supervisor.Job
}

// all local input and duplicate ownership checks finish before the engine can
// contact control. a remote failure thereafter belongs to its individual job.
func readFixedPublisherGroups(f publisherServeCommand) ([]fixedGroupInput, error) {
	if err := validateFixedPublisherGroups(f); err != nil {
		return nil, err
	}
	bindings := map[supervisor.GroupScope]supervisor.GroupBinding{}
	for _, path := range f.BindingFile {
		binding, err := supervisor.ReadGroupBinding(path)
		if err != nil {
			return nil, err
		}
		if _, duplicate := bindings[binding.Scope]; duplicate {
			return nil, supervisor.ErrJobExists
		}
		bindings[binding.Scope] = binding
	}
	startup, providers := supervisor.NewOperationLimiter(4), supervisor.NewOperationLimiter(8)
	seenPublishers, seenReplicas := map[string]bool{}, map[string]bool{}
	inputs := make([]fixedGroupInput, 0, len(f.IdentityFile))
	for _, path := range f.IdentityFile {
		value, err := credentialfile.ReadGroup(path)
		if err != nil {
			return nil, err
		}
		publisherKey := supervisor.JobKey(value.ControlURL, "publisher", value.Member.PublisherIdentityId)
		replicaKey := supervisor.JobKey(value.ControlURL, "group", value.Member.GroupId+":"+value.Instance)
		if seenPublishers[publisherKey] || seenReplicas[replicaKey] {
			return nil, supervisor.ErrJobExists
		}
		seenPublishers[publisherKey], seenReplicas[replicaKey] = true, true
		scope := supervisor.ScopeForGroup(value)
		var selected *supervisor.GroupBinding
		if binding, found := bindings[scope]; found {
			selected = &binding
			delete(bindings, scope)
		}
		runner, trust, err := supervisor.ScopedGroupRunner(value, selected, startup, providers)
		if err != nil {
			return nil, err
		}
		job := supervisor.Job{Kind: supervisor.KindGroup, ID: replicaKey, Name: value.Member.GroupName + "-" + value.Instance, Server: value.ControlURL, PublisherIdentityID: value.Member.PublisherIdentityId, GroupMember: &value.Member, GroupInstance: value.Instance, ServerCAPEM: trust}
		inputs = append(inputs, fixedGroupInput{value, runner, job})
	}
	if len(bindings) != 0 {
		return nil, supervisor.ErrScope
	}
	return inputs, nil
}

func runFixedPublisherGroups(ctx context.Context, flags publisherServeCommand, diagnostics io.Writer) error {
	inputs, err := readFixedPublisherGroups(flags)
	if err != nil {
		return err
	}
	root, err := filepath.Abs(flags.StateDir)
	if err != nil {
		return err
	}
	registry, err := supervisor.Open(ctx, supervisor.OpenOptions{Root: root, StandaloneGroups: true})
	if err != nil {
		return err
	}
	defer registry.Close()
	runners := map[string]supervisor.GroupRunner{}
	var jobs []supervisor.GroupInstall
	for _, input := range inputs {
		private, err := input.value.Validate(input.value.ControlURL, input.value.Member.ProjectKey, input.value.Member.GroupName, input.value.Instance)
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
		jobs = append(jobs, supervisor.GroupInstall{Job: input.job, Private: private})
		runners[input.job.ID] = input.runner
	}
	var outputMu sync.Mutex
	engine := supervisor.Engine{Registry: registry, Initialize: func(ctx context.Context) error { return registry.ReplaceGroups(ctx, jobs) }, Group: func(ctx context.Context, job supervisor.Job, observe func(int64, bool) error) error {
		_, private, profile, err := registry.GroupIdentity(ctx, job)
		if err != nil {
			return err
		}
		return runners[job.ID].Serve(ctx, job, profile, private, observe)
	}, Observe: func(job supervisor.Job, status supervisor.Status) error {
		outputMu.Lock()
		defer outputMu.Unlock()
		fields := []clioutput.Field{{Label: "job ID", Value: job.ID}, {Label: "server", Value: job.Server}, {Label: "team ID", Value: job.GroupMember.TeamId}, {Label: "group ID", Value: job.GroupMember.GroupId}, {Label: "publisher", Value: job.PublisherIdentityID}, {Label: "instance", Value: job.GroupInstance}, {Label: "observed revision", Value: strconv.FormatInt(status.ObservedRevision, 10)}}
		if status.Failure != "" {
			fields = append(fields, clioutput.Field{Label: "failure", Value: status.Failure})
		}
		return writeHumanFrame(diagnostics, "tnl publisher serve", string(status.State), "", clioutput.Fields(fields...))
	}}
	return engine.Serve(ctx)
}
