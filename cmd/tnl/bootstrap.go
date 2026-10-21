package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"slices"
	"time"

	"github.com/tnldotdev/tnl/internal/awsbootstrap"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/grouppublisher"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisherdeployment"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type bootstrapCommand struct {
	scopedTeamFlags `embed:""`
	Publisher       string           `arg:"" name:"publisher" help:"Configured publisher group to prepare, such as production."`
	DeploymentFile  string           `name:"deployment-file" default:"deploy/publishers/aws.json" help:"Customer deployment file, relative to the project root."`
	Deployment      string           `name:"deployment" help:"Stable deployment name from the customer file; required when the group has multiple deployments."`
	Profile         string           `name:"profile" help:"AWS shared configuration profile; otherwise use the standard credentials chain."`
	Region          string           `name:"region" help:"AWS region; must match the selected customer deployment."`
	GeneratedDir    string           `name:"generated-dir" default:".tnl/generated" help:"Current generated publisher manifest directory, relative to the project root."`
	Output          statusOutputMode `name:"output" enum:"human,json" default:"human"`
}

type bootstrapResult struct {
	State           string                                 `json:"state"`
	Deployment      string                                 `json:"deployment"`
	DeploymentID    string                                 `json:"deployment_id"`
	ProjectKey      string                                 `json:"project_key"`
	GroupID         string                                 `json:"group_id"`
	AppliedRevision int64                                  `json:"applied_revision"`
	TemplatePath    string                                 `json:"template_path"`
	TemplateSHA256  string                                 `json:"template_sha256"`
	TemplateVersion string                                 `json:"template_version"`
	Parameters      []publisherdeployment.Parameter        `json:"parameters"`
	Replicas        []awsbootstrap.Reference               `json:"replicas"`
	ObservedMembers []controlv1.PublisherGroupMemberStatus `json:"observed_members"`
	Instructions    []string                               `json:"instructions"`
}

type bootstrapLoader func(context.Context, string, string) (awsbootstrap.Secrets, awsbootstrap.Caller, error)

func runBootstrap(ctx context.Context, flags bootstrapCommand, project projectConfiguration, output, diagnostics io.Writer) error {
	return runBootstrapUsing(ctx, flags, project, output, diagnostics, awsbootstrap.Load)
}

func runBootstrapUsing(ctx context.Context, flags bootstrapCommand, project projectConfiguration, output, diagnostics io.Writer, load bootstrapLoader) error {
	// bootstrap is finite, including credential discovery and SDK retry backoff.
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	bad := func(err error) error {
		return failure.Wrap("prepare publisher deployment", failure.AWSBootstrapInvalid, err)
	}
	scopeError := func() error {
		return failure.Wrap("verify publisher deployment scope", failure.AWSBootstrapScope, errors.New("applied source or deployment binding differs"))
	}
	source, err := project.SourceIdentity(ctx)
	if err != nil {
		return bad(err)
	}
	rootPath := func(path string) string {
		if filepath.IsAbs(path) {
			return path
		}
		return filepath.Join(project.Root, path)
	}
	manifest, err := publisherdeployment.Validate(rootPath(flags.GeneratedDir), project.Config, source)
	if err != nil {
		return bad(err)
	}
	publisher, err := manifest.FindPublisher(flags.Publisher)
	if err != nil || publisher.Provider != "aws" {
		return bad(errors.New("select a generated AWS publisher"))
	}
	deployment, err := awsbootstrap.ReadDeployment(rootPath(flags.DeploymentFile), flags.Publisher, flags.Deployment)
	if err != nil {
		return err
	}
	if flags.Region != "" && flags.Region != deployment.Region {
		return scopeError()
	}
	for key := range deployment.Secrets {
		if !slices.ContainsFunc(publisher.Replicas, func(r publisherdeployment.Replica) bool { return r.Key == key }) {
			return bad(errors.New("secret override selects an unknown replica slot"))
		}
	}
	session, err := openTeamSession(ctx, flags.selection(), "tnl bootstrap", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.current(ctx)
	if err != nil {
		return err
	}
	applied, err := session.authenticated.Control.GetProjectConfiguration(ctx, current.team.Id, source.Key)
	if err != nil {
		return err
	}
	if applied.ProjectKey != source.Key || applied.TeamId != current.team.Id || applied.SourceFingerprint != source.Fingerprint || applied.Revision < 1 || applied.Groups == nil {
		return scopeError()
	}
	var group *controlv1.AppliedPublisherGroup
	for _, candidate := range *applied.Groups {
		if slices.Contains(candidate.GroupNames, flags.Publisher) {
			if group != nil || !opaqueid.Valid(candidate.Id, "pgrp_") {
				return scopeError()
			}
			group = &candidate
		}
	}
	if group == nil {
		return scopeError()
	}
	binding := awsbootstrap.Binding{ControlOrigin: session.authenticated.ServerEndpoint, TeamID: current.team.Id, ProjectKey: source.Key, GroupID: group.Id, SourceFingerprint: source.Fingerprint, AccountID: deployment.AccountID, Region: deployment.Region, DeploymentName: deployment.Name}
	deploymentID := "aws-" + binding.ID()[:40]
	parameters := publisherdeployment.Parameters{
		publisherdeployment.ControlURLParameter:       binding.ControlOrigin,
		publisherdeployment.ProjectKeyParameter:       source.Key,
		publisherdeployment.GroupParameter:            group.Name,
		publisherdeployment.TeamIDParameter:           binding.TeamID,
		publisherdeployment.PublisherGroupIDParameter: group.Id,
		publisherdeployment.DeploymentIDParameter:     deploymentID,
		publisherdeployment.TemplateSHA256Parameter:   publisher.TemplateSHA256,
	}
	// identity bindings have one owner. customer infrastructure values cannot
	// override a generated replica's signing identity or immutable scope.
	for _, r := range publisher.Replicas {
		for _, key := range []string{r.IdentitySecretARNParameter, r.IdentitySecretVersionParameter, r.InstanceParameter, r.PublisherIdentityIDParameter} {
			parameters[key] = ""
		}
	}
	for key := range parameters {
		if _, exists := deployment.Parameters[key]; exists {
			return bad(errors.New("customer parameters override a bootstrap-owned identity binding"))
		}
	}
	secrets, caller, err := load(ctx, flags.Profile, deployment.Region)
	if err != nil {
		return err
	}
	if err := awsbootstrap.CheckAccount(ctx, caller, deployment.AccountID); err != nil {
		return err
	}
	client, err := grouppublisher.NewClient(binding.ControlOrigin, nil)
	if err != nil {
		return err
	}
	receipts, err := clientstate.OpenPrivateDirectory(filepath.Join(project.Root, ".tnl", "local", "aws"))
	if err != nil {
		return err
	}
	preparer := awsbootstrap.Preparer{Store: session.store, Secrets: secrets, Control: session.authenticated.Control, Client: client, Receipts: receipts}
	result := bootstrapResult{State: "prepared", Deployment: deployment.Name, DeploymentID: deploymentID, ProjectKey: source.Key, GroupID: group.Id, AppliedRevision: applied.Revision, TemplatePath: filepath.Join(flags.GeneratedDir, publisher.TemplatePath), TemplateSHA256: publisher.TemplateSHA256, Replicas: []awsbootstrap.Reference{}, ObservedMembers: []controlv1.PublisherGroupMemberStatus{}, Instructions: []string{
		"merge these identity parameter bindings with the selected customer deployment's parameters",
		"supply PublisherImage by digest, VpcId and Subnets before deploying the generated template with your infrastructure tool",
		"preserve deployment name, replica slots, secret versions and durable replica storage on later updates",
		"inspect tnl status after deployment for current publisher egress observations; update target allowlists separately if needed",
	}}
	for _, replica := range publisher.Replicas {
		binding.ReplicaSlot = replica.Key
		ref, err := preparer.Prepare(ctx, awsbootstrap.Request{Binding: binding, Group: flags.Publisher, Secret: deployment.Secrets[replica.Key]})
		if err != nil {
			return err
		}
		parameters[replica.IdentitySecretARNParameter] = ref.SecretARN
		parameters[replica.IdentitySecretVersionParameter] = ref.SecretVersion
		parameters[replica.InstanceParameter] = ref.Instance
		parameters[replica.PublisherIdentityIDParameter] = ref.PublisherIdentityID
		result.Replicas = append(result.Replicas, ref)
	}
	// these observations came from control at the start of this finite command;
	// bootstrap does not start tasks or claim fresh egress on their behalf.
	for _, member := range applied.Members {
		if member.Runtime != nil && slices.ContainsFunc(result.Replicas, func(ref awsbootstrap.Reference) bool { return ref.PublisherIdentityID == member.PublisherIdentityId }) {
			result.ObservedMembers = append(result.ObservedMembers, member)
		}
	}
	result.Parameters = parameters.CloudFormation()
	result.TemplateVersion = publisherdeployment.TemplateVersion
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	if err := receipts.Write(deploymentID+".prepared.json", data); err != nil {
		return err
	}
	if flags.Output == statusOutputJSON {
		return json.NewEncoder(output).Encode(result)
	}
	blocks := []clioutput.Block{clioutput.Fields(clioutput.Field{Label: "deployment", Value: deployment.Name}, clioutput.Field{Label: "group ID", Value: group.Id}, clioutput.Field{Label: "account", Value: deployment.AccountID}, clioutput.Field{Label: "region", Value: deployment.Region}, clioutput.Field{Label: "template", Value: result.TemplatePath}, clioutput.Field{Label: "bindings", Value: filepath.Join(".tnl", "local", "aws", deploymentID+".prepared.json")})}
	for _, replica := range result.Replicas {
		fields := []clioutput.Field{{Label: "publisher", Value: replica.PublisherIdentityID}, {Label: "secret", Value: replica.SecretARN}, {Label: "version", Value: replica.SecretVersion}}
		var runtime *controlv1.PublisherRuntimeStatus
		for _, member := range result.ObservedMembers {
			if member.PublisherIdentityId == replica.PublisherIdentityID {
				runtime = member.Runtime
			}
		}
		fields = append(fields, publisherRuntimeFields(runtime)...)
		blocks = append(blocks, clioutput.Section(replica.Binding.ReplicaSlot, clioutput.Fields(fields...)))
	}
	for _, instruction := range result.Instructions {
		blocks = append(blocks, clioutput.Fields(clioutput.Field{Label: "next", Value: instruction}))
	}
	return writeHumanFrame(output, "tnl bootstrap", "prepared", "use the customer deployment file with your infrastructure tool", blocks...)
}
