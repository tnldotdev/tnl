package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type deploymentCommand struct {
	Create deploymentCreateCommand `cmd:"" help:"Create a deployment from existing project service declarations."`
	List   deploymentListCommand   `cmd:"" help:"List deployments in the selected project."`
	Show   deploymentSelectCommand `cmd:"" help:"Show one saved deployment by name or ID."`
	Update deploymentUpdateCommand `cmd:"" help:"Change selected existing target bindings with a revision condition."`
	Delete deploymentSelectCommand `cmd:"" help:"Delete one deployment with its current revision condition."`
}

type deploymentFlags struct {
	scopedTeamFlags `embed:""`
	ProjectKey      string           `name:"project-key" help:"Applied project key; defaults to this Git configuration source."`
	Output          statusOutputMode `name:"output" enum:"human,json" default:"human"`
}

type deploymentTargetFlags struct {
	Target            []string `name:"target" help:"SERVICE=ADDRESS; repeat for each selected binding."`
	TargetTLS         []string `name:"target-tls" help:"SERVICE=system or SERVICE=aws-rds; enable verified target TLS."`
	TargetTLSHostname []string `name:"target-tls-hostname" help:"SERVICE=HOSTNAME; override target certificate hostname with verified TLS."`
}

type deploymentCreateCommand struct {
	deploymentFlags       `embed:""`
	deploymentTargetFlags `embed:""`
	Name                  string `arg:"" name:"name" help:"Project-unique deployment name; local is reserved."`
	IdempotencyKey        string `name:"idempotency-key" help:"Original request key for automated lost-response recovery; generated once per invocation when omitted."`
}

type deploymentListCommand struct {
	deploymentFlags `embed:""`
	After           string `name:"after" help:"Resume after the previous page's deployment ID."`
	Limit           int    `name:"limit" default:"50" help:"Maximum deployments in one page, from 1 to 100."`
}

type deploymentSelectCommand struct {
	deploymentFlags `embed:""`
	Deployment      string `arg:"" name:"deployment" help:"Deployment name or immutable ID."`
}

type deploymentUpdateCommand struct {
	deploymentSelectCommand `embed:""`
	deploymentTargetFlags   `embed:""`
}

func selectedDeploymentFlags(command string, flags *cli) *deploymentFlags {
	switch command {
	case "deployment create <name>":
		return &flags.Deployment.Create.deploymentFlags
	case "deployment list":
		return &flags.Deployment.List.deploymentFlags
	case "deployment show <deployment>":
		return &flags.Deployment.Show.deploymentFlags
	case "deployment update <deployment>":
		return &flags.Deployment.Update.deploymentFlags
	case "deployment delete <deployment>":
		return &flags.Deployment.Delete.deploymentFlags
	default:
		return nil
	}
}

func deploymentTargets(flags deploymentTargetFlags) (map[string]controlv1.DeploymentTarget, error) {
	invalid := func() error {
		return failure.Wrap("select deployment targets", failure.InvalidTunnelFlags, errors.New("use unique --target SERVICE=ADDRESS entries; TLS settings must name a selected target"))
	}
	if len(flags.Target) < 1 || len(flags.Target) > 128 {
		return nil, invalid()
	}
	result := map[string]controlv1.DeploymentTarget{}
	for _, value := range flags.Target {
		name, address, ok := strings.Cut(value, "=")
		if !ok || !naming.ValidServiceName(name) || address == "" || len(address) > 8192 || strings.ContainsAny(address, "\x00\r\n") {
			return nil, invalid()
		}
		if _, duplicate := result[name]; duplicate {
			return nil, invalid()
		}
		result[name] = controlv1.DeploymentTarget{Address: address}
	}
	for _, setting := range []struct {
		values   []string
		hostname bool
	}{{flags.TargetTLS, false}, {flags.TargetTLSHostname, true}} {
		seen := map[string]bool{}
		for _, value := range setting.values {
			name, value, ok := strings.Cut(value, "=")
			target, found := result[name]
			if !ok || !found || seen[name] || value == "" {
				return nil, invalid()
			}
			seen[name] = true
			if target.Tls == nil {
				target.Tls = &controlv1.DeploymentTargetTLS{}
			}
			if setting.hostname {
				if len(value) > 253 || strings.ContainsAny(value, "\x00\r\n") {
					return nil, invalid()
				}
				target.Tls.Hostname = &value
			} else {
				if value != "system" && value != "aws-rds" {
					return nil, invalid()
				}
				target.Tls.Ca = &value
			}
			result[name] = target
		}
	}
	return result, nil
}

func runDeployment(ctx context.Context, command string, flags cli, project projectConfiguration, output, diagnostics io.Writer) error {
	selected := selectedDeploymentFlags(command, &flags)
	if selected == nil {
		return failure.Wrap("select deployment operation", failure.InvalidCommand, errors.New("unknown deployment operation"))
	}
	key := selected.ProjectKey
	if key == "" {
		source, err := project.SourceIdentity(ctx)
		if err != nil {
			return err
		}
		key = source.Key
	}
	if !naming.ValidProjectKey(key) {
		return publisherCLIError("pass a valid --project-key or run inside the applied Git project")
	}
	var targets map[string]controlv1.DeploymentTarget
	var err error
	if command == "deployment create <name>" {
		if !naming.ValidServiceName(flags.Deployment.Create.Name) || flags.Deployment.Create.Name == "local" {
			return publisherCLIError("choose a deployment name other than local")
		}
		if requestKey := flags.Deployment.Create.IdempotencyKey; len(requestKey) > 128 || strings.ContainsAny(requestKey, "\x00\r\n") {
			return publisherCLIError("use an --idempotency-key of at most 128 characters without control characters")
		}
		targets, err = deploymentTargets(flags.Deployment.Create.deploymentTargetFlags)
	} else if command == "deployment update <deployment>" {
		targets, err = deploymentTargets(flags.Deployment.Update.deploymentTargetFlags)
	}
	if err != nil {
		return err
	}
	if command == "deployment list" && (flags.Deployment.List.Limit < 1 || flags.Deployment.List.Limit > 100 || flags.Deployment.List.After != "" && !opaqueid.Valid(flags.Deployment.List.After, "pgrp_")) {
		return publisherCLIError("select --limit 1-100 and an optional deployment ID with --after")
	}
	for _, selector := range []string{flags.Deployment.Show.Deployment, flags.Deployment.Update.Deployment, flags.Deployment.Delete.Deployment} {
		if selector != "" && (selector == "local" || !naming.ValidServiceName(selector) && !opaqueid.Valid(selector, "pgrp_")) {
			return publisherCLIError("select a saved deployment name or ID; local is a client-side selection")
		}
	}
	session, err := openTeamSession(ctx, selected.selection(), "tnl "+strings.Split(command, " <")[0], diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.Current(ctx)
	if err != nil {
		return err
	}
	team, control := current.Team().Id, session.Authenticated().Control
	if command == "deployment list" {
		page, err := control.ListDeployments(ctx, team, key, flags.Deployment.List.After, flags.Deployment.List.Limit)
		if err != nil {
			return err
		}
		if len(page.Deployments) > flags.Deployment.List.Limit {
			return failure.Wrap("read deployments", failure.ServerResponseInvalid, errors.New("deployment page exceeded its requested limit"))
		}
		if page.NextCursor != nil && !opaqueid.Valid(*page.NextCursor, "pgrp_") {
			return failure.Wrap("read deployments", failure.ServerResponseInvalid, errors.New("control returned an invalid deployment cursor"))
		}
		for _, deployment := range page.Deployments {
			if err = validateDeploymentResult(deployment, team, key); err != nil {
				return err
			}
		}
		if selected.Output == statusOutputJSON {
			return failure.Wrap("write deployments", failure.OutputUnavailable, json.NewEncoder(output).Encode(page))
		}
		blocks := []clioutput.Block{}
		for _, deployment := range page.Deployments {
			blocks = append(blocks, deploymentBlock(deployment))
		}
		if page.NextCursor != nil {
			blocks = append(blocks, clioutput.Fields(clioutput.Field{Label: "next cursor", Value: *page.NextCursor}))
		}
		return writeHumanFrame(output, "tnl deployment list", "listed", "", blocks...)
	}
	var deployment controlv1.Deployment
	switch command {
	case "deployment create <name>":
		requestKey := flags.Deployment.Create.IdempotencyKey
		if requestKey == "" {
			requestKey, err = randomIdempotencyKey()
			if err != nil {
				return err
			}
		}
		deployment, err = control.CreateDeployment(ctx, team, key, requestKey, controlv1.CreateDeploymentRequest{Name: flags.Deployment.Create.Name, Targets: targets})
	case "deployment show <deployment>":
		deployment, err = control.GetDeployment(ctx, team, key, flags.Deployment.Show.Deployment)
	case "deployment update <deployment>", "deployment delete <deployment>":
		selector := flags.Deployment.Update.Deployment
		if command == "deployment delete <deployment>" {
			selector = flags.Deployment.Delete.Deployment
		}
		deployment, err = control.GetDeployment(ctx, team, key, selector)
		if err != nil {
			return err
		}
		if err = validateDeploymentResult(deployment, team, key); err != nil {
			return err
		}
		if command == "deployment delete <deployment>" {
			if err = control.DeleteDeployment(ctx, team, key, deployment.Id, deployment.Revision); err != nil {
				return err
			}
			if selected.Output == statusOutputJSON {
				return failure.Wrap("write deployment deletion", failure.OutputUnavailable, json.NewEncoder(output).Encode(struct {
					ID      string `json:"id"`
					Deleted bool   `json:"deleted"`
				}{deployment.Id, true}))
			}
			return writeHumanFrame(output, "tnl deployment delete", "deleted", "", clioutput.Fields(clioutput.Field{Label: "deployment", Value: deployment.Id}))
		}
		deployment, err = control.UpdateDeployment(ctx, team, key, deployment.Id, deployment.Revision, controlv1.UpdateDeploymentRequest{Targets: targets})
	}
	if err != nil {
		return err
	}
	if err = validateDeploymentResult(deployment, team, key); err != nil {
		return err
	}
	if selected.Output == statusOutputJSON {
		return failure.Wrap("write deployment", failure.OutputUnavailable, json.NewEncoder(output).Encode(deployment))
	}
	return writeHumanFrame(output, "tnl "+strings.Split(command, " <")[0], "saved", "no target connection or database query was checked", deploymentBlock(deployment))
}

func validateDeploymentResult(deployment controlv1.Deployment, team, project string) error {
	if deployment.TeamId != team || deployment.ProjectKey != project || !opaqueid.Valid(deployment.Id, "pgrp_") || !naming.ValidServiceName(deployment.Name) || deployment.Name == "local" || deployment.Revision < 1 {
		return failure.Wrap("read deployment", failure.ServerResponseInvalid, errors.New("control returned another or invalid deployment selection"))
	}
	for name, service := range deployment.Services {
		if !naming.ValidServiceName(name) || !opaqueid.Valid(service.Id, opaqueid.ServicePrefix) || !service.Protocol.Valid() || service.TrustRevision < 1 {
			return failure.Wrap("read deployment", failure.ServerResponseInvalid, errors.New("control returned an invalid service binding"))
		}
	}
	return nil
}

func deploymentBlock(deployment controlv1.Deployment) clioutput.Block {
	blocks := []clioutput.Block{clioutput.Fields(clioutput.Field{Label: "ID", Value: deployment.Id}, clioutput.Field{Label: "revision", Value: strconv.FormatInt(deployment.Revision, 10)})}
	for _, name := range slices.Sorted(maps.Keys(deployment.Services)) {
		service := deployment.Services[name]
		fields := []clioutput.Field{{Label: "protocol", Value: string(service.Protocol)}, {Label: "service ID", Value: service.Id}}
		target := deployment.Targets[name]
		if target.Address != nil {
			fields = append(fields, clioutput.Field{Label: "target", Value: *target.Address})
		} else if target.Discovery != nil {
			fields = append(fields, clioutput.Field{Label: "target", Value: "publisher-side discovery"})
		}
		if target.Tls != nil {
			fields = append(fields, clioutput.Field{Label: "target TLS", Value: "verified"})
			if target.Tls.Hostname != nil {
				fields = append(fields, clioutput.Field{Label: "TLS hostname", Value: *target.Tls.Hostname})
			}
		}
		blocks = append(blocks, clioutput.Section(name, clioutput.Fields(fields...)))
	}
	return clioutput.Section(deployment.Name, blocks...)
}
