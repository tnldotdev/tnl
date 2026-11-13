package main

import (
	"context"
	"io"
	"time"

	"github.com/tnldotdev/tnl/internal/client/auth"
	"github.com/tnldotdev/tnl/internal/failure"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type authCredentialCommand struct {
	Create authCredentialCreateCommand `cmd:"" help:"Approve independent deployment management, connection, and publication capabilities."`
}
type authCredentialCreateCommand struct {
	scopedTeamFlags `embed:""`
	ProjectKey      string        `name:"project-key" help:"Applied project key; defaults to this Git configuration source."`
	Name            string        `arg:"" help:"Credential name."`
	Manage          []string      `name:"manage" help:"Approved logical service; repeat for management."`
	Connect         []string      `name:"connect" help:"Approved logical service; repeat for connections."`
	Publish         []string      `name:"publish" help:"Approved HTTP service with a saved public URL; repeat for named publication."`
	Temporary       string        `name:"temporary" help:"Approve temporary public URLs: restricted or anonymous (also permits explicit anonymous access)."`
	DeploymentIDs   []string      `name:"deployment-id" help:"Exact approved deployment ID; repeat, or use --all-deployments."`
	AllDeployments  bool          `name:"all-deployments" help:"Explicitly approve current and future deployments, including runtime creation."`
	ExpiresIn       time.Duration `name:"expires-in" required:"" help:"Fixed lifetime from 1m to 720h."`
	IdempotencyKey  string        `name:"idempotency-key" required:"" help:"Original registration key; repeat this key and flags after a lost reply."`
}

func runAuthCredentialCreate(ctx context.Context, flags authCredentialCreateCommand, project projectConfiguration, output, diagnostics io.Writer) error {
	key, err := deploymentProjectKey(ctx, project, flags.ProjectKey)
	if err != nil {
		return err
	}
	if flags.ExpiresIn < time.Minute || flags.ExpiresIn > 30*24*time.Hour || len(flags.Manage)+len(flags.Connect)+len(flags.Publish) == 0 && flags.Temporary == "" || flags.AllDeployments == (len(flags.DeploymentIDs) > 0) || flags.Temporary != "" && flags.Temporary != "restricted" && flags.Temporary != "anonymous" {
		return publisherCLIError("select independent --manage/--connect/--publish services or --temporary restricted|anonymous, --deployment-id or --all-deployments, and --expires-in 1m-720h")
	}
	session, err := openTeamSession(ctx, flags.selection(), "tnl auth credential create", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.Current(ctx)
	if err != nil {
		return err
	}
	body := controlv1.RegisterDeploymentCredentialRequest{Name: flags.Name, ExpiresIn: int(flags.ExpiresIn / time.Second)}
	if len(flags.Manage) > 0 {
		body.Permissions.Manage = &flags.Manage
	}
	if len(flags.Connect) > 0 {
		body.Permissions.Connect = &flags.Connect
	}
	if flags.AllDeployments {
		body.AllDeployments = new(controlv1.RegisterDeploymentCredentialRequestAllDeployments(true))
	} else {
		body.DeploymentIds = &flags.DeploymentIDs
	}
	if len(flags.Publish) > 0 || flags.Temporary != "" {
		body.Permissions.Publish = &controlv1.DeploymentPublishSelection{}
		if len(flags.Publish) > 0 {
			body.Permissions.Publish.Services = &flags.Publish
		}
		if flags.Temporary != "" {
			body.Permissions.Publish.Temporary = new(controlv1.DeploymentTemporaryPublication(flags.Temporary))
		}
	}
	credential, err := auth.RegisterDeploymentCredential(ctx, session.Store(), session.Authenticated().Control, session.Authenticated().ServerEndpoint, current.Team().Id, current.Team().DisplayName, key, flags.IdempotencyKey, body)
	if err != nil {
		return err
	}
	value, err := credential.Encode()
	if err != nil {
		return err
	}
	_, err = io.WriteString(output, value+"\n")
	return failure.Wrap("write deployment credential", failure.OutputUnavailable, err)
}
