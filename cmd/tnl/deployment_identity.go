package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"os"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	publisherdeployment "github.com/tnldotdev/tnl/internal/publisher/deployment"
	"github.com/tnldotdev/tnl/internal/publisher/identity/credentialfile"
	"github.com/tnldotdev/tnl/internal/publisher/setup"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type deploymentIdentityProvisionOptions struct {
	Remote     remoteFlags
	Deployment string
	ProjectKey string
	Instance   string
	OutputFile string
	Services   []string
}

// runDeploymentPublisherProvision redeems once on the operator's machine, saving its
// retry key before the first request. replacement tasks only prove that key.
func runDeploymentPublisherProvision(ctx context.Context, options deploymentIdentityProvisionOptions, project projectConfiguration, output, diagnostics io.Writer) error {
	if !validDeploymentSelector(options.Deployment) || !naming.ValidServiceName(options.Instance) || options.OutputFile == "" {
		return publisherCLIError("select --deployment, --instance, and a new --output-file for one replica")
	}
	if _, err := os.Lstat(options.OutputFile); err == nil {
		return credentialfile.ErrExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return credentialfile.ErrInvalid
	}
	if options.ProjectKey == "" {
		source, err := project.SourceIdentity(ctx)
		if err != nil {
			return err
		}
		options.ProjectKey = source.Key
	}
	session, err := openTeamSession(ctx, options.Remote, "tnl publisher provision", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.Current(ctx)
	if err != nil {
		return err
	}
	server := session.Authenticated().ServerEndpoint
	client, err := publisherdeployment.NewClient(server, nil)
	if err != nil {
		return err
	}
	deployment, err := session.Authenticated().Control.GetDeployment(ctx, current.Team().Id, options.ProjectKey, options.Deployment)
	if err != nil {
		return err
	}
	if deployment.TeamId != current.Team().Id || deployment.ProjectKey != options.ProjectKey || !opaqueid.Valid(deployment.Id, "dpl_") {
		return credentialfile.ErrInvalid
	}
	value, err := setup.Ensure(ctx, session.Store(), session.Authenticated().Control, client, setup.Scope{
		Server: server, Team: current.Team().Id, Project: options.ProjectKey, DeploymentID: deployment.Id, Deployment: deployment.Name, Instance: options.Instance,
	}, options.Services)
	if err != nil {
		return err
	}
	member := value.Member
	if err := credentialfile.WriteDeployment(options.OutputFile, value); err != nil {
		return err
	}
	return writeHumanFrame(output, "tnl publisher provision", "created", "store the private file in this replica's secret", clioutput.Fields(
		clioutput.Field{Label: "file", Value: options.OutputFile}, clioutput.Field{Label: "publisher", Value: member.PublisherIdentityId}, clioutput.Field{Label: "deployment", Value: member.DeploymentName}, clioutput.Field{Label: "instance", Value: options.Instance},
	))
}

// deploymentPublisherIdentityInput consumes a private mounted file or an ECS-injected
// JSON secret. clearing the environment prevents inheritance by child processes.
// call before enrollment; a supplied invalid secret must never fall back to it.
func deploymentPublisherIdentityInput(path string) (credentialfile.DeploymentFile, bool, error) {
	encoded, supplied := os.LookupEnv("TNL_DEPLOYMENT_IDENTITY")
	if supplied {
		if err := os.Unsetenv("TNL_DEPLOYMENT_IDENTITY"); err != nil {
			return credentialfile.DeploymentFile{}, true, credentialfile.ErrInvalid
		}
		if path != "" {
			return credentialfile.DeploymentFile{}, true, publisherCLIError("select --identity-file or TNL_DEPLOYMENT_IDENTITY, not both")
		}
		value, err := credentialfile.ParseDeployment([]byte(encoded))
		return value, true, err
	}
	if path == "" {
		return credentialfile.DeploymentFile{}, false, nil
	}
	value, err := credentialfile.ReadDeployment(path)
	return value, true, err
}

// prepareDeploymentIdentity binds the server before project defaults or
// saved server selection can redirect a portable signing identity.
func prepareDeploymentIdentity(flags *publisherServeCommand) error {
	if flags.identityInputRead {
		return nil
	}
	path := ""
	if len(flags.IdentityFile) > 1 {
		return publisherCLIError("omit --deployment when supplying multiple identities")
	}
	if len(flags.IdentityFile) == 1 {
		path = flags.IdentityFile[0]
	}
	value, supplied, err := deploymentPublisherIdentityInput(path)
	if err != nil {
		return err
	}
	if supplied {
		if flags.EnrollmentKey != "" {
			return publisherCLIError("select a portable deployment identity or an enrollment key, not both")
		}
		server := value.ControlURL
		if flags.ServerURL != "" {
			server, err = naming.CanonicalControlURL(flags.ServerURL)
			if err != nil {
				return credentialfile.ErrInvalid
			}
		}
		project := flags.ProjectKey
		if project == "" {
			project = value.Member.ProjectKey
		}
		if _, err := value.Validate(server, project, flags.Deployment, flags.Instance); err != nil {
			return err
		}
		flags.ServerURL = server
		flags.ProjectKey = project
		flags.identity = &value
	}
	flags.identityInputRead = true
	return nil
}

// importDeploymentIdentity requires the caller's existing deployment identity
// lock. verify the signing key and exact current membership before saving it.
func importDeploymentIdentity(ctx context.Context, profile *clientstate.Store, client *publisherdeployment.Client, value credentialfile.DeploymentFile, server, project, deployment, instance string) (controlv1.DeploymentPublisherIdentity, ed25519.PrivateKey, error) {
	value, err := credentialfile.ResolveDeployment(ctx, client, value, server, project, deployment, instance)
	if err != nil {
		return controlv1.DeploymentPublisherIdentity{}, nil, err
	}
	if err := credentialfile.RetainDeployment(ctx, profile, value); err != nil {
		return controlv1.DeploymentPublisherIdentity{}, nil, err
	}
	private, err := credentialfile.ImportDeployment(ctx, profile, value, server, project, deployment, instance)
	if err != nil {
		return controlv1.DeploymentPublisherIdentity{}, nil, err
	}
	return value.Member, private, nil
}
