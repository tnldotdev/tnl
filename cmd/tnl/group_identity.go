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
	publishergroup "github.com/tnldotdev/tnl/internal/publisher/group"
	"github.com/tnldotdev/tnl/internal/publisher/identity/credentialfile"
	"github.com/tnldotdev/tnl/internal/publisher/setup"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type groupIdentityProvisionOptions struct {
	Remote      remoteFlags
	Environment string
	Services    []string
	ProjectKey  string
	Instance    string
	OutputFile  string
}

// runPublisherGroupProvision redeems once on the operator's machine, saving its
// retry key before the first request. replacement tasks only prove that key.
func runPublisherGroupProvision(ctx context.Context, options groupIdentityProvisionOptions, project projectConfiguration, output, diagnostics io.Writer) error {
	if !opaqueid.Valid(options.Environment, opaqueid.EnvironmentPrefix) || !naming.ValidServiceName(options.Instance) || options.OutputFile == "" || len(options.Services) == 0 {
		return publisherCLIError("select --environment ID, --services, --instance, and a new --output-file for one replica")
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
	client, err := publishergroup.NewClient(server, nil)
	if err != nil {
		return err
	}
	environment, err := session.Authenticated().Control.GetEnvironment(ctx, current.Team().Id, options.ProjectKey, options.Environment)
	if err != nil {
		return err
	}
	if environment.Id != options.Environment || environment.ProjectKey != options.ProjectKey || environment.TeamId != current.Team().Id {
		return credentialfile.ErrInvalid
	}
	value, err := setup.Ensure(ctx, session.Store(), session.Authenticated().Control, client, setup.Scope{
		Server: server, Team: current.Team().Id, Project: options.ProjectKey, EnvironmentID: environment.Id, Instance: options.Instance,
		MutationRevision: environment.MutationRevision, ConfigurationHash: environment.ConfigurationHash, Services: options.Services,
	})
	if err != nil {
		return err
	}
	member := value.Member
	if err := credentialfile.WriteGroup(options.OutputFile, value); err != nil {
		return err
	}
	return writeHumanFrame(output, "tnl publisher provision", "created", "store the private file in this replica's secret", clioutput.Fields(
		clioutput.Field{Label: "file", Value: options.OutputFile}, clioutput.Field{Label: "publisher", Value: member.PublisherIdentityId}, clioutput.Field{Label: "environment ID", Value: member.EnvironmentId}, clioutput.Field{Label: "instance", Value: options.Instance},
	))
}

// publisherGroupIdentityInput consumes a private mounted file or an ECS-injected
// JSON secret. clearing the environment prevents inheritance by child processes.
// call before enrollment; a supplied invalid secret must never fall back to it.
func publisherGroupIdentityInput(path string) (credentialfile.GroupFile, bool, error) {
	encoded, supplied := os.LookupEnv("TNL_ENVIRONMENT_PUBLISHER_IDENTITY")
	if supplied {
		if err := os.Unsetenv("TNL_ENVIRONMENT_PUBLISHER_IDENTITY"); err != nil {
			return credentialfile.GroupFile{}, true, credentialfile.ErrInvalid
		}
		if path != "" {
			return credentialfile.GroupFile{}, true, publisherCLIError("select --identity-file or TNL_ENVIRONMENT_PUBLISHER_IDENTITY, not both")
		}
		value, err := credentialfile.ParseGroup([]byte(encoded))
		return value, true, err
	}
	if path == "" {
		return credentialfile.GroupFile{}, false, nil
	}
	value, err := credentialfile.ReadGroup(path)
	return value, true, err
}

// preparePublisherGroupIdentity binds the server before project defaults or
// saved server selection can redirect a portable signing identity.
func preparePublisherGroupIdentity(flags *publisherServeCommand) error {
	if flags.identityInputRead {
		return nil
	}
	path := ""
	if len(flags.IdentityFile) > 1 {
		return publisherCLIError("omit --environment when supplying multiple identities")
	}
	if len(flags.IdentityFile) == 1 {
		path = flags.IdentityFile[0]
	}
	value, supplied, err := publisherGroupIdentityInput(path)
	if err != nil {
		return err
	}
	if supplied {
		if flags.EnrollmentKey != "" {
			return publisherCLIError("select a portable environment publisher identity or an enrollment key, not both")
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
		if _, err := value.Validate(server, project, flags.Environment, flags.Instance); err != nil {
			return err
		}
		flags.ServerURL = server
		flags.ProjectKey = project
		flags.identity = &value
	}
	flags.identityInputRead = true
	return nil
}

// importPublisherGroupIdentity requires the caller's existing group identity
// lock. verify the signing key and exact current membership before saving it.
func importPublisherGroupIdentity(ctx context.Context, profile *clientstate.Store, client *publishergroup.Client, value credentialfile.GroupFile, server, project, group, instance string) (controlv1.EnvironmentPublisher, ed25519.PrivateKey, error) {
	value, err := credentialfile.ResolveGroup(ctx, client, value, server, project, group, instance)
	if err != nil {
		return controlv1.EnvironmentPublisher{}, nil, err
	}
	if err := credentialfile.RetainGroup(ctx, profile, value); err != nil {
		return controlv1.EnvironmentPublisher{}, nil, err
	}
	private, err := credentialfile.ImportGroup(ctx, profile, value, server, project, group, instance)
	if err != nil {
		return controlv1.EnvironmentPublisher{}, nil, err
	}
	return value.Member, private, nil
}
