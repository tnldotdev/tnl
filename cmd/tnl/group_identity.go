package main

import (
	"context"
	"crypto/ed25519"
	"os"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/grouppublisher"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/publisheridentity/credentialfile"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

// publisherGroupIdentityInput consumes a private mounted file or an ECS-injected
// JSON secret. clearing the environment prevents inheritance by child processes.
// call before enrollment; a supplied invalid secret must never fall back to it.
func publisherGroupIdentityInput(path string) (credentialfile.GroupFile, bool, error) {
	encoded, supplied := os.LookupEnv("TNL_GROUP_IDENTITY")
	if supplied {
		if err := os.Unsetenv("TNL_GROUP_IDENTITY"); err != nil {
			return credentialfile.GroupFile{}, true, credentialfile.ErrInvalid
		}
		if path != "" {
			return credentialfile.GroupFile{}, true, publisherCLIError("select --identity-file or TNL_GROUP_IDENTITY, not both")
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
	value, supplied, err := publisherGroupIdentityInput(flags.IdentityFile)
	if err != nil {
		return err
	}
	if supplied {
		if flags.EnrollmentKey != "" {
			return publisherCLIError("select a portable group identity or an enrollment key, not both")
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
		if _, err := value.Validate(server, project, flags.Group, flags.Instance); err != nil {
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
func importPublisherGroupIdentity(ctx context.Context, profile *clientstate.Store, client *grouppublisher.Client, value credentialfile.GroupFile, server, project, group, instance string) (controlv1.PublisherGroupMember, ed25519.PrivateKey, error) {
	value, err := credentialfile.ResolveGroup(ctx, client, value, server, project, group, instance)
	if err != nil {
		return controlv1.PublisherGroupMember{}, nil, err
	}
	if err := credentialfile.RetainGroup(ctx, profile, value); err != nil {
		return controlv1.PublisherGroupMember{}, nil, err
	}
	private, err := credentialfile.ImportGroup(ctx, profile, value, server, project, group, instance)
	if err != nil {
		return controlv1.PublisherGroupMember{}, nil, err
	}
	return value.Member, private, nil
}
