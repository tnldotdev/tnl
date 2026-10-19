package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"os"
	"slices"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/grouppublisher"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisheridentity/credentialfile"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type groupIdentityProvisionOptions struct {
	Remote     remoteFlags
	Group      string
	ProjectKey string
	Instance   string
	OutputFile string
}

// runPublisherGroupProvision redeems once on the operator's machine, saving its
// retry key before the first request. replacement tasks only prove that key.
func runPublisherGroupProvision(ctx context.Context, options groupIdentityProvisionOptions, project projectConfiguration, output, diagnostics io.Writer) error {
	if options.Group == "local" || !naming.ValidServiceName(options.Group) || !naming.ValidServiceName(options.Instance) || options.OutputFile == "" {
		return publisherCLIError("select --group, --instance, and a new --output-file for one replica")
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
	current, err := session.current(ctx)
	if err != nil {
		return err
	}
	server := session.authenticated.ServerEndpoint
	client, err := grouppublisher.NewClient(server, nil)
	if err != nil {
		return err
	}
	applied, err := session.authenticated.Control.GetProjectConfiguration(ctx, current.team.Id, options.ProjectKey)
	if err != nil {
		return err
	}
	var groupID string
	if applied.Groups == nil {
		return credentialfile.ErrInvalid
	}
	for _, group := range *applied.Groups {
		if slices.Contains(group.GroupNames, options.Group) {
			groupID = group.Id
		}
	}
	if groupID == "" {
		return publisherCLIError("publisher group is not in this applied project's selector history")
	}
	scope := credentialfile.GroupSelection(options.ProjectKey, groupID, options.Instance)
	lock, err := session.store.LockPublisherSigningIdentity(ctx, scope)
	if err != nil {
		return err
	}
	defer lock.Close()
	var member controlv1.PublisherGroupMember
	var private ed25519.PrivateKey
	retained, retainedFound, err := credentialfile.SavedGroup(session.store, server, options.ProjectKey, groupID, options.Instance)
	if err != nil {
		return err
	}
	if retainedFound {
		if retained.Member.TeamId != current.team.Id {
			return credentialfile.ErrInvalid
		}
		if _, _, err := importPublisherGroupIdentity(ctx, session.store, client, retained, server, options.ProjectKey, options.Group, options.Instance); err != nil {
			return err
		}
		scope = credentialfile.GroupSelection(options.ProjectKey, retained.Member.GroupId, options.Instance)
	}
	saved, found, err := session.store.SelectedPublisherIdentity(ctx, "project", scope)
	if err != nil {
		return err
	}
	if found {
		if json.Unmarshal(saved.PublicDocument, &member) != nil || member.TeamId != current.team.Id {
			return credentialfile.ErrInvalid
		}
		private = ed25519.PrivateKey(saved.SigningKey)
	} else {
		pending, found, err := session.store.PendingPublisherEnrollmentForSelection(ctx, "project", scope)
		if err != nil {
			return err
		}
		if !found {
			public, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return err
			}
			id, err := opaqueid.New(opaqueid.PublisherEnrollmentPrefix)
			if err != nil {
				return err
			}
			pending = clientstate.PendingPublisherEnrollment{EnrollmentID: id, SelectionKind: "project", SelectionKey: scope, PublicKey: public, SigningKey: key, ExpiresAt: time.Now().Add(24 * time.Hour)}
			if err := session.store.SavePendingPublisherEnrollment(ctx, pending); err != nil {
				return err
			}
		}
		if len(pending.SigningKey) != ed25519.PrivateKeySize {
			return credentialfile.ErrInvalid
		}
		private = ed25519.PrivateKey(pending.SigningKey)
		if len(pending.ResultJSON) != 0 {
			if json.Unmarshal(pending.ResultJSON, &member) != nil {
				return credentialfile.ErrInvalid
			}
		} else {
			// a new bootstrap may recover an expired or lost response, but it
			// always redeems the already-protected key, never a new member key.
			enrollment, err := session.authenticated.Control.CreatePublisherGroupEnrollment(ctx, options.ProjectKey, options.Group, controlv1.CreatePublisherGroupEnrollmentRequest{TeamId: current.team.Id, MaxMembers: 1, ExpiresIn: 600})
			if err != nil {
				return err
			}
			member, err = client.Enroll(ctx, enrollment.EnrollmentKey, private.Public().(ed25519.PublicKey))
			if err != nil {
				return err
			}
		}
		if member.TeamId != current.team.Id || member.ProjectKey != options.ProjectKey || member.GroupId != groupID {
			return credentialfile.ErrInvalid
		}
		data, err := json.Marshal(member)
		if err != nil {
			return err
		}
		if err := session.store.RecordPublisherEnrollmentResult(ctx, pending.EnrollmentID, data); err != nil {
			return err
		}
		if err := session.store.PromotePublisherEnrollment(ctx, pending.EnrollmentID, clientstate.PublisherIdentity{ID: member.PublisherIdentityId, PublicDocument: data, SigningKey: private}); err != nil {
			return err
		}
	}
	value, err := credentialfile.NewGroup(server, options.Instance, member, private)
	if err != nil {
		return err
	}
	value, err = credentialfile.ResolveGroup(ctx, client, value, server, options.ProjectKey, options.Group, options.Instance)
	if err != nil {
		return err
	}
	if err := credentialfile.RetainGroup(ctx, session.store, value); err != nil {
		return err
	}
	if _, err := credentialfile.ImportGroup(ctx, session.store, value, server, options.ProjectKey, options.Group, options.Instance); err != nil {
		return err
	}
	member = value.Member
	if err := credentialfile.WriteGroup(options.OutputFile, value); err != nil {
		return err
	}
	return writeHumanFrame(output, "tnl publisher provision", "created", "store the private file in this replica's secret", clioutput.Fields(
		clioutput.Field{Label: "file", Value: options.OutputFile}, clioutput.Field{Label: "publisher", Value: member.PublisherIdentityId}, clioutput.Field{Label: "group", Value: member.GroupName}, clioutput.Field{Label: "instance", Value: options.Instance},
	))
}

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
