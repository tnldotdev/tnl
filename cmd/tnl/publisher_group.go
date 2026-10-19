package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/tnldotdev/tnl/internal/buildinfo"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/grouppublisher"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/privatepublisher"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/publisheridentity/credentialfile"
	nativeauth "github.com/tnldotdev/tnl/internal/publisheridentity/native"
	"github.com/tnldotdev/tnl/internal/publisherjob"
	"github.com/tnldotdev/tnl/internal/publisherprovenance"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type publisherServeCommand struct {
	scopedTeamFlags `embed:""`
	Group           string `name:"group" required:"" help:"Configured publisher group name."`
	ProjectKey      string `name:"project-key" help:"Applied project key; defaults to the current Git configuration source."`
	EnrollmentKey   string `name:"enroll-key" env:"TNL_GROUP_ENROLL_KEY" help:"One-use group enrollment key; use - to read stdin. Without a saved or portable identity, bootstrap with the saved person session once."`
	IdentityFile    string `name:"identity-file" type:"path" help:"Private portable group identity; alternatively inject JSON with TNL_GROUP_IDENTITY. Cannot combine with enrollment."`
	IdentityDir     string `name:"identity-dir" env:"TNL_IDENTITY_DIR" type:"path" help:"Durable publisher identity and TLS files; defaults to identities beneath the state directory. Keep SQLite task-local when using a network mount."`
	Instance        string `name:"instance" default:"default" help:"Replica identity name; must match the portable identity when supplied."`
	Foreground      bool   `name:"foreground" help:"Run in this terminal (the default)."`
	Detach          bool   `name:"detach" help:"Run independently of this terminal without automatic restart."`
	Install         bool   `name:"install" help:"Run durably with the user publisher supervisor."`
	System          bool   `name:"system" hidden:""`
	SystemStateDir  string `name:"system-state-dir" type:"path"`
	DetachedChild   string `name:"detached-child" hidden:""`

	identityInputRead bool
	identity          *credentialfile.GroupFile
}

func validatePublisherServe(flags publisherServeCommand) error {
	if flags.Group == "local" || !naming.ValidServiceName(flags.Group) || !naming.ValidServiceName(flags.Instance) {
		return publisherCLIError("select a configured publisher group other than local and a lowercase instance name")
	}
	if flags.System {
		return publisherCLIError("publisher groups use the user supervisor; --system requires an explicit single-service publisher")
	}
	if flags.Foreground && (flags.Detach || flags.Install) || flags.Detach && flags.Install {
		return publisherCLIError("select only one of --foreground, --detach, or --install")
	}
	if flags.SystemStateDir != "" && !flags.Install {
		return publisherCLIError("--system-state-dir requires --install")
	}
	_, err := publisherprovenance.ReadEnvironment(os.LookupEnv, flags.Instance, buildinfo.Version)
	return err
}

func runPublisherGroupEnrollment(ctx context.Context, flags publisherEnrollCommand, project projectConfiguration, output, diagnostics io.Writer) error {
	if flags.Group == "local" || !naming.ValidServiceName(flags.Group) || flags.PublicURLID != "" || flags.PrivateServiceID != "" || flags.Namespace || flags.Domain != "" || flags.Automation {
		return publisherCLIError("select --group NAME for a one-use configured-group bootstrap")
	}
	members, expires, err := publisherGroupEnrollmentBounds(flags)
	if err != nil {
		return err
	}
	key := flags.ProjectKey
	if key == "" {
		source, err := project.SourceIdentity(ctx)
		if err != nil {
			return err
		}
		key = source.Key
		if _, ok := project.Config.Publishers[flags.Group]; !ok {
			return publisherCLIError("publisher group is not configured in this project")
		}
	}
	session, err := openTeamSession(ctx, flags.selection(), "tnl publisher enroll", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.current(ctx)
	if err != nil {
		return err
	}
	enrollment, err := session.authenticated.Control.CreatePublisherGroupEnrollment(ctx, key, flags.Group, controlv1.CreatePublisherGroupEnrollmentRequest{TeamId: current.team.Id, MaxMembers: members, ExpiresIn: expires})
	if err != nil {
		return err
	}
	if enrollment.EnrollmentKey == "" || enrollment.MaxMembers != members || !enrollment.ExpiresAt.After(time.Now()) {
		return grouppublisher.ErrAssignment
	}
	_, err = fmt.Fprintln(output, enrollment.EnrollmentKey)
	return err
}

func publisherGroupEnrollmentBounds(flags publisherEnrollCommand) (int, int, error) {
	members := flags.Members
	lifetime := flags.ExpiresIn
	if members < 1 || members > 256 {
		return 0, 0, publisherCLIError("--members must be from 1 to 256")
	}
	if lifetime < time.Minute || lifetime > 24*time.Hour || lifetime%time.Second != 0 {
		return 0, 0, publisherCLIError("--expires-in must be a whole number of seconds from 1m to 24h")
	}
	return members, int(lifetime / time.Second), nil
}

func runPublisherServe(ctx context.Context, flags publisherServeCommand, project projectConfiguration, output, diagnostics io.Writer) error {
	if err := validatePublisherServe(flags); err != nil {
		return err
	}
	var options publisherjob.ServiceOptions
	var err error
	if flags.Install {
		options, err = (systemStateFlags{SystemStateDir: flags.SystemStateDir}).options()
		if err != nil {
			return err
		}
		if err := requireInstalledService(ctx, options, nil); err != nil {
			return err
		}
	}
	if err := preparePublisherGroupIdentity(&flags); err != nil {
		return err
	}
	if flags.ProjectKey == "" {
		source, err := project.SourceIdentity(ctx)
		if err != nil {
			return err
		}
		flags.ProjectKey = source.Key
	}
	if flags.identity != nil {
		if _, err := flags.identity.Validate(flags.ServerURL, flags.ProjectKey, flags.Group, flags.Instance); err != nil {
			return err
		}
	}
	server, state, err := resolveServer(ctx, flags.StateDir, flags.ServerURL)
	if err != nil {
		return err
	}
	defer state.Close()
	profile, err := state.Server(ctx, server)
	if err != nil {
		return err
	}
	if flags.IdentityDir != "" {
		profile, err = profile.WithIdentityDirectory(flags.IdentityDir)
		if err != nil {
			return err
		}
	}
	groupClient, err := grouppublisher.NewClient(server, nil)
	if err != nil {
		return err
	}
	if flags.identity == nil {
		value, found, err := credentialfile.ResolveSavedGroup(ctx, profile, groupClient, server, flags.ProjectKey, flags.Group, flags.Instance)
		if err != nil {
			return err
		}
		if found {
			flags.identity = &value
		}
	}
	groupIdentity := flags.Group
	if flags.identity != nil {
		groupIdentity = flags.identity.Member.GroupId
	}
	scope := credentialfile.GroupSelection(flags.ProjectKey, groupIdentity, flags.Instance)
	lock, err := profile.LockPublisherSigningIdentity(ctx, scope)
	if err != nil {
		return err
	}
	defer lock.Close()
	if flags.identity != nil {
		if _, _, err := importPublisherGroupIdentity(ctx, profile, groupClient, *flags.identity, server, flags.ProjectKey, flags.Group, flags.Instance); err != nil {
			return err
		}
		scope = credentialfile.GroupSelection(flags.ProjectKey, flags.identity.Member.GroupId, flags.Instance)
	}
	saved, found, err := profile.SelectedPublisherIdentity(ctx, "project", scope)
	if err != nil {
		return err
	}
	var member controlv1.PublisherGroupMember
	var private ed25519.PrivateKey
	if found {
		if json.Unmarshal(saved.PublicDocument, &member) != nil || member.PublisherIdentityId == "" {
			return grouppublisher.ErrAssignment
		}
		// a restarted task keeps proving its existing key. an enrollment secret
		// left in the deployment environment is neither needed nor redeemed again.
		private = ed25519.PrivateKey(saved.SigningKey)
	} else {
		pending, found, err := profile.PendingPublisherEnrollmentForSelection(ctx, "project", scope)
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
			if err := profile.SavePendingPublisherEnrollment(ctx, pending); err != nil {
				return err
			}
		}
		if len(pending.SigningKey) != ed25519.PrivateKeySize {
			return nativeauth.ErrScope
		}
		if len(pending.ResultJSON) == 0 && (len(pending.EnrollmentSecret) == 0 || flags.EnrollmentKey != "") {
			secret := ""
			if flags.EnrollmentKey != "" {
				secret, err = enrollmentKeyInput(flags.EnrollmentKey, os.Stdin)
			} else {
				remote := flags.selection()
				remote.ServerURL = server
				session, err := openTeamSession(ctx, remote, "tnl publisher serve", diagnostics)
				if err != nil {
					return err
				}
				defer session.Close()
				current, err := session.current(ctx)
				if err != nil {
					return err
				}
				enrollment, err := session.authenticated.Control.CreatePublisherGroupEnrollment(ctx, flags.ProjectKey, flags.Group, controlv1.CreatePublisherGroupEnrollmentRequest{TeamId: current.team.Id, MaxMembers: 1, ExpiresIn: 600})
				if err != nil {
					return err
				}
				secret = enrollment.EnrollmentKey
			}
			if err != nil {
				return err
			}
			// refreshing bootstrap keeps the protected key, including after a
			// lost redemption response. the server recognizes that same key.
			pending.EnrollmentSecret = []byte(secret)
			if err := profile.SetPublisherGroupEnrollmentSecret(ctx, pending.EnrollmentID, scope, pending.EnrollmentSecret); err != nil {
				return err
			}
		}
		private = ed25519.PrivateKey(pending.SigningKey)
		if len(pending.ResultJSON) != 0 {
			if json.Unmarshal(pending.ResultJSON, &member) != nil {
				return grouppublisher.ErrAssignment
			}
		} else {
			member, err = groupClient.Enroll(ctx, string(pending.EnrollmentSecret), private.Public().(ed25519.PublicKey))
			if err != nil {
				return err
			}
		}
		if member.ProjectKey != flags.ProjectKey || member.GroupId == "" || member.PublisherIdentityId == "" || member.KeyId == "" {
			return grouppublisher.ErrAssignment
		}
		data, err := json.Marshal(member)
		if err != nil {
			return err
		}
		if err := profile.RecordPublisherEnrollmentResult(ctx, pending.EnrollmentID, data); err != nil {
			return err
		}
		if err := profile.PromotePublisherEnrollment(ctx, pending.EnrollmentID, clientstate.PublisherIdentity{ID: member.PublisherIdentityId, PublicDocument: data, SigningKey: private}); err != nil {
			return err
		}
	}
	if member.ProjectKey != flags.ProjectKey || len(private) != ed25519.PrivateKeySize {
		return grouppublisher.ErrAssignment
	}
	value, err := credentialfile.NewGroup(server, flags.Instance, member, private)
	if err != nil {
		return err
	}
	member, private, err = importPublisherGroupIdentity(ctx, profile, groupClient, value, server, flags.ProjectKey, flags.Group, flags.Instance)
	if err != nil {
		return err
	}
	job := publisherjob.Job{Kind: publisherjob.KindGroup, ID: publisherjob.JobKey(server, "group", member.GroupId+":"+flags.Instance), Name: flags.Group + "-" + flags.Instance, Server: server, PublisherID: member.PublisherIdentityId, GroupMember: &member, GroupInstance: flags.Instance}
	job.IdentityDir = profile.IdentityDirectory()
	if flags.Install {
		registry, err := publisherjob.Open(ctx, publisherjob.OpenOptions{Root: options.Root, User: true})
		if err != nil {
			return err
		}
		defer registry.Close()
		if err := registry.InstallGroup(ctx, job, member, private); err != nil {
			return err
		}
		return writeSystemJobs(ctx, registry, output, "tnl publisher serve", job.ID)
	}
	detachedPublicationStarting(ctx)
	return servePublisherGroup(ctx, job, profile, private, func(revision int64, healthy bool) error {
		if healthy {
			detachedPublicationReady(ctx)
		}
		state := "reconciling"
		if healthy {
			state = "ready"
		}
		current, found, err := credentialfile.SavedGroup(profile, server, member.ProjectKey, member.GroupId, flags.Instance)
		if err != nil {
			return err
		}
		if found {
			member = current.Member
		}
		return writeHumanFrame(diagnostics, "tnl publisher serve", state, "", clioutput.Fields(clioutput.Field{Label: "group", Value: member.GroupName}, clioutput.Field{Label: "project key", Value: member.ProjectKey}, clioutput.Field{Label: "observed revision", Value: strconv.FormatInt(revision, 10)}))
	}, func(service string, event publisher.Event) error {
		if event.Type == publisher.EventProvisioningStep {
			return writeHumanFrame(diagnostics, "tnl publisher serve", "provisioning", "", clioutput.Fields(clioutput.Field{Label: "service", Value: service}, clioutput.Field{Label: "stage", Value: event.ProvisioningStage}))
		}
		return nil
	})
}

func servePublisherGroup(ctx context.Context, job publisherjob.Job, profile *clientstate.Store, private ed25519.PrivateKey, observe func(int64, bool) error, progress ...func(string, publisher.Event) error) error {
	deployment, err := publisherprovenance.ReadEnvironment(os.LookupEnv, job.GroupInstance, buildinfo.Version)
	if err != nil {
		return err
	}
	if job.IdentityDir != "" {
		var err error
		profile, err = profile.WithIdentityDirectory(job.IdentityDir)
		if err != nil {
			return err
		}
	}
	client, err := grouppublisher.NewClient(job.Server, nil)
	if err != nil {
		return err
	}
	control, authority, err := publisherjob.Clients(job)
	if err != nil {
		return err
	}
	member := *job.GroupMember
	return withPublisherCertificateState(ctx, job, profile, private, client, func(ctx context.Context) error {
		err := (grouppublisher.Runtime{Control: client, Member: member, Private: private, Deployment: deployment, Observe: observe, MemberChanged: func(current controlv1.PublisherGroupMember) error {
			value, err := credentialfile.NewGroup(job.Server, job.GroupInstance, current, private)
			if err != nil {
				return err
			}
			if err := credentialfile.RetainGroup(ctx, profile, value); err != nil {
				return err
			}
			_, err = credentialfile.ImportGroup(ctx, profile, value, job.Server, current.ProjectKey, current.GroupName, job.GroupInstance)
			return err
		}, Publish: func(ctx context.Context, assignment controlv1.PublisherGroupServiceAssignment, health func(bool)) error {
			identity := authorityv1.PublisherEnrollmentResult{ClientId: member.PublisherIdentityId, KeyId: member.KeyId, TeamId: member.TeamId, GrantId: assignment.GrantId}
			if assignment.ServiceKind == "private_service" {
				identity.Kind, identity.PrivateServiceId = authorityv1.PrivateService, &assignment.ServiceId
			} else {
				return grouppublisher.ErrAssignment
			}
			native, err := nativeauth.NewNative(control, authority, identity, private)
			if err != nil {
				return err
			}
			if assignment.ServiceKind == "private_service" {
				service, err := native.SavedPrivateService(ctx)
				if err != nil {
					return err
				}
				if service.Id != assignment.ServiceId || service.TrustRevision != assignment.TrustRevision || assignment.Configuration.Protocol == nil || service.Protocol != *assignment.Configuration.Protocol {
					return grouppublisher.ErrAssignment
				}
				privateJob := publisherjob.Job{Kind: publisherjob.KindPrivateService, Protocol: config.ProtocolName(service.Protocol), Target: assignment.Configuration.Target}
				if err := assignedTargetTrust(&privateJob, assignment.Configuration.TargetTls); err != nil {
					return err
				}
				var ready atomic.Bool
				return publisherjob.PublishPrivate(ctx, privateJob, privatepublisher.RunConfig{Control: native, State: profile, Access: native.Access, Identity: identity, PrivateServiceID: service.Id, Target: assignment.Configuration.Target, Metadata: nativeauth.PrivateServiceMetadata(service),
					Healthy: func(ctx context.Context) bool {
						healthy := publisherjob.PreflightPrivate(ctx, privateJob) == nil
						if ready.Load() {
							health(healthy)
						}
						return healthy
					}, Ready: func() error { ready.Store(true); health(true); return nil },
				})
			}
			return grouppublisher.ErrAssignment
		}}).Serve(ctx)
		if errors.Is(err, grouppublisher.ErrAssignment) {
			return errors.Join(publisherjob.ErrScope, err)
		}
		return err
	})
}
