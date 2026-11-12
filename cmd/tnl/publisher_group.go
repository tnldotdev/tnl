package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/tnldotdev/tnl/internal/buildinfo"
	"github.com/tnldotdev/tnl/internal/client/detached"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/client/supervisor"
	"github.com/tnldotdev/tnl/internal/clioutput"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/publisherprovenance"
	publishergroup "github.com/tnldotdev/tnl/internal/publisher/group"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/publisher/identity/credentialfile"
	"github.com/tnldotdev/tnl/internal/publisher/invocation"
	publisherdiscovery "github.com/tnldotdev/tnl/internal/publisher/target/discovery"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type publisherServeCommand struct {
	scopedTeamFlags `embed:""`
	Environment     string   `name:"environment" help:"Exact environment ID; omit to use the identities bound in --identity-file."`
	ProjectKey      string   `name:"project-key" help:"Applied project key; defaults to the current Git configuration source."`
	EnrollmentKey   string   `name:"enroll-key" env:"TNL_ENVIRONMENT_ENROLL_KEY" help:"One-use environment publisher enrollment key; use - to read stdin. New replicas require explicit enrollment."`
	IdentityFile    []string `name:"identity-file" type:"path" help:"Private portable environment publisher identity. Repeat for independent environments, omitting --environment. Single-environment mode also accepts TNL_ENVIRONMENT_PUBLISHER_IDENTITY."`
	BindingFile     []string `name:"binding-file" type:"path" help:"Operator-owned local dependency binding for an immutable environment publisher. Repeat per identity; omitted bindings deny secret and cloud access."`
	IdentityDir     string   `name:"identity-dir" env:"TNL_IDENTITY_DIR" type:"path" help:"Durable publisher identity and TLS files; defaults to identities beneath the state directory. Keep SQLite task-local when using a network mount."`
	Instance        string   `name:"instance" default:"default" help:"Replica identity name; must match the portable identity when supplied."`
	Foreground      bool     `name:"foreground" help:"Run in this terminal (the default)."`
	Detach          bool     `name:"detach" help:"Run independently of this terminal without automatic restart."`
	Install         bool     `name:"install" help:"Run durably with the user publisher supervisor."`
	System          bool     `name:"system" hidden:""`
	SystemStateDir  string   `name:"system-state-dir" type:"path"`
	DetachedChild   string   `name:"detached-child" hidden:""`

	identityInputRead bool
	identity          *credentialfile.GroupFile
}

func validatePublisherServe(flags publisherServeCommand) error {
	if flags.fixedList() {
		return validateFixedPublisherGroups(flags)
	}
	if !opaqueid.Valid(flags.Environment, opaqueid.EnvironmentPrefix) || !naming.ValidServiceName(flags.Instance) {
		return publisherCLIError("select an exact --environment ID and a lowercase instance name")
	}
	if flags.System {
		return publisherCLIError("environment publishers use the user supervisor; --system requires an explicit single-service publisher")
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
	if !opaqueid.Valid(flags.Environment, opaqueid.EnvironmentPrefix) || flags.PublicURLID != "" || flags.ServiceID != "" || flags.Namespace || flags.Domain != "" || flags.Automation || len(flags.Services) == 0 {
		return publisherCLIError("select --environment ID and --services for one exact environment publisher bootstrap")
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
	}
	session, err := openTeamSession(ctx, flags.selection(), "tnl publisher enroll", diagnostics)
	if err != nil {
		return err
	}
	defer session.Close()
	current, err := session.Current(ctx)
	if err != nil {
		return err
	}
	environment, err := session.Authenticated().Control.GetEnvironment(ctx, current.Team().Id, key, flags.Environment)
	if err != nil {
		return err
	}
	if environment.Id != flags.Environment || environment.ProjectKey != key || environment.TeamId != current.Team().Id {
		return publishergroup.ErrAssignment
	}
	enrollment, err := session.Authenticated().Control.CreateEnvironmentPublisherEnrollment(ctx, key, flags.Environment, "", controlv1.CreateEnvironmentPublisherEnrollmentRequest{TeamId: current.Team().Id, MaxMembers: members, ExpiresIn: expires, ExpectedRevision: environment.MutationRevision, ConfigurationHash: environment.ConfigurationHash, Services: flags.Services})
	if err != nil {
		return err
	}
	if enrollment.EnrollmentKey == "" || enrollment.MaxMembers != members || !enrollment.ExpiresAt.After(time.Now()) || enrollment.Ref.EnvironmentId != flags.Environment || enrollment.Ref.ProjectKey != key || enrollment.Ref.Server != session.Authenticated().ServerEndpoint {
		return publishergroup.ErrAssignment
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
	if flags.fixedList() {
		return runFixedPublisherGroups(ctx, flags, diagnostics)
	}
	if err := validatePublisherServe(flags); err != nil {
		return err
	}
	var options supervisor.ServiceOptions
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
		if _, err := flags.identity.Validate(flags.ServerURL, flags.ProjectKey, flags.Environment, flags.Instance); err != nil {
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
	groupClient, err := publishergroup.NewClient(server, nil)
	if err != nil {
		return err
	}
	if flags.identity == nil {
		value, found, err := credentialfile.ResolveSavedGroup(ctx, profile, groupClient, server, flags.ProjectKey, flags.Environment, flags.Instance)
		if err != nil {
			return err
		}
		if found {
			flags.identity = &value
		}
	}
	scope := credentialfile.GroupSelection(flags.ProjectKey, flags.Environment, flags.Instance)
	lock, err := profile.LockPublisherSigningIdentity(ctx, scope)
	if err != nil {
		return err
	}
	defer lock.Close()
	if flags.identity != nil {
		if _, _, err := importPublisherGroupIdentity(ctx, profile, groupClient, *flags.identity, server, flags.ProjectKey, flags.Environment, flags.Instance); err != nil {
			return err
		}
		scope = credentialfile.GroupSelection(flags.ProjectKey, flags.identity.Member.EnvironmentId, flags.Instance)
	}
	saved, found, err := profile.SelectedPublisherIdentity(ctx, "project", scope)
	if err != nil {
		return err
	}
	var member controlv1.EnvironmentPublisher
	var private ed25519.PrivateKey
	if found {
		if json.Unmarshal(saved.PublicDocument, &member) != nil || member.PublisherIdentityId == "" {
			return publishergroup.ErrAssignment
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
			if flags.EnrollmentKey == "" {
				return publisherCLIError("this replica has no saved identity; pass --enroll-key or --identity-file")
			}
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
			return publisheridentity.ErrScope
		}
		if len(pending.ResultJSON) == 0 && (len(pending.EnrollmentSecret) == 0 || flags.EnrollmentKey != "") {
			if flags.EnrollmentKey == "" {
				return publisherCLIError("this replica requires its explicit --enroll-key; no person session is used")
			}
			secret, err := invocation.EnrollmentKeyInput(flags.EnrollmentKey, os.Stdin)
			if err != nil {
				return err
			}
			// refreshing bootstrap keeps the protected key, including after a
			// lost redemption response. the server recognizes that same key.
			pending.EnrollmentSecret = []byte(secret)
			if err := profile.SetEnvironmentPublisherEnrollmentSecret(ctx, pending.EnrollmentID, scope, pending.EnrollmentSecret); err != nil {
				return err
			}
		}
		private = ed25519.PrivateKey(pending.SigningKey)
		if len(pending.ResultJSON) != 0 {
			if json.Unmarshal(pending.ResultJSON, &member) != nil {
				return publishergroup.ErrAssignment
			}
		} else {
			member, err = groupClient.Enroll(ctx, string(pending.EnrollmentSecret), private.Public().(ed25519.PublicKey))
			if err != nil {
				return err
			}
		}
		if member.ProjectKey != flags.ProjectKey || member.EnvironmentId != flags.Environment || member.PublisherIdentityId == "" || member.KeyId == "" {
			return publishergroup.ErrAssignment
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
	if member.ProjectKey != flags.ProjectKey || member.EnvironmentId != flags.Environment || len(private) != ed25519.PrivateKeySize {
		return publishergroup.ErrAssignment
	}
	value, err := credentialfile.NewGroup(server, flags.Instance, member, private)
	if err != nil {
		return err
	}
	member, private, err = importPublisherGroupIdentity(ctx, profile, groupClient, value, server, flags.ProjectKey, flags.Environment, flags.Instance)
	if err != nil {
		return err
	}
	job := supervisor.Job{Kind: supervisor.KindGroup, ID: supervisor.JobKey(server, "env", member.EnvironmentId+":"+flags.Instance), Name: flags.Instance, Server: server, PublisherIdentityID: member.PublisherIdentityId, GroupMember: &member, GroupInstance: flags.Instance}
	job.IdentityDir = profile.IdentityDirectory()
	if flags.Install {
		registry, err := supervisor.Open(ctx, supervisor.OpenOptions{Root: options.Root, User: true})
		if err != nil {
			return err
		}
		defer registry.Close()
		if err := registry.InstallGroup(ctx, job, member, private); err != nil {
			return err
		}
		return writeSystemJobs(ctx, registry, output, "tnl publisher serve", job.ID)
	}
	// setup has finished; the reusable runner acquires the immutable selection
	// lock and the durable publisher.lock for its full serving lifetime.
	if err := lock.Close(); err != nil {
		return err
	}
	detached.Starting(ctx)
	return servePublisherGroup(ctx, job, profile, private, func(revision int64, healthy bool) error {
		if healthy {
			detached.Ready(ctx)
		}
		state := "reconciling"
		if healthy {
			state = "ready"
		}
		current, found, err := credentialfile.SavedGroup(profile, server, member.ProjectKey, member.EnvironmentId, flags.Instance)
		if err != nil {
			return err
		}
		if found {
			member = current.Member
		}
		return writeHumanFrame(diagnostics, "tnl publisher serve", state, "", clioutput.Fields(clioutput.Field{Label: "environment ID", Value: member.EnvironmentId}, clioutput.Field{Label: "project key", Value: member.ProjectKey}, clioutput.Field{Label: "observed revision", Value: strconv.FormatInt(revision, 10)}))
	})
}

func servePublisherGroup(ctx context.Context, job supervisor.Job, profile *clientstate.Store, private ed25519.PrivateKey, observe func(int64, bool) error) error {
	return servePublisherGroupWithDiscovery(ctx, job, profile, private, observe, nil)
}

func servePublisherGroupWithDiscovery(ctx context.Context, job supervisor.Job, profile *clientstate.Store, private ed25519.PrivateKey, observe func(int64, bool) error, provider publisherdiscovery.Provider) error {
	deployment, err := publisherprovenance.ReadEnvironment(os.LookupEnv, job.GroupInstance, buildinfo.Version)
	if err != nil {
		return err
	}
	if provider == nil {
		provider = publisherdiscovery.AWS{}
	}
	return (supervisor.GroupRunner{Discovery: provider, Deployment: deployment}).Serve(ctx, job, profile, private, observe)
}
