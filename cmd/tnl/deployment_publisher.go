package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/tnldotdev/tnl/internal/buildinfo"
	"github.com/tnldotdev/tnl/internal/client/detached"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	clienttelemetry "github.com/tnldotdev/tnl/internal/client/telemetry"
	"github.com/tnldotdev/tnl/internal/clioutput"
	installedjobs "github.com/tnldotdev/tnl/internal/installed"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/publisherprovenance"
	publisherdeployment "github.com/tnldotdev/tnl/internal/publisher/deployment"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/publisher/identity/credentialfile"
	"github.com/tnldotdev/tnl/internal/publisher/invocation"
	publisherdiscovery "github.com/tnldotdev/tnl/internal/publisher/target/discovery"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type publisherServeCommand struct {
	telemetry         *clienttelemetry.Collector
	telemetryDisabled bool
	scopedTeamFlags   `embed:""`
	Deployment        string   `name:"deployment" help:"Saved deployment name or ID; omit to use the identities bound in --identity-file."`
	ProjectKey        string   `name:"project-key" help:"Applied project key; defaults to the current Git configuration source."`
	EnrollmentKey     string   `name:"enroll-key" env:"TNL_DEPLOYMENT_ENROLL_KEY" help:"Scoped enrollment from publisher setup --deployment --service; use - to read stdin. Serving never approves its own bindings."`
	IdentityFile      []string `name:"identity-file" type:"path" help:"Private portable deployment identity. Repeat for independent deployments in this process, omitting --deployment. Single-deployment mode also accepts TNL_DEPLOYMENT_IDENTITY."`
	BindingFile       []string `name:"binding-file" type:"path" help:"Operator-owned local dependency binding for an immutable deployment identity. Repeat per deployment; omitted bindings deny secret and cloud access."`
	IdentityDir       string   `name:"identity-dir" env:"TNL_IDENTITY_DIR" type:"path" help:"Durable publisher identity and TLS files; defaults to identities beneath the state directory. Keep SQLite task-local when using a network mount."`
	Instance          string   `name:"instance" default:"default" help:"Replica identity name; must match the portable identity when supplied."`
	Foreground        bool     `name:"foreground" help:"Run in this terminal (the default)."`
	Detach            bool     `name:"detach" help:"Run independently of this terminal without automatic restart."`
	Install           bool     `name:"install" help:"Run durably with the user publisher supervisor."`
	System            bool     `name:"system" hidden:""`
	SystemStateDir    string   `name:"system-state-dir" type:"path"`
	DetachedChild     string   `name:"detached-child" hidden:""`

	identityInputRead bool
	identity          *credentialfile.DeploymentFile
}

func validatePublisherServe(flags publisherServeCommand) error {
	if flags.fixedList() {
		return validateFixedDeploymentRuntime(flags)
	}
	if !validDeploymentSelector(flags.Deployment) || !naming.ValidServiceName(flags.Instance) {
		return publisherCLIError("select a configured deployment other than local and a lowercase instance name")
	}
	if flags.System {
		return publisherCLIError("deployments use the user supervisor; --system requires an explicit single-service publisher")
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

func runPublisherServe(ctx context.Context, flags publisherServeCommand, project projectConfiguration, output, diagnostics io.Writer) error {
	if flags.fixedList() {
		return runFixedDeploymentRuntime(ctx, flags, diagnostics)
	}
	if err := validatePublisherServe(flags); err != nil {
		return err
	}
	var options installedjobs.ServiceOptions
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
	if err := prepareDeploymentIdentity(&flags); err != nil {
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
		if _, err := flags.identity.Validate(flags.ServerURL, flags.ProjectKey, flags.Deployment, flags.Instance); err != nil {
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
	deploymentClient, err := publisherdeployment.NewClient(server, nil)
	if err != nil {
		return err
	}
	if flags.identity == nil {
		value, found, err := credentialfile.ResolveSavedDeployment(ctx, profile, deploymentClient, server, flags.ProjectKey, flags.Deployment, flags.Instance)
		if err != nil {
			return err
		}
		if found {
			flags.identity = &value
		}
	}
	deploymentIdentity := flags.Deployment
	if flags.identity != nil {
		deploymentIdentity = flags.identity.Member.DeploymentId
	}
	scope := credentialfile.DeploymentSelection(flags.ProjectKey, deploymentIdentity, flags.Instance)
	lock, err := profile.LockPublisherSigningIdentity(ctx, scope)
	if err != nil {
		return err
	}
	defer lock.Close()
	if flags.identity != nil {
		if _, _, err := importDeploymentIdentity(ctx, profile, deploymentClient, *flags.identity, server, flags.ProjectKey, flags.Deployment, flags.Instance); err != nil {
			return err
		}
		scope = credentialfile.DeploymentSelection(flags.ProjectKey, flags.identity.Member.DeploymentId, flags.Instance)
	}
	saved, found, err := profile.SelectedPublisherIdentity(ctx, "project", scope)
	if err != nil {
		return err
	}
	var member controlv1.DeploymentPublisherIdentity
	var private ed25519.PrivateKey
	if found {
		if json.Unmarshal(saved.PublicDocument, &member) != nil || member.PublisherIdentityId == "" {
			return publisherdeployment.ErrAssignment
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
			return publisheridentity.ErrScope
		}
		if len(pending.ResultJSON) == 0 && (len(pending.EnrollmentSecret) == 0 || flags.EnrollmentKey != "") {
			secret := ""
			if flags.EnrollmentKey != "" {
				secret, err = invocation.EnrollmentKeyInput(flags.EnrollmentKey, os.Stdin)
			} else {
				return publisherCLIError("supply --enroll-key from publisher setup --deployment --service; serving cannot approve its own bindings")
			}
			if err != nil {
				return err
			}
			// refreshing bootstrap keeps the protected key, including after a
			// lost redemption response. the server recognizes that same key.
			pending.EnrollmentSecret = []byte(secret)
			if err := profile.SetDeploymentPublisherEnrollmentSecret(ctx, pending.EnrollmentID, scope, pending.EnrollmentSecret); err != nil {
				return err
			}
		}
		private = ed25519.PrivateKey(pending.SigningKey)
		if len(pending.ResultJSON) != 0 {
			if json.Unmarshal(pending.ResultJSON, &member) != nil {
				return publisherdeployment.ErrAssignment
			}
		} else {
			member, err = deploymentClient.Enroll(ctx, string(pending.EnrollmentSecret), private.Public().(ed25519.PublicKey))
			if err != nil {
				return err
			}
		}
		if member.ProjectKey != flags.ProjectKey || member.DeploymentId == "" || member.PublisherIdentityId == "" || member.KeyId == "" {
			return publisherdeployment.ErrAssignment
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
		return publisherdeployment.ErrAssignment
	}
	value, err := credentialfile.NewDeployment(server, flags.Instance, member, private)
	if err != nil {
		return err
	}
	member, private, err = importDeploymentIdentity(ctx, profile, deploymentClient, value, server, flags.ProjectKey, flags.Deployment, flags.Instance)
	if err != nil {
		return err
	}
	job := installedjobs.Job{Kind: installedjobs.KindDeployment, ID: installedjobs.JobKey(server, "deployment", member.DeploymentId+":"+flags.Instance), Name: flags.Deployment + "-" + flags.Instance, Server: server, PublisherIdentityID: member.PublisherIdentityId, DeploymentMember: &member, DeploymentInstance: flags.Instance}
	job.IdentityDir = profile.IdentityDirectory()
	job.TelemetryDisabled = flags.telemetryDisabled
	if flags.Install {
		registry, err := installedjobs.Open(ctx, installedjobs.OpenOptions{Root: options.Root, User: true})
		if err != nil {
			return err
		}
		defer registry.Close()
		if err := registry.InstallDeployment(ctx, job, member, private); err != nil {
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
	return serveDeploymentPublisher(ctx, job, profile, private, flags.telemetry, func(revision int64, healthy bool) error {
		if healthy {
			detached.Ready(ctx)
		}
		state := "reconciling"
		if healthy {
			state = "ready"
		}
		current, found, err := credentialfile.SavedDeployment(profile, server, member.ProjectKey, member.DeploymentId, flags.Instance)
		if err != nil {
			return err
		}
		if found {
			member = current.Member
		}
		return writeHumanFrame(diagnostics, "tnl publisher serve", state, "", clioutput.Fields(clioutput.Field{Label: "deployment", Value: member.DeploymentName}, clioutput.Field{Label: "project key", Value: member.ProjectKey}, clioutput.Field{Label: "observed revision", Value: strconv.FormatInt(revision, 10)}))
	})
}

func serveDeploymentPublisher(ctx context.Context, job installedjobs.Job, profile *clientstate.Store, private ed25519.PrivateKey, telemetry *clienttelemetry.Collector, observe func(int64, bool) error) error {
	return serveDeploymentPublisherWithDiscovery(ctx, job, profile, private, telemetry, observe, nil)
}

func serveDeploymentPublisherWithDiscovery(ctx context.Context, job installedjobs.Job, profile *clientstate.Store, private ed25519.PrivateKey, telemetry *clienttelemetry.Collector, observe func(int64, bool) error, provider publisherdiscovery.Provider) error {
	deployment, err := publisherprovenance.ReadEnvironment(os.LookupEnv, job.DeploymentInstance, buildinfo.Version)
	if err != nil {
		return err
	}
	if provider == nil {
		provider = publisherdiscovery.AWS{}
	}
	return (installedjobs.DeploymentRunner{Telemetry: telemetry, Discovery: provider, Deployment: deployment}).Serve(ctx, job, profile, private, observe)
}
