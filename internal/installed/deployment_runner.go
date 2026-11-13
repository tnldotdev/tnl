package installed

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	clienttelemetry "github.com/tnldotdev/tnl/internal/client/telemetry"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/policy/publisherprovenance"
	publisherdeployment "github.com/tnldotdev/tnl/internal/publisher/deployment"
	"github.com/tnldotdev/tnl/internal/publisher/identity/credentialfile"
	publisherdiscovery "github.com/tnldotdev/tnl/internal/publisher/target/discovery"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// DeploymentRunner assembles the same deployment lifecycle for foreground and supervised
// jobs. dependencies are explicit; nil discovery providers are rejected
// rather than selecting process credentials. providers must honor cancellation.
type DeploymentRunner struct {
	Telemetry  *clienttelemetry.Collector
	scope      *deploymentRunnerScope
	Discovery  publisherdiscovery.Provider
	Deployment *controlv1.PublisherDeploymentReport
	// Startup bounds finite setup only, never a deployment's lease lifetime.
	Startup *OperationLimiter
}

type deploymentRunnerScope struct {
	identity                 DeploymentScope
	project, instance, keyID string
	public                   ed25519.PublicKey
}

func (r DeploymentRunner) Serve(ctx context.Context, job Job, profile *clientstate.Store, private ed25519.PrivateKey, observe func(int64, bool) error) (result error) {
	if validateJob(&job) != nil || job.Kind != KindDeployment || profile == nil || r.Discovery == nil || publisherprovenance.Validate(r.Deployment) != nil || r.Deployment != nil && r.Deployment.Instance != job.DeploymentInstance {
		return ErrScope
	}
	if r.scope != nil {
		s := r.scope
		if s.identity != (DeploymentScope{job.Server, job.DeploymentMember.TeamId, job.DeploymentMember.DeploymentId, job.PublisherIdentityID}) || s.project != job.DeploymentMember.ProjectKey || s.instance != job.DeploymentInstance || s.keyID != job.DeploymentMember.KeyId || len(private) != ed25519.PrivateKeySize || !bytes.Equal(s.public, private.Public().(ed25519.PublicKey)) {
			return ErrScope
		}
	}
	identity := observability.Identity{TeamID: job.DeploymentMember.TeamId, DeploymentID: job.DeploymentMember.DeploymentId, PublisherIdentityID: job.DeploymentMember.PublisherIdentityId}
	if r.Deployment != nil {
		identity.ReportedDeploymentID, identity.ReplicaKey = r.Deployment.DeploymentId, r.Deployment.ReplicaKey
	}
	ctx = observability.ReplaceIdentity(ctx, identity)
	setup, finishStartup := observability.PublisherOperation(ctx, "deployment_startup")
	defer func() { finishStartup(result) }()
	if job.IdentityDir != "" {
		var err error
		profile, err = profile.WithIdentityDirectory(job.IdentityDir)
		if err != nil {
			return err
		}
	}
	release, err := r.Startup.Acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	setupCtx, cancelSetup := context.WithTimeout(setup, 30*time.Second)
	defer cancelSetup()
	signingLock, err := profile.LockPublisherSigningIdentity(setupCtx, credentialfile.DeploymentSelection(job.DeploymentMember.ProjectKey, job.DeploymentMember.DeploymentId, job.DeploymentInstance))
	if err != nil {
		return err
	}
	defer signingLock.Close()
	client, err := DeploymentClient(job)
	if err != nil {
		return err
	}
	control, authority, err := Clients(job)
	if err != nil {
		return err
	}
	member := *job.DeploymentMember
	value, err := credentialfile.NewDeployment(job.Server, job.DeploymentInstance, member, private)
	if err != nil {
		return errors.Join(ErrScope, err)
	}
	value, err = credentialfile.ResolveDeployment(setupCtx, client, value, job.Server, member.ProjectKey, member.DeploymentName, job.DeploymentInstance)
	if err != nil {
		return err
	}
	member = value.Member
	if err := credentialfile.RetainDeployment(setupCtx, profile, value); err != nil {
		return err
	}
	if _, err := credentialfile.ImportDeployment(setupCtx, profile, value, job.Server, member.ProjectKey, member.DeploymentName, job.DeploymentInstance); err != nil {
		return err
	}
	job.DeploymentMember = &member
	resolver, err := publisherdiscovery.New(r.Discovery, publisherdiscovery.Options{})
	if err != nil {
		return err
	}
	// Runtime.Serve joins assignments before shared discovery is canceled/joined.
	defer resolver.Close()
	publications := publisherdeployment.AssignmentPublisher{Telemetry: r.Telemetry, Member: member, Private: private, State: profile, Control: control.NativeControl, Authority: authority, Discovery: resolver}
	return WithCertificateState(setupCtx, job, profile, private, client, func(_ context.Context) error {
		finishStartup(nil)
		ctx = observability.Independent(setup)
		cancelSetup()
		release()
		err := (publisherdeployment.Runtime{Control: client, Member: member, Private: private, Deployment: r.Deployment, Observe: observe, MemberChanged: func(current controlv1.DeploymentPublisherIdentity) error {
			value, err := credentialfile.NewDeployment(job.Server, job.DeploymentInstance, current, private)
			if err != nil {
				return err
			}
			if err := credentialfile.RetainDeployment(ctx, profile, value); err != nil {
				return err
			}
			_, err = credentialfile.ImportDeployment(ctx, profile, value, job.Server, current.ProjectKey, current.DeploymentName, job.DeploymentInstance)
			return err
		}, Publish: publications.Publish}).Serve(ctx)
		if errors.Is(err, publisherdeployment.ErrAssignment) {
			return errors.Join(ErrScope, err)
		}
		return err
	})
}

// WithCertificateState holds the durable replica writer lock across setup and
// serving. control's issuance history forbids silently replacing lost TLS keys.
func WithCertificateState(ctx context.Context, job Job, profile *clientstate.Store, private ed25519.PrivateKey, client *publisherdeployment.Client, serve func(context.Context) error) error {
	if job.DeploymentMember == nil {
		return ErrScope
	}
	member := *job.DeploymentMember
	files, err := profile.PublisherIdentityFiles(member.TeamId, member.PublisherIdentityId)
	if err != nil {
		return err
	}
	lock, err := files.Lock(ctx, "publisher.lock")
	if err != nil {
		return err
	}
	defer lock.Close()
	lease, err := client.Lease(ctx, member, private)
	if err != nil {
		return err
	}
	assignments, err := client.Assignments(ctx, lease.AccessToken)
	if err != nil {
		return err
	}
	actual := assignments.Member
	actual.DeploymentName = member.DeploymentName
	if actual != member || assignments.CertificateStatePlans == nil {
		return failure.Wrap("read publisher certificate recovery boundary", failure.ServerResponseInvalid, ErrScope)
	}
	found, err := profile.PublisherCertificateMaterialExists(ctx, member.TeamId, member.PublisherIdentityId)
	if err != nil {
		return err
	}
	if len(assignments.CertificateStatePlans) != 0 && !found {
		return failure.Wrap("restore publisher certificate state", failure.PublisherCertificateStateMissing, clientstate.ErrPublisherStateConflict)
	}
	if len(assignments.CertificateStatePlans) != 0 {
		if err := profile.RequirePublisherCertificatePlans(ctx, member.TeamId, member.PublisherIdentityId, assignments.CertificateStatePlans); err != nil {
			return failure.Wrap("restore every publisher certificate plan", failure.PublisherCertificateStateMissing, err)
		}
	}
	return serve(ctx)
}
