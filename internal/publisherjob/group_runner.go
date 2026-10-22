package publisherjob

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/grouppublisher"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/publisheridentity/credentialfile"
	"github.com/tnldotdev/tnl/internal/publisherprovenance"
	"github.com/tnldotdev/tnl/internal/targetdiscovery"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

// GroupRunner assembles the same group lifecycle for foreground and supervised
// jobs. dependencies are explicit; nil discovery providers are rejected
// rather than selecting process credentials. providers must honor cancellation.
type GroupRunner struct {
	scope      *groupRunnerScope
	Discovery  targetdiscovery.Provider
	Deployment *controlv1.PublisherDeploymentReport
	// Startup bounds finite setup only, never a group's lease lifetime.
	Startup *OperationLimiter
}

type groupRunnerScope struct {
	identity                 GroupScope
	project, instance, keyID string
	public                   ed25519.PublicKey
}

func (r GroupRunner) Serve(ctx context.Context, job Job, profile *clientstate.Store, private ed25519.PrivateKey, observe func(int64, bool) error) (result error) {
	if validateJob(&job) != nil || job.Kind != KindGroup || profile == nil || r.Discovery == nil || publisherprovenance.Validate(r.Deployment) != nil || r.Deployment != nil && r.Deployment.Instance != job.GroupInstance {
		return ErrScope
	}
	if r.scope != nil {
		s := r.scope
		if s.identity != (GroupScope{job.Server, job.GroupMember.TeamId, job.GroupMember.GroupId, job.PublisherID}) || s.project != job.GroupMember.ProjectKey || s.instance != job.GroupInstance || s.keyID != job.GroupMember.KeyId || len(private) != ed25519.PrivateKeySize || !bytes.Equal(s.public, private.Public().(ed25519.PublicKey)) {
			return ErrScope
		}
	}
	identity := observability.Identity{TeamID: job.GroupMember.TeamId, PublisherGroupID: job.GroupMember.GroupId, PublisherIdentityID: job.GroupMember.PublisherIdentityId}
	if r.Deployment != nil {
		identity.DeploymentID, identity.ReplicaKey = r.Deployment.DeploymentId, r.Deployment.ReplicaKey
	}
	ctx = observability.ReplaceIdentity(ctx, identity)
	setup, finishStartup := observability.PublisherOperation(ctx, "group_startup")
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
	signingLock, err := profile.LockPublisherSigningIdentity(setupCtx, credentialfile.GroupSelection(job.GroupMember.ProjectKey, job.GroupMember.GroupId, job.GroupInstance))
	if err != nil {
		return err
	}
	defer signingLock.Close()
	client, err := GroupClient(job)
	if err != nil {
		return err
	}
	control, authority, err := Clients(job)
	if err != nil {
		return err
	}
	member := *job.GroupMember
	value, err := credentialfile.NewGroup(job.Server, job.GroupInstance, member, private)
	if err != nil {
		return errors.Join(ErrScope, err)
	}
	value, err = credentialfile.ResolveGroup(setupCtx, client, value, job.Server, member.ProjectKey, member.GroupName, job.GroupInstance)
	if err != nil {
		return err
	}
	member = value.Member
	if err := credentialfile.RetainGroup(setupCtx, profile, value); err != nil {
		return err
	}
	if _, err := credentialfile.ImportGroup(setupCtx, profile, value, job.Server, member.ProjectKey, member.GroupName, job.GroupInstance); err != nil {
		return err
	}
	job.GroupMember = &member
	resolver, err := targetdiscovery.New(r.Discovery, targetdiscovery.Options{})
	if err != nil {
		return err
	}
	// Runtime.Serve joins assignments before shared discovery is canceled/joined.
	defer resolver.Close()
	publications := GroupPublisher{Member: member, Private: private, State: profile, Control: control, Authority: authority, Discovery: resolver}
	return WithCertificateState(setupCtx, job, profile, private, client, func(_ context.Context) error {
		finishStartup(nil)
		ctx = observability.Independent(setup)
		cancelSetup()
		release()
		err := (grouppublisher.Runtime{Control: client, Member: member, Private: private, Deployment: r.Deployment, Observe: observe, MemberChanged: func(current controlv1.PublisherGroupMember) error {
			value, err := credentialfile.NewGroup(job.Server, job.GroupInstance, current, private)
			if err != nil {
				return err
			}
			if err := credentialfile.RetainGroup(ctx, profile, value); err != nil {
				return err
			}
			_, err = credentialfile.ImportGroup(ctx, profile, value, job.Server, current.ProjectKey, current.GroupName, job.GroupInstance)
			return err
		}, Publish: publications.Publish}).Serve(ctx)
		if errors.Is(err, grouppublisher.ErrAssignment) {
			return errors.Join(ErrScope, err)
		}
		return err
	})
}

// WithCertificateState holds the durable replica writer lock across setup and
// serving. control's issuance history forbids silently replacing lost TLS keys.
func WithCertificateState(ctx context.Context, job Job, profile *clientstate.Store, private ed25519.PrivateKey, client *grouppublisher.Client, serve func(context.Context) error) error {
	if job.GroupMember == nil {
		return ErrScope
	}
	member := *job.GroupMember
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
	actual.GroupName = member.GroupName
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
