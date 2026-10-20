package publisherjob

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"net/http"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/grouppublisher"
	"github.com/tnldotdev/tnl/internal/privatepublisher"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/internal/publisheridentity/credentialfile"
	nativeauth "github.com/tnldotdev/tnl/internal/publisheridentity/native"
	"github.com/tnldotdev/tnl/internal/targetdiscovery"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

// GroupClient uses the same selected control trust as native service clients.
// group HTTPS and discovered target TLS remain independent trust boundaries.
func GroupClient(job Job) (*grouppublisher.Client, error) {
	roots, err := trustRoots(job.ServerCAPEM)
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}
	transport.DisableKeepAlives = true
	return grouppublisher.NewClient(job.Server, &http.Client{Transport: transport})
}

// GroupPublisher is the common foreground/installed assignment callback. its
// resolver belongs to the surrounding group loop and outlives all its workers.
type GroupPublisher struct {
	Member    controlv1.PublisherGroupMember
	Private   ed25519.PrivateKey
	State     *clientstate.Store
	Control   nativeauth.NativeControl
	Authority nativeauth.AssertionExchanger
	Discovery *targetdiscovery.Resolver
}

func (GroupPublisher) String() string   { return "publisher group publications" }
func (GroupPublisher) GoString() string { return "publisher group publications" }

func (p GroupPublisher) Publish(ctx context.Context, assignment controlv1.PublisherGroupServiceAssignment, health func(bool)) error {
	if assignment.ServiceKind != "private_service" || assignment.Configuration.Protocol == nil || assignment.TrustRevision < 1 {
		return grouppublisher.ErrAssignment
	}
	identity := authorityv1.PublisherEnrollmentResult{ClientId: p.Member.PublisherIdentityId, KeyId: p.Member.KeyId, TeamId: p.Member.TeamId, GrantId: assignment.GrantId, Kind: authorityv1.PrivateService, PrivateServiceId: &assignment.ServiceId}
	native, err := nativeauth.NewNative(p.Control, p.Authority, identity, p.Private)
	if err != nil {
		return err
	}
	service, err := native.SavedPrivateService(ctx)
	if err != nil {
		return err
	}
	if service.Id != assignment.ServiceId || service.TrustRevision != assignment.TrustRevision || service.Protocol != *assignment.Configuration.Protocol {
		return grouppublisher.ErrAssignment
	}
	run := privatepublisher.RunConfig{Control: native, State: p.State, Access: native.Access, Identity: identity, PrivateServiceID: service.Id, Metadata: nativeauth.PrivateServiceMetadata(service), ObserveReadiness: func(status privatepublisher.RunStatus) {
		if health != nil {
			health(status.Ready)
		}
	}}
	if assignment.Configuration.TargetDiscovery != nil {
		// PrivateService carries approved protocol/trust revision, not a second
		// selector. the exact authenticated assignment owns the cloud descriptor.
		if service.TargetTls != nil {
			return grouppublisher.ErrAssignment
		}
		request, err := grouppublisher.AssignmentDiscovery(assignment.Configuration)
		if err != nil {
			return err
		}
		return grouppublisher.PublishCloudAssignment(ctx, p.Discovery, request, run)
	}
	job := Job{Kind: KindPrivateService, Protocol: config.ProtocolName(service.Protocol), Target: assignment.Configuration.Target}
	if trust := assignment.Configuration.TargetTls; trust != nil {
		snapshot := projectconfig.TargetTrustSnapshot{Hostname: trust.Hostname, Digest: trust.Digest}
		if trust.CaPem != nil {
			snapshot.CAPEM = []byte(*trust.CaPem)
		}
		job.Trust, err = snapshot.PrivateSnapshot()
		if err != nil {
			return err
		}
	}
	if err := nativeauth.MatchPrivateServiceDeclaration(service, string(job.Protocol), job.Trust); err != nil {
		return err
	}
	run.Target = job.Target
	return PublishPrivate(ctx, job, run)
}

// InstallGroup captures the task's own signing identity. no person session or
// project checkout is required by the supervisor after installation.
func (r *Registry) InstallGroup(ctx context.Context, job Job, member controlv1.PublisherGroupMember, private ed25519.PrivateKey) error {
	if !r.user || job.Kind != KindGroup || job.GroupMember == nil || *job.GroupMember != member || len(private) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(private.Seed()), private) {
		return ErrScope
	}
	if err := validateJob(&job); err != nil {
		return err
	}
	return r.update(ctx, func(jobs *[]Job) error {
		for i, existing := range *jobs {
			if existing.ID != job.ID {
				continue
			}
			if existing.GroupMember == nil || !credentialfile.SameGroupIdentity(*existing.GroupMember, member) || existing.Server != job.Server || existing.GroupInstance != job.GroupInstance {
				return ErrScope
			}
			_, key, _, err := r.GroupIdentity(ctx, existing)
			if err != nil || !bytes.Equal(key, private) {
				return ErrScope
			}
			if err := r.retainGroup(ctx, job, member, private); err != nil {
				return err
			}
			job.Enabled, job.Revision, job.Status = true, existing.Revision+1, Status{State: "starting"}
			(*jobs)[i] = job
			return nil
		}
		if len(*jobs) >= 1024 {
			return ErrScope
		}
		if err := r.retainGroup(ctx, job, member, private); err != nil {
			return err
		}
		job.Enabled, job.Revision, job.Status = true, 1, Status{State: "starting"}
		*jobs = append(*jobs, job)
		return nil
	})
}

func (r *Registry) groupProfile(ctx context.Context, job Job) (*clientstate.Store, error) {
	profile, err := r.Profile(ctx, job.Server)
	if err == nil && job.IdentityDir != "" {
		profile, err = profile.WithIdentityDirectory(job.IdentityDir)
	}
	return profile, err
}

func (r *Registry) retainGroup(ctx context.Context, job Job, member controlv1.PublisherGroupMember, private ed25519.PrivateKey) error {
	profile, err := r.groupProfile(ctx, job)
	if err != nil {
		return err
	}
	value, err := credentialfile.NewGroup(job.Server, job.GroupInstance, member, private)
	if err != nil {
		return errors.Join(ErrScope, err)
	}
	if err := credentialfile.RetainGroup(ctx, profile, value); err != nil {
		return errors.Join(ErrScope, err)
	}
	return nil
}

func (r *Registry) GroupIdentity(ctx context.Context, job Job) (controlv1.PublisherGroupMember, ed25519.PrivateKey, *clientstate.Store, error) {
	var member controlv1.PublisherGroupMember
	if job.Kind != KindGroup || job.GroupMember == nil {
		return member, nil, nil, ErrScope
	}
	profile, err := r.groupProfile(ctx, job)
	if err != nil {
		return member, nil, nil, err
	}
	saved, found, err := credentialfile.SavedGroup(profile, job.Server, job.GroupMember.ProjectKey, job.GroupMember.GroupId, job.GroupInstance)
	if err != nil {
		return member, nil, nil, err
	}
	if !found || !credentialfile.SameGroupIdentity(saved.Member, *job.GroupMember) {
		return member, nil, nil, ErrScope
	}
	private, err := saved.Validate(job.Server, job.GroupMember.ProjectKey, job.GroupMember.GroupName, job.GroupInstance)
	if err != nil {
		return member, nil, nil, errors.Join(ErrScope, err)
	}
	return saved.Member, private, profile, nil
}
