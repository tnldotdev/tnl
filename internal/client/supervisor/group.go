package supervisor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"net/http"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	publishergroup "github.com/tnldotdev/tnl/internal/publisher/group"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/publisher/identity/credentialfile"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	targetplan "github.com/tnldotdev/tnl/internal/publisher/target"
	publisherdiscovery "github.com/tnldotdev/tnl/internal/publisher/target/discovery"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// GroupClient uses the same selected control trust as native service clients.
// group HTTPS and discovered target TLS remain independent trust boundaries.
func GroupClient(job Job) (*publishergroup.Client, error) {
	roots, err := trustRoots(job.ServerCAPEM)
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}
	transport.DisableKeepAlives = true
	return publishergroup.NewClient(job.Server, &http.Client{Transport: transport})
}

// GroupPublisher is the common foreground/installed assignment callback. its
// resolver belongs to the surrounding group loop and outlives all its workers.
type GroupPublisher struct {
	Member    controlv1.PublisherGroupMember
	Private   ed25519.PrivateKey
	State     *clientstate.Store
	Control   publisheridentity.NativeControl
	Authority publisheridentity.AssertionExchanger
	Discovery *publisherdiscovery.Resolver
}

type GroupInstall struct {
	Job     Job
	Private ed25519.PrivateKey
}

func (GroupInstall) String() string   { return "publisher group installation" }
func (GroupInstall) GoString() string { return "publisher group installation" }

// ReplaceGroups installs the fixed startup list as one desired-state snapshot.
// it is available only to an identity-only standalone registry. an omitted job
// cannot accidentally resume from a previous invocation's list.
func (r *Registry) ReplaceGroups(ctx context.Context, inputs []GroupInstall) error {
	if !r.groups || r.user || len(inputs) == 0 || len(inputs) > 256 {
		return ErrScope
	}
	jobs := make([]Job, 0, len(inputs))
	seen, replicas := map[string]bool{}, map[string]bool{}
	for _, input := range inputs {
		job := input.Job
		if validateJob(&job) != nil || job.Kind != KindGroup || len(input.Private) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(input.Private.Seed()), input.Private) {
			return ErrScope
		}
		owner := JobKey(job.Server, "publisher", job.PublisherIdentityID)
		replica := JobKey(job.Server, "group", job.GroupMember.GroupId+":"+job.GroupInstance)
		if seen[owner] || replicas[replica] || job.ID != replica {
			return ErrJobExists
		}
		seen[owner], replicas[replica] = true, true
		job.Enabled, job.Revision, job.Status = true, 1, Status{State: JobStarting}
		jobs = append(jobs, job)
	}
	return r.update(ctx, func(existing *[]Job) error {
		// Engine.Initialize holds exclusive supervisor ownership before this
		// fixed-list replacement. omitted replicas leave active name discovery;
		// their durable signing authority is retained behind immutable pins.
		for _, old := range *existing {
			if seen[JobKey(old.Server, "publisher", old.PublisherIdentityID)] {
				continue
			}
			if old.Kind != KindGroup {
				return ErrScope
			}
			member, private, profile, err := r.GroupIdentity(ctx, old)
			if err != nil {
				return err
			}
			value, err := credentialfile.NewGroup(old.Server, old.GroupInstance, member, private)
			if err != nil {
				return err
			}
			if err := credentialfile.RetireGroup(ctx, profile, value); err != nil {
				return err
			}
		}
		for i, job := range jobs {
			if err := r.retainGroup(ctx, job, *job.GroupMember, inputs[i].Private); err != nil {
				return err
			}
		}
		*existing = jobs
		return nil
	})
}

func (GroupPublisher) String() string   { return "publisher group publications" }
func (GroupPublisher) GoString() string { return "publisher group publications" }

func (p GroupPublisher) Publish(ctx context.Context, assignment controlv1.PublisherGroupServiceAssignment, health func(bool)) error {
	if assignment.ServiceKind != "service" || assignment.Configuration.Protocol == nil || assignment.TrustRevision < 1 || assignment.Configuration.PublisherGroup == nil || *assignment.Configuration.PublisherGroup == "" || *assignment.Configuration.PublisherGroup == "local" {
		return publishergroup.ErrAssignment
	}
	identity := authorityv1.PublisherEnrollmentResult{ClientId: p.Member.PublisherIdentityId, KeyId: p.Member.KeyId, TeamId: p.Member.TeamId, GrantId: assignment.GrantId, Kind: authorityv1.Service, ServiceId: &assignment.ServiceId}
	native, err := publisheridentity.NewNative(p.Control, p.Authority, identity, p.Private)
	if err != nil {
		return err
	}
	service, err := native.SavedService(ctx)
	if err != nil {
		return err
	}
	if service.Id != assignment.ServiceId || service.TrustRevision != assignment.TrustRevision || service.Protocol != *assignment.Configuration.Protocol {
		return publishergroup.ErrAssignment
	}
	run := publisherservice.RunConfig{Control: native, State: p.State, Access: native.Access, Identity: identity, ServiceID: service.Id, Metadata: publisheridentity.ServiceMetadata(service), ObserveReadiness: func(status publisherservice.RunStatus) {
		if health != nil {
			health(status.Ready)
		}
	}}
	if assignment.Configuration.TargetDiscovery != nil {
		// Service carries approved protocol/trust revision, not a second
		// selector. the exact authenticated assignment owns the cloud descriptor.
		if service.TargetTls != nil {
			return publishergroup.ErrAssignment
		}
		request, err := publishergroup.AssignmentDiscovery(assignment.Configuration)
		if err != nil {
			return err
		}
		return publishergroup.PublishCloudAssignment(ctx, p.Discovery, request, run)
	}
	plan := targetplan.TargetPlan{Protocol: config.ProtocolName(service.Protocol), Target: assignment.Configuration.Target}
	if trust := assignment.Configuration.TargetTls; trust != nil {
		snapshot := clientproject.TargetTrustSnapshot{Hostname: trust.Hostname, Digest: trust.Digest}
		if trust.CaPem != nil {
			snapshot.CAPEM = []byte(*trust.CaPem)
		}
		plan.Trust, err = snapshot.TargetTrust()
		if err != nil {
			return err
		}
	}
	if err := publisheridentity.MatchServiceDeclaration(service, string(plan.Protocol), plan.Trust); err != nil {
		return err
	}
	run.Target = plan.Target
	return targetplan.PublishPrivate(ctx, plan, run)
}

// InstallGroup captures the task's own signing identity. no person session or
// project checkout is required by the supervisor after installation.
func (r *Registry) InstallGroup(ctx context.Context, job Job, member controlv1.PublisherGroupMember, private ed25519.PrivateKey) error {
	if !r.groups || job.Kind != KindGroup || job.GroupMember == nil || *job.GroupMember != member || len(private) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(private.Seed()), private) {
		return ErrScope
	}
	if err := validateJob(&job); err != nil {
		return err
	}
	return r.update(ctx, func(jobs *[]Job) error {
		for i, existing := range *jobs {
			if existing.ID != job.ID {
				if existing.Server == job.Server && (existing.PublisherIdentityID == job.PublisherIdentityID || existing.GroupMember != nil && existing.GroupMember.GroupId == member.GroupId && existing.GroupInstance == job.GroupInstance) {
					return ErrJobExists
				}
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
			job.Enabled, job.Revision, job.Status = true, existing.Revision+1, Status{State: JobStarting}
			(*jobs)[i] = job
			return nil
		}
		if len(*jobs) >= 1024 {
			return ErrScope
		}
		if err := r.retainGroup(ctx, job, member, private); err != nil {
			return err
		}
		job.Enabled, job.Revision, job.Status = true, 1, Status{State: JobStarting}
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
