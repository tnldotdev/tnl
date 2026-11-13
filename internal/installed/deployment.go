package installed

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"net/http"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	publisherdeployment "github.com/tnldotdev/tnl/internal/publisher/deployment"
	"github.com/tnldotdev/tnl/internal/publisher/identity/credentialfile"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// DeploymentClient uses the same selected control trust as native service clients.
// deployment HTTPS and discovered target TLS remain independent trust boundaries.
func DeploymentClient(job Job) (*publisherdeployment.Client, error) {
	roots, err := trustRoots(job.ServerCAPEM)
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}
	transport.DisableKeepAlives = true
	return publisherdeployment.NewClient(job.Server, &http.Client{Transport: transport})
}

type DeploymentInstall struct {
	Job     Job
	Private ed25519.PrivateKey
}

func (DeploymentInstall) String() string   { return "deployment installation" }
func (DeploymentInstall) GoString() string { return "deployment installation" }

// ReplaceDeployments installs the fixed startup list as one desired-state snapshot.
// it is available only to an identity-only standalone registry. an omitted job
// cannot accidentally resume from a previous invocation's list.
func (r *Registry) ReplaceDeployments(ctx context.Context, inputs []DeploymentInstall) error {
	if !r.deployments || r.user || len(inputs) == 0 || len(inputs) > 256 {
		return ErrScope
	}
	jobs := make([]Job, 0, len(inputs))
	seen, replicas := map[string]bool{}, map[string]bool{}
	for _, input := range inputs {
		job := input.Job
		if validateJob(&job) != nil || job.Kind != KindDeployment || len(input.Private) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(input.Private.Seed()), input.Private) {
			return ErrScope
		}
		owner := JobKey(job.Server, "publisher", job.PublisherIdentityID)
		replica := JobKey(job.Server, "deployment", job.DeploymentMember.DeploymentId+":"+job.DeploymentInstance)
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
			if old.Kind != KindDeployment {
				return ErrScope
			}
			member, private, profile, err := r.DeploymentIdentity(ctx, old)
			if err != nil {
				return err
			}
			value, err := credentialfile.NewDeployment(old.Server, old.DeploymentInstance, member, private)
			if err != nil {
				return err
			}
			if err := credentialfile.RetireDeployment(ctx, profile, value); err != nil {
				return err
			}
		}
		for i, job := range jobs {
			if err := r.retainDeployment(ctx, job, *job.DeploymentMember, inputs[i].Private); err != nil {
				return err
			}
		}
		*existing = jobs
		return nil
	})
}

// InstallDeployment captures the task's own signing identity. no person session or
// project checkout is required by the supervisor after installation.
func (r *Registry) InstallDeployment(ctx context.Context, job Job, member controlv1.DeploymentPublisherIdentity, private ed25519.PrivateKey) error {
	if !r.deployments || job.Kind != KindDeployment || job.DeploymentMember == nil || *job.DeploymentMember != member || len(private) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(private.Seed()), private) {
		return ErrScope
	}
	if err := validateJob(&job); err != nil {
		return err
	}
	return r.update(ctx, func(jobs *[]Job) error {
		for i, existing := range *jobs {
			if existing.ID != job.ID {
				if existing.Server == job.Server && (existing.PublisherIdentityID == job.PublisherIdentityID || existing.DeploymentMember != nil && existing.DeploymentMember.DeploymentId == member.DeploymentId && existing.DeploymentInstance == job.DeploymentInstance) {
					return ErrJobExists
				}
				continue
			}
			if existing.DeploymentMember == nil || !credentialfile.SameDeploymentIdentity(*existing.DeploymentMember, member) || existing.Server != job.Server || existing.DeploymentInstance != job.DeploymentInstance {
				return ErrScope
			}
			_, key, _, err := r.DeploymentIdentity(ctx, existing)
			if err != nil || !bytes.Equal(key, private) {
				return ErrScope
			}
			if err := r.retainDeployment(ctx, job, member, private); err != nil {
				return err
			}
			job.Enabled, job.Revision, job.Status = true, existing.Revision+1, Status{State: JobStarting}
			(*jobs)[i] = job
			return nil
		}
		if len(*jobs) >= 1024 {
			return ErrScope
		}
		if err := r.retainDeployment(ctx, job, member, private); err != nil {
			return err
		}
		job.Enabled, job.Revision, job.Status = true, 1, Status{State: JobStarting}
		*jobs = append(*jobs, job)
		return nil
	})
}

func (r *Registry) deploymentProfile(ctx context.Context, job Job) (*clientstate.Store, error) {
	profile, err := r.Profile(ctx, job.Server)
	if err == nil && job.IdentityDir != "" {
		profile, err = profile.WithIdentityDirectory(job.IdentityDir)
	}
	return profile, err
}

func (r *Registry) retainDeployment(ctx context.Context, job Job, member controlv1.DeploymentPublisherIdentity, private ed25519.PrivateKey) error {
	profile, err := r.deploymentProfile(ctx, job)
	if err != nil {
		return err
	}
	value, err := credentialfile.NewDeployment(job.Server, job.DeploymentInstance, member, private)
	if err != nil {
		return errors.Join(ErrScope, err)
	}
	if err := credentialfile.RetainDeployment(ctx, profile, value); err != nil {
		return errors.Join(ErrScope, err)
	}
	return nil
}

func (r *Registry) DeploymentIdentity(ctx context.Context, job Job) (controlv1.DeploymentPublisherIdentity, ed25519.PrivateKey, *clientstate.Store, error) {
	var member controlv1.DeploymentPublisherIdentity
	if job.Kind != KindDeployment || job.DeploymentMember == nil {
		return member, nil, nil, ErrScope
	}
	profile, err := r.deploymentProfile(ctx, job)
	if err != nil {
		return member, nil, nil, err
	}
	saved, found, err := credentialfile.SavedDeployment(profile, job.Server, job.DeploymentMember.ProjectKey, job.DeploymentMember.DeploymentId, job.DeploymentInstance)
	if err != nil {
		return member, nil, nil, err
	}
	if !found || !credentialfile.SameDeploymentIdentity(saved.Member, *job.DeploymentMember) {
		return member, nil, nil, ErrScope
	}
	private, err := saved.Validate(job.Server, job.DeploymentMember.ProjectKey, job.DeploymentMember.DeploymentName, job.DeploymentInstance)
	if err != nil {
		return member, nil, nil, errors.Join(ErrScope, err)
	}
	return saved.Member, private, profile, nil
}
