package installed

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"net/http"
	"slices"

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

// fixedDeploymentID preserves the private worker key used by fixed-list
// deployment runtimes. it is not a public job handle.
func fixedDeploymentID(job Job) string {
	digest := sha256.Sum256([]byte(job.Server + "\x00deployment\x00" + job.DeploymentMember.DeploymentId + ":" + job.DeploymentInstance))
	return "dpl-" + hex.EncodeToString(digest[:12])
}

// ReplaceDeployments installs the fixed startup list as one desired-state snapshot
// and returns the saved jobs in input order. an omitted job cannot resume from
// a previous invocation's list. only an identity-only standalone registry may use it.
func (r *Registry) ReplaceDeployments(ctx context.Context, inputs []DeploymentInstall) ([]Job, error) {
	if !r.fixedDeployments || len(inputs) == 0 {
		return nil, ErrScope
	}
	jobs := make([]Job, 0, len(inputs))
	publishers, replicas := map[publisherBinding]bool{}, map[jobBinding]bool{}
	for _, input := range inputs {
		job := input.Job
		if !validDeploymentInstall(job, input.Private) || validateJob(&job) != nil {
			return nil, ErrScope
		}
		owner, replica := job.publisherBinding(), job.binding()
		if publishers[owner] || replicas[replica] {
			return nil, ErrJobExists
		}
		publishers[owner], replicas[replica] = true, true
		jobs = append(jobs, job)
	}
	err := r.update(ctx, func(existing *[]Job) error {
		// Engine.Initialize holds exclusive supervisor ownership before this
		// fixed-list replacement. validate this list before retiring any replica.
		oldReplicas := make(map[jobBinding]Job, len(*existing))
		oldPublishers := make(map[publisherBinding]jobBinding, len(*existing))
		usedIDs := make(map[string]jobBinding, len(*existing)+len(jobs))
		for _, old := range *existing {
			binding := old.binding()
			oldReplicas[binding], oldPublishers[old.publisherBinding()] = old, binding
			usedIDs[old.ID] = binding
		}
		for i, job := range jobs {
			binding := job.binding()
			if prior, found := oldPublishers[job.publisherBinding()]; found && prior != binding {
				return ErrJobExists
			}
			id, revision := fixedDeploymentID(job), uint64(1)
			if prior, found := usedIDs[id]; found && prior != binding {
				return ErrJobExists
			}
			if old, found := oldReplicas[binding]; found {
				if err := r.verifyDeploymentIdentity(ctx, old, *job.DeploymentMember, inputs[i].Private); err != nil {
					return err
				}
				revision = old.Revision + 1
			}
			jobs[i] = restartDefinition(job, id, revision)
			usedIDs[id] = binding
		}
		// omitted replicas leave active name discovery, but keep their pins.
		for _, old := range *existing {
			if replicas[old.binding()] {
				continue
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
		*existing = slices.Clone(jobs)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return jobs, nil
}

// InstallDeployment captures the task's own signing identity. no person session or
// project checkout is required by the supervisor after installation.
func (r *Registry) InstallDeployment(ctx context.Context, job Job, member controlv1.DeploymentPublisherIdentity, private ed25519.PrivateKey) (Job, error) {
	if !r.user || !validDeploymentInstall(job, private) || *job.DeploymentMember != member {
		return Job{}, ErrScope
	}
	if err := validateJob(&job); err != nil {
		return Job{}, err
	}
	return r.install(ctx, job, func(existing *Job, job Job) error {
		if existing != nil {
			if err := r.verifyDeploymentIdentity(ctx, *existing, member, private); err != nil {
				return err
			}
		}
		return r.retainDeployment(ctx, job, member, private)
	})
}

func validDeploymentInstall(job Job, private ed25519.PrivateKey) bool {
	return job.ID == "" && job.Kind == KindDeployment && job.DeploymentMember != nil &&
		len(private) == ed25519.PrivateKeySize && bytes.Equal(ed25519.NewKeyFromSeed(private.Seed()), private)
}

func (r *Registry) verifyDeploymentIdentity(ctx context.Context, existing Job, member controlv1.DeploymentPublisherIdentity, private ed25519.PrivateKey) error {
	if !credentialfile.SameDeploymentIdentity(*existing.DeploymentMember, member) {
		return ErrScope
	}
	_, key, _, err := r.DeploymentIdentity(ctx, existing)
	if err != nil || !bytes.Equal(key, private) {
		return errors.Join(ErrScope, err)
	}
	return nil
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
