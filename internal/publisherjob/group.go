package publisherjob

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/publisheridentity/credentialfile"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

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
