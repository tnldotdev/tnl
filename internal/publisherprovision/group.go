// package publisherprovision owns durable group signing identity provisioning.
package publisherprovision

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisheridentity/credentialfile"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type Control interface {
	CreatePublisherGroupEnrollment(context.Context, string, string, controlv1.CreatePublisherGroupEnrollmentRequest) (controlv1.PublisherGroupEnrollment, error)
}

type Client interface {
	credentialfile.GroupVerifier
	Enroll(context.Context, string, ed25519.PublicKey) (controlv1.PublisherGroupMember, error)
}

type Scope struct {
	Server, Team, Project, GroupID, Group, Instance string
}

type journal struct {
	Scope      Scope
	Key        []byte
	Member     *controlv1.PublisherGroupMember
	Enrollment string
	ExpiresAt  time.Time
}

func (journal) String() string   { return "protected publisher provisioning operation" }
func (journal) GoString() string { return "protected publisher provisioning operation" }

// Ensure saves the private key before any enrollment request. retries, including
// lost replies and expired enrollment tokens, redeem only this same key. control
// deduplicates by public key and refuses revoked or foreign group membership.
func Ensure(ctx context.Context, store *clientstate.Store, control Control, client Client, scope Scope, beforeEnroll ...func() error) (credentialfile.GroupFile, error) {
	canonical, err := naming.CanonicalControlURL(scope.Server)
	if err != nil || canonical != scope.Server || scope.Team == "" || !opaqueid.Valid(scope.GroupID, "pgrp_") || !naming.ValidServiceName(scope.Instance) || !naming.ValidProjectKey(scope.Project) || !naming.ValidServiceName(scope.Group) || scope.Group == "local" {
		return credentialfile.GroupFile{}, credentialfile.ErrInvalid
	}
	selection := credentialfile.GroupSelection(scope.Project, scope.GroupID, scope.Instance)
	lock, err := store.LockPublisherSigningIdentity(ctx, selection)
	if err != nil {
		return credentialfile.GroupFile{}, err
	}
	defer lock.Close()
	data, revision, err := store.PublisherProvision(ctx, "group", selection)
	if err != nil {
		return credentialfile.GroupFile{}, err
	}
	j := journal{Scope: scope}
	if revision != 0 {
		if json.Unmarshal(data, &j) != nil {
			return credentialfile.GroupFile{}, credentialfile.ErrInvalid
		}
		old := j.Scope
		old.Group = scope.Group
		if old != scope {
			return credentialfile.GroupFile{}, credentialfile.ErrInvalid
		}
	} else {
		// reuse the established local identity owner, including portable imports.
		retained, found, err := credentialfile.SavedGroup(store, scope.Server, scope.Project, scope.GroupID, scope.Instance)
		if err != nil {
			return credentialfile.GroupFile{}, err
		}
		if found {
			key, err := retained.Validate(scope.Server, scope.Project, scope.Group, scope.Instance)
			if err != nil {
				return credentialfile.GroupFile{}, err
			}
			j.Key, j.Member = key, &retained.Member
		} else if saved, found, err := store.SelectedPublisherIdentity(ctx, "project", selection); err != nil {
			return credentialfile.GroupFile{}, err
		} else if found {
			j.Member = &controlv1.PublisherGroupMember{}
			if json.Unmarshal(saved.PublicDocument, j.Member) != nil {
				return credentialfile.GroupFile{}, credentialfile.ErrInvalid
			}
			j.Key = saved.SigningKey
		} else if pending, found, err := store.PendingPublisherEnrollmentForSelection(ctx, "project", selection); err != nil {
			return credentialfile.GroupFile{}, err
		} else if found {
			j.Key = pending.SigningKey
			if len(pending.ResultJSON) != 0 {
				j.Member = &controlv1.PublisherGroupMember{}
				if json.Unmarshal(pending.ResultJSON, j.Member) != nil {
					return credentialfile.GroupFile{}, credentialfile.ErrInvalid
				}
			}
		} else {
			_, j.Key, err = ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return credentialfile.GroupFile{}, err
			}
		}
		if err := save(ctx, store, selection, &revision, j); err != nil {
			return credentialfile.GroupFile{}, err
		}
	}
	if len(j.Key) != ed25519.PrivateKeySize {
		return credentialfile.GroupFile{}, credentialfile.ErrInvalid
	}
	private := ed25519.PrivateKey(j.Key)
	if !private.Equal(ed25519.NewKeyFromSeed(private.Seed())) {
		return credentialfile.GroupFile{}, credentialfile.ErrInvalid
	}
	if j.Member == nil {
		for _, ready := range beforeEnroll {
			if err := ready(); err != nil {
				return credentialfile.GroupFile{}, err
			}
		}
		if j.Enrollment == "" || !j.ExpiresAt.After(time.Now()) {
			enrollment, err := control.CreatePublisherGroupEnrollment(ctx, scope.Project, scope.Group, controlv1.CreatePublisherGroupEnrollmentRequest{TeamId: scope.Team, MaxMembers: 1, ExpiresIn: 600})
			if err != nil {
				return credentialfile.GroupFile{}, err
			}
			j.Enrollment, j.ExpiresAt = enrollment.EnrollmentKey, enrollment.ExpiresAt
			if j.Enrollment == "" || !j.ExpiresAt.After(time.Now()) {
				return credentialfile.GroupFile{}, credentialfile.ErrInvalid
			}
			if err := save(ctx, store, selection, &revision, j); err != nil {
				return credentialfile.GroupFile{}, err
			}
		}
		member, err := client.Enroll(ctx, j.Enrollment, private.Public().(ed25519.PublicKey))
		if err != nil {
			return credentialfile.GroupFile{}, err
		}
		j.Member = &member
		if !matches(member, scope) {
			return credentialfile.GroupFile{}, credentialfile.ErrInvalid
		}
		if err := save(ctx, store, selection, &revision, j); err != nil {
			return credentialfile.GroupFile{}, err
		}
	}
	if !matches(*j.Member, scope) {
		return credentialfile.GroupFile{}, credentialfile.ErrInvalid
	}
	value, err := credentialfile.NewGroup(scope.Server, scope.Instance, *j.Member, private)
	if err != nil {
		return credentialfile.GroupFile{}, err
	}
	return Import(ctx, store, client, value, scope)
}

// Import verifies current control membership before retaining an exact identity.
// the caller owns the selection lock; no invalid secret falls back to enrollment.
func Import(ctx context.Context, store *clientstate.Store, client credentialfile.GroupVerifier, value credentialfile.GroupFile, scope Scope) (credentialfile.GroupFile, error) {
	if !matches(value.Member, scope) {
		return credentialfile.GroupFile{}, credentialfile.ErrInvalid
	}
	value, err := credentialfile.ResolveGroup(ctx, client, value, scope.Server, scope.Project, scope.Group, scope.Instance)
	if err != nil {
		return credentialfile.GroupFile{}, err
	}
	if err := credentialfile.RetainGroup(ctx, store, value); err != nil {
		return credentialfile.GroupFile{}, err
	}
	_, err = credentialfile.ImportGroup(ctx, store, value, scope.Server, scope.Project, scope.Group, scope.Instance)
	return value, err
}

func matches(member controlv1.PublisherGroupMember, scope Scope) bool {
	return member.TeamId == scope.Team && member.ProjectKey == scope.Project && member.GroupId == scope.GroupID
}

func save(ctx context.Context, store *clientstate.Store, selection string, revision *int64, j journal) error {
	data, err := json.Marshal(j)
	if err != nil {
		return errors.Join(credentialfile.ErrInvalid, err)
	}
	if err := store.AppendPublisherProvision(ctx, "group", selection, *revision, data); err != nil {
		return err
	}
	*revision++
	return nil
}
