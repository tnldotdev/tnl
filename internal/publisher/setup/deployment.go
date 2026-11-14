// package setup owns durable deployment signing identity provisioning.
package setup

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	json "encoding/json/v2"
	"errors"
	"slices"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisher/identity/credentialfile"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type Control interface {
	CreateDeploymentPublisherEnrollment(context.Context, string, string, string, string, controlv1.CreateDeploymentPublisherEnrollmentRequest) (controlv1.DeploymentPublisherEnrollment, error)
	GetDeploymentPublisher(context.Context, string, string, string, string) (controlv1.DeploymentPublisher, error)
}

type Client interface {
	credentialfile.DeploymentVerifier
	Enroll(context.Context, string, ed25519.PublicKey) (controlv1.DeploymentPublisherIdentity, error)
}

type Scope struct {
	Server, Team, Project, DeploymentID, Deployment, Instance string
}

type journal struct {
	Scope      Scope
	Key        []byte
	Member     *controlv1.DeploymentPublisherIdentity
	Enrollment string
	ExpiresAt  time.Time
	Services   []string
	RequestKey string
}

func (journal) String() string   { return "protected publisher provisioning operation" }
func (journal) GoString() string { return "protected publisher provisioning operation" }

// Ensure saves the private key before any enrollment request. lost replies retry
// only that key and captured approval; expiry never issues a replacement.
func Ensure(ctx context.Context, store *clientstate.Store, control Control, client Client, scope Scope, services []string, beforeEnroll ...func() error) (credentialfile.DeploymentFile, error) {
	services = slices.Clone(services)
	slices.Sort(services)
	if len(services) < 1 || len(services) > 128 {
		return credentialfile.DeploymentFile{}, credentialfile.ErrInvalid
	}
	for i, name := range services {
		if !naming.ValidServiceName(name) || i > 0 && name == services[i-1] {
			return credentialfile.DeploymentFile{}, credentialfile.ErrInvalid
		}
	}
	canonical, err := naming.CanonicalControlURL(scope.Server)
	if err != nil || canonical != scope.Server || scope.Team == "" || !opaqueid.Valid(scope.DeploymentID, "dpl_") || !naming.ValidServiceName(scope.Instance) || !naming.ValidProjectKey(scope.Project) || !naming.ValidServiceName(scope.Deployment) || scope.Deployment == "local" {
		return credentialfile.DeploymentFile{}, credentialfile.ErrInvalid
	}
	selection := credentialfile.DeploymentSelection(scope.Project, scope.DeploymentID, scope.Instance)
	lock, err := store.LockPublisherSigningIdentity(ctx, selection)
	if err != nil {
		return credentialfile.DeploymentFile{}, err
	}
	defer lock.Close()
	data, revision, err := store.PublisherProvision(ctx, "deployment", selection)
	if err != nil {
		return credentialfile.DeploymentFile{}, err
	}
	j := journal{Scope: scope, Services: services}
	if revision != 0 {
		if json.Unmarshal(data, &j, json.RejectUnknownMembers(true)) != nil || !opaqueid.Valid(j.RequestKey, opaqueid.IdempotencyPrefix) {
			return credentialfile.DeploymentFile{}, credentialfile.ErrInvalid
		}
		old := j.Scope
		old.Deployment = scope.Deployment
		if old != scope || !slices.Equal(j.Services, services) {
			return credentialfile.DeploymentFile{}, credentialfile.ErrInvalid
		}
	} else {
		// reuse the established local identity owner, including portable imports.
		retained, found, err := credentialfile.SavedDeployment(store, scope.Server, scope.Project, scope.DeploymentID, scope.Instance)
		if err != nil {
			return credentialfile.DeploymentFile{}, err
		}
		if found {
			key, err := retained.Validate(scope.Server, scope.Project, scope.Deployment, scope.Instance)
			if err != nil {
				return credentialfile.DeploymentFile{}, err
			}
			j.Key, j.Member = key, &retained.Member
		} else if saved, found, err := store.SelectedPublisherIdentity(ctx, "project", selection); err != nil {
			return credentialfile.DeploymentFile{}, err
		} else if found {
			j.Member = &controlv1.DeploymentPublisherIdentity{}
			if json.Unmarshal(saved.PublicDocument, j.Member, json.RejectUnknownMembers(true)) != nil {
				return credentialfile.DeploymentFile{}, credentialfile.ErrInvalid
			}
			j.Key = saved.SigningKey
		} else if pending, found, err := store.PendingPublisherEnrollmentForSelection(ctx, "project", selection); err != nil {
			return credentialfile.DeploymentFile{}, err
		} else if found {
			j.Key = pending.SigningKey
			j.Member = &controlv1.DeploymentPublisherIdentity{}
			if json.Unmarshal(pending.ResultJSON, j.Member, json.RejectUnknownMembers(true)) != nil {
				// finish the original enrollment before provisioning; a pending
				// key is not permission to issue replacement approval.
				return credentialfile.DeploymentFile{}, credentialfile.ErrInvalid
			}
		} else {
			_, j.Key, err = ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return credentialfile.DeploymentFile{}, err
			}
		}
		if j.Member != nil {
			// reject a different scope without pinning that failed request in
			// a new journal or changing the established identity.
			return importApproved(ctx, store, control, client, scope, services, *j.Member, j.Key)
		}
		j.RequestKey, err = opaqueid.New(opaqueid.IdempotencyPrefix)
		if err != nil {
			return credentialfile.DeploymentFile{}, err
		}
		if err := save(ctx, store, selection, &revision, j); err != nil {
			return credentialfile.DeploymentFile{}, err
		}
	}
	if len(j.Key) != ed25519.PrivateKeySize {
		return credentialfile.DeploymentFile{}, credentialfile.ErrInvalid
	}
	private := ed25519.PrivateKey(j.Key)
	if !private.Equal(ed25519.NewKeyFromSeed(private.Seed())) {
		return credentialfile.DeploymentFile{}, credentialfile.ErrInvalid
	}
	if j.Member == nil {
		for _, ready := range beforeEnroll {
			if err := ready(); err != nil {
				return credentialfile.DeploymentFile{}, err
			}
		}
		if j.Enrollment == "" {
			enrollment, err := control.CreateDeploymentPublisherEnrollment(ctx, scope.Team, scope.Project, scope.DeploymentID, j.RequestKey, controlv1.CreateDeploymentPublisherEnrollmentRequest{Services: services, MaxMembers: new(1), ExpiresIn: new(600)})
			if err != nil {
				return credentialfile.DeploymentFile{}, err
			}
			if enrollment.DeploymentId != scope.DeploymentID || enrollment.MaxMembers != 1 || !opaqueid.Valid(enrollment.EnrollmentId, opaqueid.PublisherEnrollmentPrefix) || len(enrollment.Services) != len(services) {
				return credentialfile.DeploymentFile{}, credentialfile.ErrInvalid
			}
			for _, service := range services {
				if !enrollment.Services[service].Valid() {
					return credentialfile.DeploymentFile{}, credentialfile.ErrInvalid
				}
			}
			j.Enrollment, j.ExpiresAt = enrollment.EnrollmentKey, enrollment.ExpiresAt
			if j.Enrollment == "" || !j.ExpiresAt.After(time.Now()) {
				return credentialfile.DeploymentFile{}, credentialfile.ErrInvalid
			}
			if err := save(ctx, store, selection, &revision, j); err != nil {
				return credentialfile.DeploymentFile{}, err
			}
		}
		if !j.ExpiresAt.After(time.Now()) {
			return credentialfile.DeploymentFile{}, credentialfile.ErrInvalid
		}
		member, err := client.Enroll(ctx, j.Enrollment, private.Public().(ed25519.PublicKey))
		if err != nil {
			return credentialfile.DeploymentFile{}, err
		}
		j.Member = &member
		if !matches(member, scope) {
			return credentialfile.DeploymentFile{}, credentialfile.ErrInvalid
		}
		if err := save(ctx, store, selection, &revision, j); err != nil {
			return credentialfile.DeploymentFile{}, err
		}
	}
	return importApproved(ctx, store, control, client, scope, services, *j.Member, private)
}

func importApproved(ctx context.Context, store *clientstate.Store, control Control, client Client, scope Scope, services []string, member controlv1.DeploymentPublisherIdentity, private ed25519.PrivateKey) (credentialfile.DeploymentFile, error) {
	if !matches(member, scope) {
		return credentialfile.DeploymentFile{}, credentialfile.ErrInvalid
	}
	value, err := credentialfile.NewDeployment(scope.Server, scope.Instance, member, private)
	if err != nil {
		return credentialfile.DeploymentFile{}, err
	}
	// authenticated status owns captured approval. membership verification below
	// still proves this exact signing key without acquiring a lease or enrolling.
	publisher, err := control.GetDeploymentPublisher(ctx, scope.Team, scope.Project, scope.DeploymentID, member.PublisherIdentityId)
	if err != nil {
		return credentialfile.DeploymentFile{}, err
	}
	if publisher.TeamId != member.TeamId || publisher.ProjectKey != member.ProjectKey || publisher.DeploymentId != member.DeploymentId || publisher.PublisherIdentityId != member.PublisherIdentityId || publisher.KeyId != member.KeyId || publisher.RevokedAt != nil || len(publisher.Services) != len(services) {
		return credentialfile.DeploymentFile{}, credentialfile.ErrInvalid
	}
	for _, service := range services {
		if !publisher.Services[service].Valid() {
			return credentialfile.DeploymentFile{}, credentialfile.ErrInvalid
		}
	}
	return Import(ctx, store, client, value, scope)
}

// Import verifies current control membership before retaining an exact identity.
// the caller owns the selection lock; no invalid secret falls back to enrollment.
func Import(ctx context.Context, store *clientstate.Store, client credentialfile.DeploymentVerifier, value credentialfile.DeploymentFile, scope Scope) (credentialfile.DeploymentFile, error) {
	if !matches(value.Member, scope) {
		return credentialfile.DeploymentFile{}, credentialfile.ErrInvalid
	}
	value, err := credentialfile.ResolveDeployment(ctx, client, value, scope.Server, scope.Project, scope.Deployment, scope.Instance)
	if err != nil {
		return credentialfile.DeploymentFile{}, err
	}
	if err := credentialfile.RetainDeployment(ctx, store, value); err != nil {
		return credentialfile.DeploymentFile{}, err
	}
	_, err = credentialfile.ImportDeployment(ctx, store, value, scope.Server, scope.Project, scope.Deployment, scope.Instance)
	return value, err
}

func matches(member controlv1.DeploymentPublisherIdentity, scope Scope) bool {
	return member.TeamId == scope.Team && member.ProjectKey == scope.Project && member.DeploymentId == scope.DeploymentID
}

func save(ctx context.Context, store *clientstate.Store, selection string, revision *int64, j journal) error {
	data, err := json.Marshal(j)
	if err != nil {
		return errors.Join(credentialfile.ErrInvalid, err)
	}
	if err := store.AppendPublisherProvision(ctx, "deployment", selection, *revision, data); err != nil {
		return err
	}
	*revision++
	return nil
}
