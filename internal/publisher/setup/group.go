// package setup owns durable publisher signing identity provisioning.
package setup

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
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
	CreateEnvironmentPublisherEnrollment(context.Context, string, string, string, controlv1.CreateEnvironmentPublisherEnrollmentRequest) (controlv1.EnvironmentPublisherEnrollment, error)
}

type Client interface {
	credentialfile.GroupVerifier
	Enroll(context.Context, string, ed25519.PublicKey) (controlv1.EnvironmentPublisher, error)
}

type Scope struct {
	Server, Team, Project, EnvironmentID, Instance string
	MutationRevision                               int64
	ConfigurationHash                              string
	Services                                       []string
}

type journal struct {
	Scope       Scope
	Key         []byte
	Member      *controlv1.EnvironmentPublisher
	IssuanceKey string
	Enrollment  string
	ExpiresAt   time.Time
}

func (journal) String() string   { return "protected publisher provisioning operation" }
func (journal) GoString() string { return "protected publisher provisioning operation" }

// Ensure saves the private key before any enrollment request. retries, including
// lost replies and expired enrollment tokens, redeem only this same key. control
// deduplicates by public key and refuses revoked or foreign environment identity.
func Ensure(ctx context.Context, store *clientstate.Store, control Control, client Client, scope Scope, beforeEnroll ...func() error) (credentialfile.GroupFile, error) {
	canonical, err := naming.CanonicalControlURL(scope.Server)
	hash, hashErr := hex.DecodeString(scope.ConfigurationHash)
	if err != nil || canonical != scope.Server || !opaqueid.Valid(scope.Team, opaqueid.TeamPrefix) || !opaqueid.Valid(scope.EnvironmentID, opaqueid.EnvironmentPrefix) || !naming.ValidServiceName(scope.Instance) || !naming.ValidProjectKey(scope.Project) || scope.MutationRevision < 1 || hashErr != nil || len(hash) != 32 || hex.EncodeToString(hash) != scope.ConfigurationHash || len(scope.Services) == 0 || len(scope.Services) > 128 {
		return credentialfile.GroupFile{}, credentialfile.ErrInvalid
	}
	seen := map[string]bool{}
	for _, service := range scope.Services {
		if !naming.ValidServiceName(service) || seen[service] {
			return credentialfile.GroupFile{}, credentialfile.ErrInvalid
		}
		seen[service] = true
	}
	scope.Services = slices.Clone(scope.Services)
	selection := credentialfile.GroupSelection(scope.Project, scope.EnvironmentID, scope.Instance)
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
		if j.Scope.Server != scope.Server || j.Scope.Team != scope.Team || j.Scope.Project != scope.Project || j.Scope.EnvironmentID != scope.EnvironmentID || j.Scope.Instance != scope.Instance {
			return credentialfile.GroupFile{}, credentialfile.ErrInvalid
		}
	} else {
		// reuse the established local identity owner, including portable imports.
		retained, found, err := credentialfile.SavedGroup(store, scope.Server, scope.Project, scope.EnvironmentID, scope.Instance)
		if err != nil {
			return credentialfile.GroupFile{}, err
		}
		if found {
			key, err := retained.Validate(scope.Server, scope.Project, scope.EnvironmentID, scope.Instance)
			if err != nil {
				return credentialfile.GroupFile{}, err
			}
			j.Key, j.Member = key, &retained.Member
		} else if saved, found, err := store.SelectedPublisherIdentity(ctx, "project", selection); err != nil {
			return credentialfile.GroupFile{}, err
		} else if found {
			j.Member = &controlv1.EnvironmentPublisher{}
			if json.Unmarshal(saved.PublicDocument, j.Member) != nil {
				return credentialfile.GroupFile{}, credentialfile.ErrInvalid
			}
			j.Key = saved.SigningKey
		} else if pending, found, err := store.PendingPublisherEnrollmentForSelection(ctx, "project", selection); err != nil {
			return credentialfile.GroupFile{}, err
		} else if found {
			j.Key = pending.SigningKey
			if len(pending.ResultJSON) != 0 {
				j.Member = &controlv1.EnvironmentPublisher{}
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
			if j.Enrollment != "" {
				// only a known expired result starts a new issuance intent. clearing
				// it before the request keeps lost renewal replies on the same key.
				j.Enrollment, j.IssuanceKey, j.ExpiresAt = "", "", time.Time{}
			}
			if j.IssuanceKey == "" {
				j.IssuanceKey, err = opaqueid.New(opaqueid.IdempotencyPrefix)
				if err != nil {
					return credentialfile.GroupFile{}, err
				}
				// machine issuance spends an enrollment budget. persist both its
				// idempotency key and unchanged original authorization intent first.
				if err := save(ctx, store, selection, &revision, j); err != nil {
					return credentialfile.GroupFile{}, err
				}
			}
			enrollment, err := control.CreateEnvironmentPublisherEnrollment(ctx, j.Scope.Project, j.Scope.EnvironmentID, j.IssuanceKey, controlv1.CreateEnvironmentPublisherEnrollmentRequest{TeamId: j.Scope.Team, MaxMembers: 1, ExpiresIn: 600, ExpectedRevision: j.Scope.MutationRevision, ConfigurationHash: j.Scope.ConfigurationHash, Services: j.Scope.Services})
			if err != nil {
				return credentialfile.GroupFile{}, err
			}
			j.Enrollment, j.ExpiresAt = enrollment.EnrollmentKey, enrollment.ExpiresAt
			if j.Enrollment == "" || !j.ExpiresAt.After(time.Now()) || enrollment.Ref.EnvironmentId != scope.EnvironmentID || enrollment.Ref.ProjectKey != scope.Project || enrollment.Ref.Server != scope.Server || enrollment.MaxMembers != 1 {
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
	value, err := credentialfile.ResolveGroup(ctx, client, value, scope.Server, scope.Project, scope.EnvironmentID, scope.Instance)
	if err != nil {
		return credentialfile.GroupFile{}, err
	}
	if err := credentialfile.RetainGroup(ctx, store, value); err != nil {
		return credentialfile.GroupFile{}, err
	}
	_, err = credentialfile.ImportGroup(ctx, store, value, scope.Server, scope.Project, scope.EnvironmentID, scope.Instance)
	return value, err
}

func matches(member controlv1.EnvironmentPublisher, scope Scope) bool {
	return member.TeamId == scope.Team && member.ProjectKey == scope.Project && member.EnvironmentId == scope.EnvironmentID
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
