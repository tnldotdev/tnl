package identity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"reflect"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type EnvironmentControl interface {
	AcquireEnvironmentPublisherLease(context.Context, controlv1.EnvironmentPublisherProof) (controlv1.EnvironmentPublisherLease, error)
	GetEnvironmentPublisherAssignments(context.Context, string) (controlv1.EnvironmentPublisherAssignments, error)
	AcknowledgeEnvironmentPublisher(context.Context, string, controlv1.EnvironmentPublisherAcknowledgement) error
}

// environment owns one replica's signed identity. persist the fresh private key before
// enrollment, and retry redemption with that same key after response loss. each
// replica must have its own key and independently scoped certificate cache.
type Environment struct {
	mu           sync.Mutex
	control      NativeControl
	environments EnvironmentControl
	authority    AssertionExchanger
	server       string
	publisher    controlv1.EnvironmentPublisher
	private      ed25519.PrivateKey
	lease        controlv1.EnvironmentPublisherLease
	assigned     controlv1.EnvironmentPublisherAssignments
}

func (*Environment) String() string   { return "environment publisher identity" }
func (*Environment) GoString() string { return "environment publisher identity" }

func NewEnvironment(control NativeControl, environments EnvironmentControl, authority AssertionExchanger, server string, publisher controlv1.EnvironmentPublisher, private ed25519.PrivateKey) (*Environment, error) {
	canonical, err := naming.CanonicalControlURL(server)
	if err != nil || canonical != server || control.PublicURLControl == nil || control.ControlURL() != server || control.Services == nil || environments == nil || authority == nil || len(private) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(private.Seed()), private) || !opaqueid.Valid(publisher.PublisherIdentityId, opaqueid.PublisherIdentityPrefix) || !opaqueid.Valid(publisher.KeyId, opaqueid.PublisherIdentityKeyPrefix) || publisher.TeamId == "" || !naming.ValidProjectKey(publisher.ProjectKey) || !opaqueid.Valid(publisher.EnvironmentId, opaqueid.EnvironmentPrefix) {
		return nil, ErrScope
	}
	return &Environment{control: control, environments: environments, authority: authority, server: server, publisher: publisher, private: append(ed25519.PrivateKey(nil), private...)}, nil
}

func (g *Environment) leaseToken(ctx context.Context) (string, error) {
	if g.lease.ExpiresAt.After(time.Now().Add(20 * time.Second)) {
		return g.lease.AccessToken, nil
	}
	assertion, err := publisherproof.Sign(g.publisher.PublisherIdentityId, g.publisher.KeyId, g.publisher.EnvironmentId, g.server+"/v1/environment-publishers/lease", g.private, time.Now())
	if err != nil {
		return "", err
	}
	lease, err := g.environments.AcquireEnvironmentPublisherLease(ctx, controlv1.EnvironmentPublisherProof{PublisherIdentityId: g.publisher.PublisherIdentityId, EnvironmentId: g.publisher.EnvironmentId, Assertion: assertion})
	if err != nil {
		return "", err
	}
	if lease.AccessToken == "" || !lease.ExpiresAt.After(time.Now()) || lease.ExpiresAt.After(time.Now().Add(3*time.Minute)) {
		return "", ErrScope
	}
	g.lease = lease
	return lease.AccessToken, nil
}

func (g *Environment) Poll(ctx context.Context) (controlv1.EnvironmentPublisherAssignments, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	g.mu.Lock()
	defer g.mu.Unlock()
	token, err := g.leaseToken(ctx)
	if err != nil {
		return controlv1.EnvironmentPublisherAssignments{}, err
	}
	assignments, err := g.environments.GetEnvironmentPublisherAssignments(ctx, token)
	if err != nil {
		return assignments, err
	}
	publication := assignments.Environment
	previous := g.assigned.Environment
	if assignments.Publisher != g.publisher || !validEnvironmentPublication(&publication) || publication.EnvironmentId != g.publisher.EnvironmentId || len(assignments.Services) > 128 || publication.MutationRevision < previous.MutationRevision || publication.MutationRevision == previous.MutationRevision && publication.ConfigurationHash != previous.ConfigurationHash {
		return controlv1.EnvironmentPublisherAssignments{}, ErrScope
	}
	seen, ids := map[string]bool{}, map[string]bool{}
	for _, a := range assignments.Services {
		if !naming.ValidServiceName(a.Service) || seen[a.Service] || ids[a.ServiceId] || !a.Configuration.Protocol.Valid() || !opaqueid.Valid(a.GrantId, opaqueid.PublisherGrantPrefix) {
			return controlv1.EnvironmentPublisherAssignments{}, ErrScope
		}
		seen[a.Service], ids[a.ServiceId] = true, true
		if _, err = environmentAssignmentIdentity(g.publisher, a); err != nil {
			return controlv1.EnvironmentPublisherAssignments{}, err
		}
	}
	// keep an independent snapshot: a caller may edit its returned target or
	// grant fields, but that must not change which assignments Service accepts.
	encoded, err := json.Marshal(assignments)
	if err != nil {
		return controlv1.EnvironmentPublisherAssignments{}, err
	}
	var snapshot controlv1.EnvironmentPublisherAssignments
	if err = json.Unmarshal(encoded, &snapshot); err != nil {
		return controlv1.EnvironmentPublisherAssignments{}, err
	}
	if err := context.Cause(ctx); err != nil {
		return controlv1.EnvironmentPublisherAssignments{}, err
	}
	g.assigned = snapshot
	return assignments, nil
}

func environmentAssignmentIdentity(m controlv1.EnvironmentPublisher, a controlv1.EnvironmentPublisherAssignment) (authorityv1.PublisherEnrollmentResult, error) {
	i := authorityv1.PublisherEnrollmentResult{ClientId: m.PublisherIdentityId, KeyId: m.KeyId, GrantId: a.GrantId, TeamId: m.TeamId}
	if opaqueid.Valid(a.ServiceId, opaqueid.ServicePrefix) && a.TrustRevision > 0 {
		i.Kind, i.ServiceId = "service", &a.ServiceId
	} else {
		return i, ErrScope
	}
	return i, nil
}

// Service adapts an exact assignment from the latest poll to the shared native
// public/private publish lifecycle. target and trust remain in the assignment;
// the adapter carries only the exact service grant and this replica's key.
func (g *Environment) Service(publication controlv1.EnvironmentPublication, a controlv1.EnvironmentPublisherAssignment) (*Native, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if publication != g.assigned.Environment || !validEnvironmentPublication(&publication) {
		return nil, ErrScope
	}
	found := false
	for _, current := range g.assigned.Services {
		if reflect.DeepEqual(current, a) {
			found = true
			break
		}
	}
	if !found {
		return nil, ErrScope
	}
	i, err := environmentAssignmentIdentity(g.publisher, a)
	if err != nil {
		return nil, err
	}
	return NewNative(g.control, g.authority, i, g.private, &publication)
}

func (g *Environment) Acknowledge(ctx context.Context, publication controlv1.EnvironmentPublication, healthy bool) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	g.mu.Lock()
	defer g.mu.Unlock()
	if publication != g.assigned.Environment || !validEnvironmentPublication(&publication) {
		return ErrScope
	}
	token, err := g.leaseToken(ctx)
	if err != nil {
		return err
	}
	return g.environments.AcknowledgeEnvironmentPublisher(ctx, token, controlv1.EnvironmentPublisherAcknowledgement{Environment: publication, Healthy: healthy})
}
