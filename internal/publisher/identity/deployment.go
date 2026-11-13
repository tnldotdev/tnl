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

type DeploymentControl interface {
	RedeemDeploymentPublisherEnrollment(context.Context, string, ed25519.PublicKey) (controlv1.DeploymentPublisherIdentity, error)
	AcquireDeploymentPublisherLease(context.Context, controlv1.DeploymentPublisherLeaseRequest) (controlv1.DeploymentPublisherLease, error)
	GetDeploymentPublisherAssignments(context.Context, string) (controlv1.DeploymentPublisherAssignments, error)
	AcknowledgeDeploymentPublisherConfiguration(context.Context, string, controlv1.DeploymentPublisherAcknowledgement) error
}

// Deployment owns one replica's signed identity. persist the fresh private key before
// enrollment, and retry redemption with that same key after response loss. each
// replica must have its own key and independently scoped certificate cache.
type Deployment struct {
	mu          sync.Mutex
	control     NativeControl
	deployments DeploymentControl
	authority   AssertionExchanger
	server      string
	member      controlv1.DeploymentPublisherIdentity
	private     ed25519.PrivateKey
	lease       controlv1.DeploymentPublisherLease
	assigned    controlv1.DeploymentPublisherAssignments
}

func NewDeployment(control NativeControl, deployments DeploymentControl, authority AssertionExchanger, server string, member controlv1.DeploymentPublisherIdentity, private ed25519.PrivateKey) (*Deployment, error) {
	canonical, err := naming.CanonicalControlURL(server)
	if err != nil || canonical != server || control.PublicURLControl == nil || control.ControlURL() != server || control.Services == nil || deployments == nil || authority == nil || len(private) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(private.Seed()), private) || !opaqueid.Valid(member.PublisherIdentityId, opaqueid.PublisherIdentityPrefix) || !opaqueid.Valid(member.KeyId, opaqueid.PublisherIdentityKeyPrefix) || member.TeamId == "" || member.ProjectKey == "" || member.DeploymentId == "" || member.DeploymentName == "local" || member.DeploymentName == "" {
		return nil, ErrScope
	}
	return &Deployment{control: control, deployments: deployments, authority: authority, server: server, member: member, private: append(ed25519.PrivateKey(nil), private...)}, nil
}

func (g *Deployment) leaseToken(ctx context.Context) (string, error) {
	if g.lease.ExpiresAt.After(time.Now().Add(20 * time.Second)) {
		return g.lease.AccessToken, nil
	}
	assertion, err := publisherproof.Sign(g.member.PublisherIdentityId, g.member.KeyId, g.member.DeploymentId, g.server+"/v1/publisher/deployments/lease", g.private, time.Now())
	if err != nil {
		return "", err
	}
	lease, err := g.deployments.AcquireDeploymentPublisherLease(ctx, controlv1.DeploymentPublisherLeaseRequest{PublisherIdentityId: g.member.PublisherIdentityId, DeploymentId: g.member.DeploymentId, Assertion: assertion})
	if err != nil {
		return "", err
	}
	if lease.AccessToken == "" || !lease.ExpiresAt.After(time.Now()) || lease.ExpiresAt.After(time.Now().Add(3*time.Minute)) {
		return "", ErrScope
	}
	g.lease = lease
	return lease.AccessToken, nil
}

func (g *Deployment) Poll(ctx context.Context) (controlv1.DeploymentPublisherAssignments, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	token, err := g.leaseToken(ctx)
	if err != nil {
		return controlv1.DeploymentPublisherAssignments{}, err
	}
	assignments, err := g.deployments.GetDeploymentPublisherAssignments(ctx, token)
	if err != nil {
		return assignments, err
	}
	member := assignments.Member
	member.DeploymentName = g.member.DeploymentName
	if member != g.member || assignments.Revision < 1 || len(assignments.ConfigurationHash) != 64 || len(assignments.Services) > 128 {
		return controlv1.DeploymentPublisherAssignments{}, ErrScope
	}
	g.member.DeploymentName = assignments.Member.DeploymentName
	seen := map[string]bool{}
	for _, a := range assignments.Services {
		if a.Service == "" || seen[a.Service] || !opaqueid.Valid(a.GrantId, opaqueid.PublisherGrantPrefix) {
			return controlv1.DeploymentPublisherAssignments{}, ErrScope
		}
		seen[a.Service] = true
		if _, err = deploymentAssignmentIdentity(g.member, a); err != nil {
			return controlv1.DeploymentPublisherAssignments{}, err
		}
	}
	// keep an independent snapshot: a caller may edit its returned target or
	// grant fields, but that must not change which assignments Service accepts.
	encoded, err := json.Marshal(assignments)
	if err != nil {
		return controlv1.DeploymentPublisherAssignments{}, err
	}
	if err = json.Unmarshal(encoded, &g.assigned); err != nil {
		return controlv1.DeploymentPublisherAssignments{}, err
	}
	return assignments, nil
}

func deploymentAssignmentIdentity(m controlv1.DeploymentPublisherIdentity, a controlv1.DeploymentPublisherServiceAssignment) (authorityv1.PublisherEnrollmentResult, error) {
	i := authorityv1.PublisherEnrollmentResult{ClientId: m.PublisherIdentityId, KeyId: m.KeyId, GrantId: a.GrantId, TeamId: m.TeamId}
	if a.ServiceKind == "service" && opaqueid.Valid(a.ServiceId, opaqueid.ServicePrefix) && a.TrustRevision > 0 {
		i.Kind, i.ServiceId = "service", &a.ServiceId
	} else {
		return i, ErrScope
	}
	return i, nil
}

// Service adapts an exact assignment from the latest poll to the shared native
// public/private publish lifecycle. target and trust remain in the assignment;
// the adapter carries only the exact service grant and this replica's key.
func (g *Deployment) Service(a controlv1.DeploymentPublisherServiceAssignment) (*Native, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
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
	i, err := deploymentAssignmentIdentity(g.member, a)
	if err != nil {
		return nil, err
	}
	return NewNative(g.control, g.authority, i, g.private)
}

func (g *Deployment) Acknowledge(ctx context.Context, revision int64, hash string, healthy bool) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if revision != g.assigned.Revision || hash != g.assigned.ConfigurationHash || revision < 1 {
		return ErrScope
	}
	token, err := g.leaseToken(ctx)
	if err != nil {
		return err
	}
	return g.deployments.AcknowledgeDeploymentPublisherConfiguration(ctx, token, controlv1.DeploymentPublisherAcknowledgement{Revision: revision, ConfigurationHash: hash, Healthy: healthy})
}
