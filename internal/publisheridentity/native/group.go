package native

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"reflect"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisheridentity"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type GroupControl interface {
	RedeemPublisherGroupEnrollment(context.Context, string, ed25519.PublicKey) (controlv1.PublisherGroupMember, error)
	AcquirePublisherGroupLease(context.Context, controlv1.PublisherGroupLeaseRequest) (controlv1.PublisherGroupLease, error)
	GetPublisherGroupAssignments(context.Context, string) (controlv1.PublisherGroupAssignments, error)
	AcknowledgePublisherGroupConfiguration(context.Context, string, controlv1.PublisherGroupAcknowledgement) error
}

// Group owns one replica's signed identity. persist the fresh private key before
// enrollment, and retry redemption with that same key after response loss. each
// replica must have its own key and independently scoped certificate cache.
type Group struct {
	mu        sync.Mutex
	control   NativeControl
	groups    GroupControl
	authority AssertionExchanger
	server    string
	member    controlv1.PublisherGroupMember
	private   ed25519.PrivateKey
	lease     controlv1.PublisherGroupLease
	assigned  controlv1.PublisherGroupAssignments
}

func NewGroup(control NativeControl, groups GroupControl, authority AssertionExchanger, server string, member controlv1.PublisherGroupMember, private ed25519.PrivateKey) (*Group, error) {
	canonical, err := naming.CanonicalControlURL(server)
	if err != nil || canonical != server || control == nil || groups == nil || authority == nil || len(private) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(private.Seed()), private) || !opaqueid.Valid(member.PublisherIdentityId, opaqueid.PublisherIdentityPrefix) || !opaqueid.Valid(member.KeyId, opaqueid.PublisherIdentityKeyPrefix) || member.TeamId == "" || member.ProjectKey == "" || member.GroupId == "" || member.GroupName == "local" || member.GroupName == "" {
		return nil, ErrScope
	}
	return &Group{control: control, groups: groups, authority: authority, server: server, member: member, private: append(ed25519.PrivateKey(nil), private...)}, nil
}

func (g *Group) leaseToken(ctx context.Context) (string, error) {
	if g.lease.ExpiresAt.After(time.Now().Add(20 * time.Second)) {
		return g.lease.AccessToken, nil
	}
	assertion, err := publisheridentity.Sign(g.member.PublisherIdentityId, g.member.KeyId, g.member.GroupId, g.server+"/v1/publisher-groups/lease", g.private, time.Now())
	if err != nil {
		return "", err
	}
	lease, err := g.groups.AcquirePublisherGroupLease(ctx, controlv1.PublisherGroupLeaseRequest{PublisherIdentityId: g.member.PublisherIdentityId, GroupId: g.member.GroupId, Assertion: assertion})
	if err != nil {
		return "", err
	}
	if lease.AccessToken == "" || !lease.ExpiresAt.After(time.Now()) || lease.ExpiresAt.After(time.Now().Add(3*time.Minute)) {
		return "", ErrScope
	}
	g.lease = lease
	return lease.AccessToken, nil
}

func (g *Group) Poll(ctx context.Context) (controlv1.PublisherGroupAssignments, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	token, err := g.leaseToken(ctx)
	if err != nil {
		return controlv1.PublisherGroupAssignments{}, err
	}
	assignments, err := g.groups.GetPublisherGroupAssignments(ctx, token)
	if err != nil {
		return assignments, err
	}
	member := assignments.Member
	member.GroupName = g.member.GroupName
	if member != g.member || assignments.Revision < 1 || len(assignments.ConfigurationHash) != 64 || len(assignments.Services) > 128 {
		return controlv1.PublisherGroupAssignments{}, ErrScope
	}
	g.member.GroupName = assignments.Member.GroupName
	seen := map[string]bool{}
	for _, a := range assignments.Services {
		if a.Service == "" || seen[a.Service] || !opaqueid.Valid(a.GrantId, opaqueid.PublisherGrantPrefix) || a.Configuration.Publisher == nil || *a.Configuration.Publisher != g.member.GroupName {
			return controlv1.PublisherGroupAssignments{}, ErrScope
		}
		seen[a.Service] = true
		if _, err = groupAssignmentIdentity(g.member, a); err != nil {
			return controlv1.PublisherGroupAssignments{}, err
		}
	}
	// keep an independent snapshot: a caller may edit its returned target or
	// grant fields, but that must not change which assignments Service accepts.
	encoded, err := json.Marshal(assignments)
	if err != nil {
		return controlv1.PublisherGroupAssignments{}, err
	}
	if err = json.Unmarshal(encoded, &g.assigned); err != nil {
		return controlv1.PublisherGroupAssignments{}, err
	}
	return assignments, nil
}

func groupAssignmentIdentity(m controlv1.PublisherGroupMember, a controlv1.PublisherGroupServiceAssignment) (authorityv1.PublisherEnrollmentResult, error) {
	i := authorityv1.PublisherEnrollmentResult{ClientId: m.PublisherIdentityId, KeyId: m.KeyId, GrantId: a.GrantId, TeamId: m.TeamId}
	if a.ServiceKind == "private_service" && opaqueid.Valid(a.ServiceId, opaqueid.PrivateServicePrefix) && a.TrustRevision > 0 {
		i.Kind, i.PrivateServiceId = "private_service", &a.ServiceId
	} else {
		return i, ErrScope
	}
	return i, nil
}

// Service adapts an exact assignment from the latest poll to the shared native
// public/private publish lifecycle. target and trust remain in the assignment;
// the adapter carries only the exact service grant and this replica's key.
func (g *Group) Service(a controlv1.PublisherGroupServiceAssignment) (*Native, error) {
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
	i, err := groupAssignmentIdentity(g.member, a)
	if err != nil {
		return nil, err
	}
	return NewNative(g.control, g.authority, i, g.private)
}

func (g *Group) Acknowledge(ctx context.Context, revision int64, hash string, healthy bool) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if revision != g.assigned.Revision || hash != g.assigned.ConfigurationHash || revision < 1 {
		return ErrScope
	}
	token, err := g.leaseToken(ctx)
	if err != nil {
		return err
	}
	return g.groups.AcknowledgePublisherGroupConfiguration(ctx, token, controlv1.PublisherGroupAcknowledgement{Revision: revision, ConfigurationHash: hash, Healthy: healthy})
}
