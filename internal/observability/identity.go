package observability

import (
	"context"
	"strings"

	"go.opentelemetry.io/otel/attribute"
)

// Identity contains authenticated stable scope, not request-supplied identifiers.
// the public URL and service slots are mutually exclusive. a conflicting
// or invalid identity is cleared rather than attributed to the previous tenant.
type Identity struct {
	TeamID, PublisherGroupID, PublisherIdentityID, DeploymentID, ReplicaKey string
	ServiceID, PublicURLID                                                  string
	ServiceKind                                                             ServiceKind
}
type identityKey struct{}

func IdentityFromContext(ctx context.Context) Identity {
	id, _ := ctx.Value(identityKey{}).(Identity)
	return id
}

// ReplaceIdentity replaces every field, including empty fields. use this at an
// authentication boundary, especially when a context may belong to another team.
func ReplaceIdentity(ctx context.Context, id Identity) context.Context {
	if !validIdentity(id) {
		id = Identity{}
	}
	if id.ServiceID != "" {
		id.ServiceKind = Service
	}
	if id.PublicURLID != "" {
		id.ServiceKind = PublicURL
	}
	return context.WithValue(ctx, identityKey{}, id)
}

// NarrowIdentity keeps parent deployment/group scope only within the same team
// and publisher. service scope is always replaced (or cleared). a changed team,
// publisher, group, or deployment starts a new scope instead of inheriting it.
func NarrowIdentity(ctx context.Context, id Identity) context.Context {
	p := IdentityFromContext(ctx)
	if id.TeamID != "" && id.TeamID != p.TeamID || id.PublisherIdentityID != "" && id.PublisherIdentityID != p.PublisherIdentityID || id.PublisherGroupID != "" && id.PublisherGroupID != p.PublisherGroupID || id.DeploymentID != "" && id.DeploymentID != p.DeploymentID {
		return ReplaceIdentity(ctx, id)
	}
	if id.TeamID == "" {
		id.TeamID = p.TeamID
	}
	if id.PublisherIdentityID == "" {
		id.PublisherIdentityID = p.PublisherIdentityID
	}
	if id.PublisherGroupID == "" {
		id.PublisherGroupID = p.PublisherGroupID
	}
	if id.DeploymentID == "" {
		id.DeploymentID = p.DeploymentID
	}
	if id.ReplicaKey == "" {
		id.ReplicaKey = p.ReplicaKey
	}
	return ReplaceIdentity(ctx, id)
}

func validIdentity(id Identity) bool {
	if id.ServiceID != "" && id.PublicURLID != "" {
		return false
	}
	if id.ServiceKind != 0 && id.ServiceKind != Service && id.ServiceKind != PublicURL {
		return false
	}
	if id.ServiceID != "" && id.ServiceKind == PublicURL || id.PublicURLID != "" && id.ServiceKind == Service {
		return false
	}
	for _, v := range []string{id.TeamID, id.PublisherGroupID, id.PublisherIdentityID, id.DeploymentID, id.ReplicaKey, id.ServiceID, id.PublicURLID} {
		if len(v) > 128 || strings.ContainsAny(v, "\r\n\x00") {
			return false
		}
	}
	return true
}

func identityAttributes(ctx context.Context) []attribute.KeyValue {
	id := IdentityFromContext(ctx)
	var out []attribute.KeyValue
	for _, item := range []struct {
		k metricStringKey
		v string
	}{{TeamID, id.TeamID}, {PublisherGroupID, id.PublisherGroupID}, {PublisherIdentityID, id.PublisherIdentityID}, {DeploymentID, id.DeploymentID}, {ReplicaKey, id.ReplicaKey}, {ServiceID, id.ServiceID}, {PublicURLID, id.PublicURLID}} {
		if item.v != "" {
			out = append(out, item.k.String(item.v))
		}
	}
	if id.ServiceKind != 0 {
		out = append(out, ServiceKindKey.Value(id.ServiceKind))
	}
	return out
}
