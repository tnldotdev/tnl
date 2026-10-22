package identity

import (
	"slices"

	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// nativeScope owns the validated scalar authority of one worker. wire documents
// and their optional fields never remain part of its authorization decisions.
type nativeScope struct {
	clientID, keyID, grantID, teamID string
	kind                             authorityv1.PublisherEnrollmentResultKind
	publicURLID, serviceID           string
	domainID, namespace              string
}

func newNativeScope(i authorityv1.PublisherEnrollmentResult) (nativeScope, error) {
	if !opaqueid.Valid(i.ClientId, opaqueid.PublisherIdentityPrefix) || !opaqueid.Valid(i.KeyId, opaqueid.PublisherIdentityKeyPrefix) || !opaqueid.Valid(i.GrantId, opaqueid.PublisherGrantPrefix) || i.TeamId == "" || !i.Kind.Valid() {
		return nativeScope{}, ErrScope
	}
	s := nativeScope{clientID: i.ClientId, keyID: i.KeyId, grantID: i.GrantId, teamID: i.TeamId, kind: i.Kind}
	switch i.Kind {
	case authorityv1.SavedPublicUrl:
		if i.PublicUrlId == nil || !opaqueid.Valid(*i.PublicUrlId, opaqueid.PublicURLPrefix) || i.ServiceId != nil || i.Namespace != nil || i.DomainId != nil {
			return nativeScope{}, ErrScope
		}
		s.publicURLID = *i.PublicUrlId
	case authorityv1.Service:
		if i.ServiceId == nil || !opaqueid.Valid(*i.ServiceId, opaqueid.ServicePrefix) || i.PublicUrlId != nil || i.Namespace != nil || i.DomainId != nil {
			return nativeScope{}, ErrScope
		}
		s.serviceID = *i.ServiceId
	case authorityv1.Namespace:
		if i.Namespace == nil || i.DomainId == nil || i.PublicUrlId != nil || i.ServiceId != nil || !opaqueid.Valid(*i.DomainId, opaqueid.DomainPrefix) {
			return nativeScope{}, ErrScope
		}
		canonical, err := naming.CanonicalizeHostname(*i.Namespace)
		if err != nil || canonical != *i.Namespace {
			return nativeScope{}, ErrScope
		}
		s.domainID, s.namespace = *i.DomainId, canonical
	}
	return s, nil
}

func (s nativeScope) enrollment() authorityv1.PublisherEnrollmentResult {
	i := authorityv1.PublisherEnrollmentResult{ClientId: s.clientID, KeyId: s.keyID, GrantId: s.grantID, TeamId: s.teamID, Kind: s.kind}
	switch s.kind {
	case authorityv1.SavedPublicUrl:
		i.PublicUrlId = &s.publicURLID
	case authorityv1.Service:
		i.ServiceId = &s.serviceID
	case authorityv1.Namespace:
		i.DomainId, i.Namespace = &s.domainID, &s.namespace
	}
	return i
}

func copyOptional[T any](value *T) *T {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func clonePublicURL(u controlv1.PublicURL) controlv1.PublicURL {
	u.ExpiresAt = copyOptional(u.ExpiresAt)
	u.MembershipId = copyOptional(u.MembershipId)
	u.OpenPublishRunId = copyOptional(u.OpenPublishRunId)
	u.PublisherPool = copyOptional(u.PublisherPool)
	if u.AllowedIpPrefixes != nil {
		prefixes := slices.Clone(*u.AllowedIpPrefixes)
		u.AllowedIpPrefixes = &prefixes
	}
	return u
}
