package identity

import (
	"time"

	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

// nativeScope owns the validated scalar authority of one worker. wire documents
// and their optional fields never remain part of its authorization decisions.
type nativeScope struct {
	clientID, keyID, grantID, teamID string
	guestID                          string
	expiresAt                        time.Time
	kind                             string
	serviceID                        string
	domainID, namespace              string
}

func newNativeScope(i authorityv1.PublisherEnrollmentResult) (nativeScope, error) {
	if !opaqueid.Valid(i.ClientId, opaqueid.PublisherIdentityPrefix) || !opaqueid.Valid(i.KeyId, opaqueid.PublisherIdentityKeyPrefix) || !opaqueid.Valid(i.GrantId, opaqueid.PublisherGrantPrefix) ||
		(i.TeamId == "") == (i.GuestId == "") || !i.Kind.Valid() {
		return nativeScope{}, ErrScope
	}
	s := nativeScope{clientID: i.ClientId, keyID: i.KeyId, grantID: i.GrantId, teamID: i.TeamId, guestID: i.GuestId, kind: string(i.Kind)}
	if i.GuestId != "" {
		if !opaqueid.Valid(i.GuestId, opaqueid.GuestPrefix) || i.Kind != authorityv1.Service || i.ExpiresAt == nil || !i.ExpiresAt.After(time.Now()) {
			return nativeScope{}, ErrScope
		}
		s.expiresAt = *i.ExpiresAt
	}
	switch i.Kind {
	case authorityv1.Service:
		if i.ServiceId == nil || !opaqueid.Valid(*i.ServiceId, opaqueid.ServicePrefix) || i.Namespace != nil || i.DomainId != nil {
			return nativeScope{}, ErrScope
		}
		s.serviceID = *i.ServiceId
	case authorityv1.Namespace:
		if i.Namespace == nil || i.DomainId == nil || i.ServiceId != nil || !opaqueid.Valid(*i.DomainId, opaqueid.DomainPrefix) {
			return nativeScope{}, ErrScope
		}
		canonical, err := naming.CanonicalizeHostname(*i.Namespace)
		if err != nil || canonical != *i.Namespace {
			return nativeScope{}, ErrScope
		}
		s.domainID, s.namespace = *i.DomainId, canonical
	default:
		return nativeScope{}, ErrScope
	}
	return s, nil
}
