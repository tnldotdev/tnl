package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// enrollmentSelection names one exact owner scope, not a reusable grant policy.
type enrollmentSelection struct {
	kind, team, id, namespace string
	publicURL                 *controlv1.PublicURL
}

func (s enrollmentSelection) matches(kind, team string, publicURL, service, domain, namespace *string) bool {
	if kind != s.kind || team != s.team {
		return false
	}
	switch s.kind {
	case "saved_public_url":
		return publicURL != nil && *publicURL == s.id
	case "service":
		return service != nil && *service == s.id
	case "namespace":
		return domain != nil && *domain == s.id && namespace != nil && *namespace == s.namespace && publicURL == nil
	}
	return false
}

// ensureSelectedEnrollment keeps selection, pending-key recovery, and promotion
// under one scope lock. explicit namespace setup alone also records a default;
// saved URLs select their serving resource, while service trust stays above it.
func ensureSelectedEnrollment(ctx context.Context, state *clientstate.Store, control OwnerControl, authority EnrollmentAuthority, scope enrollmentSelection) (*Native, authorityv1.PublisherEnrollmentResult, error) {
	if state == nil || control == nil || authority == nil {
		return nil, authorityv1.PublisherEnrollmentResult{}, ErrScope
	}
	selection, key := "project", "owner-url:"+scope.id
	request := controlv1.CreatePublisherEnrollmentRequest{TeamId: scope.team, Name: "tnl", Kind: controlv1.CreatePublisherEnrollmentRequestKindInstalled}
	switch scope.kind {
	case "saved_public_url":
		request.PublicUrlId = &scope.id
	case "service":
		key, request.ServiceId = "project-publisher:service:"+scope.id, &scope.id
	case "namespace":
		selection, key, request.DomainId = "namespace", namespaceScope(scope.team, scope.id), &scope.id
	default:
		return nil, authorityv1.PublisherEnrollmentResult{}, ErrScope
	}
	lock, err := state.LockPublisherSigningIdentity(ctx, key)
	if err != nil {
		return nil, authorityv1.PublisherEnrollmentResult{}, err
	}
	defer lock.Close()
	saved, found, err := state.SelectedPublisherIdentity(ctx, selection, key)
	if err != nil {
		return nil, authorityv1.PublisherEnrollmentResult{}, err
	}
	var native *Native
	var identity authorityv1.PublisherEnrollmentResult
	if found {
		if json.Unmarshal(saved.PublicDocument, &identity) != nil || identity.ClientId != saved.ID ||
			!scope.matches(string(identity.Kind), identity.TeamId, identity.PublicUrlId, identity.ServiceId, identity.DomainId, identity.Namespace) {
			return nil, identity, ErrScope
		}
		native, identity, err = LoadNative(ctx, state, control, authority, identity.ClientId)
		if err != nil {
			return nil, identity, err
		}
		if scope.kind == "namespace" && !bytes.Equal(native.private, saved.SigningKey) {
			return nil, identity, ErrScope
		}
	} else {
		pending, found, err := state.PendingPublisherEnrollmentForSelection(ctx, selection, key)
		if err != nil {
			return nil, identity, err
		}
		if !found {
			enrollment, err := control.CreatePublisherEnrollment(ctx, request)
			if err != nil {
				return nil, identity, err
			}
			if !scope.matches(string(enrollment.Kind), enrollment.TeamId, enrollment.PublicUrlId, enrollment.ServiceId, enrollment.DomainId, enrollment.Namespace) ||
				scope.kind == "namespace" && !enrollment.ExpiresAt.After(time.Now()) {
				return nil, identity, ErrScope
			}
			pending, err = savePendingEnrollment(ctx, state, selection, key, enrollment.Id, enrollment.EnrollmentKey)
			if err != nil {
				return nil, identity, err
			}
		}
		native, identity, err = EnrollNative(ctx, state, control, authority, string(pending.EnrollmentSecret))
		if err != nil {
			return nil, identity, err
		}
	}
	if !scope.matches(string(identity.Kind), identity.TeamId, identity.PublicUrlId, identity.ServiceId, identity.DomainId, identity.Namespace) {
		return nil, identity, ErrScope
	}
	switch scope.kind {
	case "saved_public_url":
		err = native.SelectPublicURL(*scope.publicURL)
	case "namespace":
		if _, err = native.Access(ctx); err == nil {
			err = saveDefaultNamespace(ctx, state, identity)
		}
	}
	if err != nil {
		return nil, identity, err
	}
	return native, identity, nil
}
