// Package serviceaccess projects the existing exact-service access records for
// both the control-session API and the signed-human authority bridge.
package serviceaccess

import (
	openapi_types "github.com/oapi-codegen/runtime/types"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func Service(record controlstate.PrivateServiceRecord) controlv1.PrivateService {
	result := controlv1.PrivateService{Id: record.ID, TeamId: record.TeamID, Name: record.Name,
		Enabled: record.Enabled, CreatedAt: record.CreatedAt, Protocol: controlv1.PrivateServiceProtocol(record.Protocol),
		PublisherPool: record.PublisherPool, TrustRevision: record.TrustRevision}
	if t := record.ManagedTLS; t != nil {
		result.ManagedTls = &controlv1.ManagedServiceTLS{Hostname: t.Hostname, Port: t.Port, Public: t.Public}
	}
	if h := record.HTTPLimits; h != nil {
		result.HttpLimits = &controlv1.ProjectHTTPApplicationLimits{Total: h.Total, Concurrency: h.Concurrency}
		if r := h.Rate; r != nil {
			result.HttpLimits.Rate = &controlv1.ProjectApplicationRate{Count: r.Count, Per: r.Per, Burst: r.Burst}
		}
	}
	if record.DomainID != "" {
		result.DomainId = &record.DomainID
	}
	if p := record.Placement; p != nil {
		result.Placement = &controlv1.PrivateServicePlacement{}
		if p.DomainID != "" {
			result.Placement.DomainId = &p.DomainID
		}
		if p.WorktreeKey != "" {
			result.Placement.WorktreeKey = &p.WorktreeKey
		}
		if p.WorktreeLabel != "" {
			result.Placement.WorktreeLabel = &p.WorktreeLabel
		}
	}
	if s := record.Source; s != nil {
		result.Source = &controlv1.LocalServiceSource{ProjectKey: s.ProjectKey, SourceFingerprint: s.SourceFingerprint, Service: s.Service, WorktreeKey: s.WorktreeKey}
	}
	if t := record.TLS; t != nil {
		result.TargetTls = &controlv1.PrivateServiceTLS{Hostname: t.Hostname, System: t.System, Digest: t.Digest}
		if t.PEM != "" {
			result.TargetTls.Pem = &t.PEM
		}
	}
	return result
}

// Summary preserves service identity and selection fields without publisher-only
// target trust or HTTP limits. callers needing approved trust fetch one service.
func Summary(record controlstate.PrivateServiceRecord) controlv1.PrivateService {
	record.TLS, record.HTTPLimits = nil, nil
	return Service(record)
}

func Grant(grant controlstate.PrivateServiceGrant) controlv1.PrivateServiceGrant {
	result := controlv1.PrivateServiceGrant{Id: grant.ID, PrivateServiceId: grant.PrivateServiceID,
		Kind: controlv1.PrivateServiceGrantKind(grant.Kind), CreatedAt: grant.CreatedAt,
		ExpiresAt: grant.ExpiresAt, RevokedAt: grant.RevokedAt}
	if grant.IdentityID != "" {
		result.IdentityId = &grant.IdentityID
	}
	if grant.InvitationID != "" {
		result.InvitationId = &grant.InvitationID
	}
	return result
}

func Invitation(invitation controlstate.PrivateServiceInvitation) controlv1.PrivateServiceInvitation {
	result := controlv1.PrivateServiceInvitation{Id: invitation.ID, PrivateServiceId: invitation.PrivateServiceID,
		Email: openapi_types.Email(invitation.Email), ExpiresAt: invitation.ExpiresAt,
		AcceptedAt: invitation.AcceptedAt, RevokedAt: invitation.RevokedAt}
	if invitation.Secret != "" {
		result.Secret = &invitation.Secret
	}
	return result
}
