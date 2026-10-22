// Package serviceaccess projects the existing exact-service access records for
// both the control-session API and the signed-human authority bridge.
package serviceaccess

import (
	openapi_types "github.com/oapi-codegen/runtime/types"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func Service(record controlstate.ServiceRecord) controlv1.Service {
	result := controlv1.Service{Id: record.ID, TeamId: record.TeamID, Name: record.Name,
		Enabled: record.Enabled, CreatedAt: record.CreatedAt, Protocol: controlv1.ServiceProtocol(record.Protocol),
		PublisherPool: record.PublisherPool, TrustRevision: record.TrustRevision}
	if t := record.Endpoint; t != nil {
		result.Endpoint = &controlv1.ServiceEndpoint{Hostname: t.Hostname, Port: t.Port, Public: t.Public}
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
		result.Placement = &controlv1.ServicePlacement{}
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
		result.TargetTls = &controlv1.ServiceTargetTLS{Hostname: t.Hostname, System: t.System, Digest: t.Digest}
		if t.PEM != "" {
			result.TargetTls.Pem = &t.PEM
		}
	}
	return result
}

// Summary preserves service identity and selection fields without publisher-only
// target trust or HTTP limits. callers needing approved trust fetch one service.
func Summary(record controlstate.ServiceRecord) controlv1.Service {
	record.TLS, record.HTTPLimits = nil, nil
	return Service(record)
}

func Grant(grant controlstate.ServiceGrant) controlv1.ServiceGrant {
	result := controlv1.ServiceGrant{Id: grant.ID, ServiceId: grant.ServiceID,
		Kind: controlv1.ServiceGrantKind(grant.Kind), CreatedAt: grant.CreatedAt,
		ExpiresAt: grant.ExpiresAt, RevokedAt: grant.RevokedAt}
	if grant.IdentityID != "" {
		result.IdentityId = &grant.IdentityID
	}
	if grant.InvitationID != "" {
		result.InvitationId = &grant.InvitationID
	}
	return result
}

func Invitation(invitation controlstate.ServiceInvitation) controlv1.ServiceInvitation {
	result := controlv1.ServiceInvitation{Id: invitation.ID, ServiceId: invitation.ServiceID,
		Email: openapi_types.Email(invitation.Email), ExpiresAt: invitation.ExpiresAt,
		AcceptedAt: invitation.AcceptedAt, RevokedAt: invitation.RevokedAt}
	if invitation.Secret != "" {
		result.Secret = &invitation.Secret
	}
	return result
}
