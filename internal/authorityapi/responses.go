package authorityapi

import (
	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

func controlSessionResponse(session controlstate.ControlSession) authorityv1.ControlSessionResponse {
	return authorityv1.ControlSessionResponse{
		SessionId: session.SessionID, AccessToken: session.AccessToken.String(),
		AccessExpiresAt: session.AccessExpiresAt, RefreshToken: session.RefreshToken.String(),
		RefreshExpiresAt: session.RefreshExpiresAt, Identity: identityContextResponse(session.Identity),
	}
}

func identityContextResponse(context controlstate.IdentityContext) authorityv1.IdentityContext {
	identity := authorityv1.Identity{
		Id: context.Identity.ID, DisplayName: context.Identity.DisplayName,
		Administrator: context.Identity.Administrator, CreatedAt: context.Identity.CreatedAt,
	}
	if context.Identity.NormalizedEmail != "" {
		email := openapi_types.Email(context.Identity.NormalizedEmail)
		verified := context.Identity.EmailVerified
		identity.NormalizedEmail, identity.EmailVerified = &email, &verified
	}
	memberships := make([]authorityv1.Membership, len(context.Memberships))
	for index, membership := range context.Memberships {
		memberships[index] = membershipResponse(membership)
	}
	return authorityv1.IdentityContext{
		Identity: identity, PersonalTeamId: context.PersonalTeamID, Memberships: memberships,
	}
}

func membershipResponse(membership controlstate.Membership) authorityv1.Membership {
	return authorityv1.Membership{
		Id: membership.ID, TeamId: membership.TeamID, IdentityId: membership.IdentityID,
		TeamDisplayName: membership.TeamDisplayName, TeamKind: authorityv1.TeamKind(membership.TeamKind),
		Role: authorityv1.TeamRole(membership.Role), MemberSlug: membership.MemberSlug,
		ManagedLabel: membership.ManagedLabel, PolicyRevision: membership.PolicyRevision,
		CreatedAt: membership.CreatedAt, UpdatedAt: membership.UpdatedAt,
	}
}

func invitationResponse(invitation controlstate.Invitation) authorityv1.Invitation {
	result := authorityv1.Invitation{
		Id: invitation.ID, TeamId: invitation.TeamID, MemberSlug: invitation.MemberSlug,
		InitialRole: authorityv1.TeamRole(invitation.InitialRole), State: authorityv1.InvitationState(invitation.State),
		CreatedAt: invitation.CreatedAt, ExpiresAt: invitation.ExpiresAt,
	}
	if invitation.NormalizedEmailRestriction != "" {
		email := openapi_types.Email(invitation.NormalizedEmailRestriction)
		result.NormalizedEmailRestriction = &email
	}
	return result
}

func teamResponse(team controlstate.Team) authorityv1.Team {
	return authorityv1.Team{
		Id: team.ID, Kind: authorityv1.TeamKind(team.Kind), DisplayName: team.DisplayName,
		ManagedLabel: team.ManagedLabel, DefaultDomainId: team.DefaultDomainID,
		PolicyRevision: team.PolicyRevision, CreatedAt: team.CreatedAt, UpdatedAt: team.UpdatedAt,
	}
}

func domainResponse(domain controlstate.Domain) authorityv1.Domain {
	result := authorityv1.Domain{
		Id: domain.ID, Kind: authorityv1.DomainKind(domain.Kind), CanonicalDomain: domain.CanonicalDomain,
		State: authorityv1.DomainState(domain.State), AuthorityRevision: domain.AuthorityRevision,
		RequiredRecords: make([]authorityv1.DNSRecord, len(domain.RequiredRecords)),
		CreatedAt:       domain.CreatedAt, UpdatedAt: domain.UpdatedAt,
	}
	for index, record := range domain.RequiredRecords {
		result.RequiredRecords[index] = authorityv1.DNSRecord{
			Name: record.Name, Type: authorityv1.DNSRecordType(record.Type), Value: record.Value,
		}
	}
	if domain.TeamID != "" {
		result.TeamId = &domain.TeamID
	}
	if !domain.VerifiedAt.IsZero() {
		result.VerifiedAt = &domain.VerifiedAt
	}
	return result
}
