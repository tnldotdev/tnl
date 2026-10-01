package controlstate

// TeamRole is a membership's authorization role.
type TeamRole string

const (
	TeamRoleMember TeamRole = "member"
	TeamRoleAdmin  TeamRole = "admin"
	TeamRoleOwner  TeamRole = "owner"
)

func (role TeamRole) valid() bool {
	return role == TeamRoleMember || role == TeamRoleAdmin || role == TeamRoleOwner
}

// TeamKind distinguishes personal and organization teams.
type TeamKind string

const (
	TeamKindPersonal     TeamKind = "personal"
	TeamKindOrganization TeamKind = "organization"
)

// InvitationState is the stored state of a team invitation.
type InvitationState string

const (
	InvitationPending  InvitationState = "pending"
	InvitationAccepted InvitationState = "accepted"
	InvitationRevoked  InvitationState = "revoked"
	InvitationExpired  InvitationState = "expired"
)

// DomainKind distinguishes managed and claimed team domains.
type DomainKind string

const (
	DomainKindManaged DomainKind = "managed"
	DomainKindClaimed DomainKind = "claimed"
)

// DomainState is the stored state of a team domain, including released domains.
// the team-domain query excludes released domains from public responses.
type DomainState string

const (
	DomainPending   DomainState = "pending"
	DomainReady     DomainState = "ready"
	DomainReleasing DomainState = "releasing"
	DomainReleased  DomainState = "released"
	DomainFailed    DomainState = "failed"
)
