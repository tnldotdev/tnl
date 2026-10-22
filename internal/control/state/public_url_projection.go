package controlstate

import (
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func publicURLFromModel(row controlstatedb.ControlPublicUrl, openPublishRunID string) PublicURL {
	return publicURLFromProjection(publicURLProjection{
		ID: row.ID, TeamID: row.TeamID, DomainID: row.DomainID, MembershipID: row.MembershipID,
		CanonicalHostname: row.CanonicalHostname, Target: row.Target, Namespace: row.Namespace,
		PublicURLScope: row.PublicURLScope, Purpose: row.Purpose, AccessMode: row.AccessMode,
		PolicyRevision: row.PolicyRevision, LifecycleState: row.LifecycleState,
		DNSAuthorityReference: row.DnsAuthorityReference, DNSState: row.DnsState,
		NextPublishRunNumber: row.NextPublishRunNumber, MutationRevision: row.MutationRevision,
		Ephemeral: row.Ephemeral, ExpiresAt: row.ExpiresAt, OpenPublishRunID: openPublishRunID,
		CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt, ServiceProtocol: row.ServiceProtocol, PublisherPool: row.PublisherPool,
	})
}

func publicURLFromIdempotencyRow(row controlstatedb.GetPublicURLByCreatorIdempotencyRow) PublicURL {
	return publicURLFromProjection(publicURLProjection{
		ID: row.ID, TeamID: row.TeamID, DomainID: row.DomainID, MembershipID: row.MembershipID,
		CanonicalHostname: row.CanonicalHostname, Target: row.Target, Namespace: row.Namespace,
		PublicURLScope: row.PublicURLScope, Purpose: row.Purpose, AccessMode: row.AccessMode,
		PolicyRevision: row.PolicyRevision, LifecycleState: row.LifecycleState,
		DNSAuthorityReference: row.DnsAuthorityReference, DNSState: row.DnsState,
		NextPublishRunNumber: row.NextPublishRunNumber, MutationRevision: row.MutationRevision,
		Ephemeral: row.Ephemeral, ExpiresAt: row.ExpiresAt, OpenPublishRunID: row.OpenPublishRunID,
		CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt, ServiceProtocol: row.ServiceProtocol, PublisherPool: row.PublisherPool,
	})
}

func publicURLFromIdentityRow(row controlstatedb.GetIdentityPublicURLRow) PublicURL {
	return publicURLFromProjection(publicURLProjection{
		ID: row.ID, TeamID: row.TeamID, DomainID: row.DomainID, MembershipID: row.MembershipID,
		CanonicalHostname: row.CanonicalHostname, Target: row.Target, Namespace: row.Namespace,
		PublicURLScope: row.PublicURLScope, Purpose: row.Purpose, AccessMode: row.AccessMode,
		PolicyRevision: row.PolicyRevision, LifecycleState: row.LifecycleState,
		DNSAuthorityReference: row.DnsAuthorityReference, DNSState: row.DnsState,
		NextPublishRunNumber: row.NextPublishRunNumber, MutationRevision: row.MutationRevision,
		Ephemeral: row.Ephemeral, ExpiresAt: row.ExpiresAt, OpenPublishRunID: row.OpenPublishRunID,
		CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt, ServiceProtocol: row.ServiceProtocol, PublisherPool: row.PublisherPool,
	})
}

func publicURLFromListRow(row controlstatedb.ListIdentityPublicURLsRow) PublicURL {
	return publicURLFromProjection(publicURLProjection{
		ID: row.ID, TeamID: row.TeamID, DomainID: row.DomainID, MembershipID: row.MembershipID,
		CanonicalHostname: row.CanonicalHostname, Target: row.Target, Namespace: row.Namespace,
		PublicURLScope: row.PublicURLScope, Purpose: row.Purpose, AccessMode: row.AccessMode,
		PolicyRevision: row.PolicyRevision, LifecycleState: row.LifecycleState,
		DNSAuthorityReference: row.DnsAuthorityReference, DNSState: row.DnsState,
		NextPublishRunNumber: row.NextPublishRunNumber, MutationRevision: row.MutationRevision,
		Ephemeral: row.Ephemeral, ExpiresAt: row.ExpiresAt, OpenPublishRunID: row.OpenPublishRunID,
		CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt, ServiceProtocol: row.ServiceProtocol, PublisherPool: row.PublisherPool,
	})
}

func publicURLFromAuthorizedListRow(row controlstatedb.ListAuthorizedPublicURLsDataRow) PublicURL {
	return publicURLFromProjection(publicURLProjection{
		ID: row.ID, TeamID: row.TeamID, DomainID: row.DomainID, MembershipID: row.MembershipID,
		CanonicalHostname: row.CanonicalHostname, Target: row.Target, Namespace: row.Namespace,
		PublicURLScope: row.PublicURLScope, Purpose: row.Purpose, AccessMode: row.AccessMode,
		PolicyRevision: row.PolicyRevision, LifecycleState: row.LifecycleState,
		DNSAuthorityReference: row.DnsAuthorityReference, DNSState: row.DnsState,
		NextPublishRunNumber: row.NextPublishRunNumber, MutationRevision: row.MutationRevision,
		Ephemeral: row.Ephemeral, ExpiresAt: row.ExpiresAt, OpenPublishRunID: row.OpenPublishRunID,
		CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt, ServiceProtocol: row.ServiceProtocol, PublisherPool: row.PublisherPool,
	})
}

type publicURLProjection struct {
	ID, TeamID, DomainID, CanonicalHostname, Target, Namespace string
	MembershipID                                               pgtype.Text
	PublicURLScope, Purpose, AccessMode, LifecycleState        string
	PolicyRevision, NextPublishRunNumber, MutationRevision     int64
	DNSAuthorityReference                                      pgtype.Text
	DNSState, OpenPublishRunID, ServiceProtocol                string
	Ephemeral, PublisherPool                                   bool
	ExpiresAt, CreatedAt, UpdatedAt                            pgtype.Timestamptz
	AuthorizationPublishRunNumber                              *int64
}

func publicURLFromProjection(p publicURLProjection) PublicURL {
	authorizationNumber := p.NextPublishRunNumber
	if p.AuthorizationPublishRunNumber != nil {
		authorizationNumber = *p.AuthorizationPublishRunNumber
	}
	result := PublicURL{
		ID: p.ID, TeamID: p.TeamID, DomainID: p.DomainID, MembershipID: p.MembershipID.String,
		CanonicalHostname: p.CanonicalHostname, Namespace: p.Namespace, Target: p.Target, PublicURLScope: PublicURLScope(p.PublicURLScope), Purpose: PublicURLPurpose(p.Purpose),
		ServiceProtocol: PublicURLServiceProtocol(p.ServiceProtocol),
		PublisherPool:   p.PublisherPool,
		PolicyRevision:  p.PolicyRevision, AccessMode: VisitorAccessMode(p.AccessMode), LifecycleState: PublicURLLifecycleState(p.LifecycleState),
		DNSAuthorityReference: p.DNSAuthorityReference.String, DNSState: PublicURLDNSState(p.DNSState),
		NextPublishRunNumber: p.NextPublishRunNumber,
		MutationRevision:     uint64(p.MutationRevision), AuthorizationPublishRunNumber: uint64(authorizationNumber),
		Ephemeral:        p.Ephemeral,
		OpenPublishRunID: p.OpenPublishRunID, CreatedAt: p.CreatedAt.Time, UpdatedAt: p.UpdatedAt.Time,
	}
	if p.ExpiresAt.Valid {
		value := p.ExpiresAt.Time
		result.ExpiresAt = &value
	}
	return result
}

func publicURLModelFromDeleteRow(row controlstatedb.LockIdentityPublicURLForDeleteRow) controlstatedb.ControlPublicUrl {
	return controlstatedb.ControlPublicUrl{
		ID: row.ID, TeamID: row.TeamID, DomainID: row.DomainID, MembershipID: row.MembershipID,
		CreatedByIdentityID: row.CreatedByIdentityID, IdempotencyKey: row.IdempotencyKey,
		RequestDigestCiphertext:   row.RequestDigestCiphertext,
		RequestDigestStorageKeyID: row.RequestDigestStorageKeyID,
		CanonicalHostname:         row.CanonicalHostname, Target: row.Target,
		PublicURLScope: row.PublicURLScope, Purpose: row.Purpose, ServiceProtocol: row.ServiceProtocol, PublisherPool: row.PublisherPool,
		PolicyRevision: row.PolicyRevision, AccessMode: row.AccessMode, IpPolicy: row.IpPolicy,
		AllowedIpPolicyCiphertext:   row.AllowedIpPolicyCiphertext,
		AllowedIpPolicyStorageKeyID: row.AllowedIpPolicyStorageKeyID,
		AllowedIpHashes:             row.AllowedIpHashes, AllowedIpHashKeyID: row.AllowedIpHashKeyID,
		LifecycleState: row.LifecycleState,
		Ephemeral:      row.Ephemeral, ExpiresAt: row.ExpiresAt,
		DnsAuthorityReference: row.DnsAuthorityReference, DnsState: row.DnsState,
		DnsRevision: row.DnsRevision, NextPublishRunNumber: row.NextPublishRunNumber, MutationRevision: row.MutationRevision,
		SuspensionRevision: row.SuspensionRevision, SuspensionReason: row.SuspensionReason,
		CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt, SuspendedAt: row.SuspendedAt, DeletedAt: row.DeletedAt,
	}
}
