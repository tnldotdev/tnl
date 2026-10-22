package controlstate

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func (d *Database) UpdateAuthorizedPublicURL(
	ctx context.Context,
	request AuthorizedPublicURLUpdateRequest,
	now time.Time,
) (result PublicURL, retErr error) {
	prefixes, err := validateAuthorizedPublicURLUpdateRequest(request)
	if err != nil {
		return PublicURL{}, err
	}
	if err := d.requireOpen(); err != nil {
		return PublicURL{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return PublicURL{}, fmt.Errorf("controlstate: update public_url: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "update route", &retErr)()
	queries := controlstatedb.New(tx)
	pendingEvents := pendingIngressRoutingTableEvents{}
	policyRevision := positive(request.PolicyRevision)
	{
		if _, err := queries.LockLocalTeamForMutation(ctx, request.TeamID); errors.Is(err, pgx.ErrNoRows) {
			return PublicURL{}, ErrPublicURLAccess
		} else if err != nil {
			return PublicURL{}, fmt.Errorf("controlstate: update public_url: lock team: %w", err)
		}
	}
	route, err := queries.LockPublicURLForRun(ctx, request.PublicURLID)
	if errors.Is(err, pgx.ErrNoRows) || err == nil &&
		(route.TeamID != request.TeamID || PublicURLLifecycleState(route.LifecycleState) == PublicURLLifecycleDeleted) {
		return PublicURL{}, ErrPublicURLNotFound
	}
	if err != nil {
		return PublicURL{}, fmt.Errorf("controlstate: update public_url: lock public_url: %w", err)
	}
	if PublicURLLifecycleState(route.LifecycleState) != PublicURLLifecycleEnabled {
		return PublicURL{}, ErrPublicURLNotEnabled
	}
	if request.Target == "" && (route.Target != "" || !PublicURLServiceProtocol(route.ServiceProtocol).ValidCreateTarget(PublicURLPurpose(route.Purpose), "", route.Ephemeral)) ||
		request.Target != "" && route.ServiceProtocol != string(PublicURLServiceHTTP) {
		return PublicURL{}, ErrPublicURLInvalid
	}
	if !matchesPositiveInt64(route.MutationRevision, request.ExpectedMutationRevision) {
		return PublicURL{}, ErrPublicURLMutationStale
	}
	if route.PolicyRevision > policyRevision {
		return PublicURL{}, ErrPublicURLAuthority
	}
	hasOpenSession, _, err := expireStaleOpenPublishRun(ctx, queries, &pendingEvents, route, now)
	if err != nil {
		return PublicURL{}, err
	}
	if hasOpenSession {
		return PublicURL{}, ErrPublishRunOpen
	}
	{
		membership, err := queries.GetActivePublishRunMembership(ctx, controlstatedb.GetActivePublishRunMembershipParams{
			TeamID: request.TeamID, IdentityID: request.ActingIdentityID,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return PublicURL{}, ErrPublicURLAccess
		}
		if err != nil {
			return PublicURL{}, fmt.Errorf("controlstate: update public_url: read membership: %w", err)
		}
		if membership.PolicyRevision != policyRevision ||
			route.PublicURLScope == string(PublicURLScopeMember) && (!route.MembershipID.Valid || route.MembershipID.String != membership.ID) ||
			route.PublicURLScope == string(PublicURLScopeShared) && membership.Role != "admin" && membership.Role != "owner" {
			return PublicURL{}, ErrPublicURLAccess
		}
	}
	if err = rejectProjectManagedDefinition(ctx, tx, request.PublicURLID); err != nil {
		return PublicURL{}, err
	}
	policyCiphertext, policyHashes, policyKeyID, err := d.storeIPPolicy(request.PublicURLID, prefixes, false)
	if err != nil {
		return PublicURL{}, fmt.Errorf("controlstate: protect updated IP policy: %w", err)
	}
	policyStorageKeyID := ""
	if len(policyCiphertext) != 0 {
		policyStorageKeyID = d.storageKey.CurrentID()
	}
	updated, err := queries.UpdatePublicURL(ctx, controlstatedb.UpdatePublicURLParams{
		Target: request.Target, PolicyRevision: policyRevision, IpPolicy: string(routeIPPolicy(prefixes)),
		AllowedIpPolicyCiphertext:   policyCiphertext,
		AllowedIpPolicyStorageKeyID: nullableText(policyStorageKeyID),
		AllowedIpHashes:             policyHashes, AllowedIpHashKeyID: nullableText(policyKeyID),
		UpdatedAt: timestamptz(now), PublicURLID: request.PublicURLID,
		ExpectedMutationRevision: positive(request.ExpectedMutationRevision),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return PublicURL{}, ErrPublicURLMutationStale
	}
	if err != nil {
		return PublicURL{}, fmt.Errorf("controlstate: update public_url: update public_url: %w", err)
	}
	requestID, err := opaqueid.New(opaqueid.RequestPrefix)
	if err != nil {
		return PublicURL{}, fmt.Errorf("controlstate: update public_url: generate request ID: %w", err)
	}
	if err := queries.InsertPublicURLUpdateAuditEvent(ctx, controlstatedb.InsertPublicURLUpdateAuditEventParams{
		ActorIdentityID: text(request.ActingIdentityID), RequestID: requestID,
		PublicURLID: request.PublicURLID, OccurredAt: timestamptz(now),
	}); err != nil {
		return PublicURL{}, fmt.Errorf("controlstate: update public_url: insert audit event: %w", err)
	}
	if err := pendingEvents.publish(ctx, queries); err != nil {
		return PublicURL{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return PublicURL{}, fmt.Errorf("controlstate: update public_url: commit: %w", err)
	}
	result = publicURLFromModel(updated, "")
	result.AllowedIPPrefixes = append([]netip.Prefix(nil), prefixes...)
	return result, nil
}
