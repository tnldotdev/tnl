package controlstate

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

const maximumOperatorIPEntries = 64
const maximumOperatorIPLifetime = 24 * time.Hour
const operatorIPExpiryBatch = 32

type LiveIPPolicyChange struct {
	PublicURLID, TeamID, ActingIdentityID    string
	Source                                   *[]string
	AddOperator                              string
	OperatorLifetime                         time.Duration
	RevokeOperatorID                         string
	PolicyRevision, ExpectedMutationRevision uint64
}

type OperatorIPGrant struct {
	ID, Prefix, OwnerID string
	ExpiresAt           time.Time
}

// ChangeLiveIPPolicy updates admission and publishes a new ingress entry while
// a publish run is ready. target and publisher connections stay untouched.
func (d *Database) ChangeLiveIPPolicy(ctx context.Context, change LiveIPPolicyChange, now time.Time) (result PublicURL, issued *OperatorIPGrant, retErr error) {
	modes := 0
	if change.Source != nil {
		modes++
	}
	if change.AddOperator != "" {
		modes++
	}
	if change.RevokeOperatorID != "" {
		modes++
	}
	if modes != 1 || !validStateText(change.PublicURLID) ||
		change.TeamID == "" || change.ActingIdentityID == "" || change.PolicyRevision == 0 ||
		change.ExpectedMutationRevision == 0 || now.IsZero() {
		return PublicURL{}, nil, ErrPublicURLInvalid
	}
	if change.AddOperator != "" && (change.OperatorLifetime < time.Minute || change.OperatorLifetime > maximumOperatorIPLifetime) {
		return PublicURL{}, nil, ErrPublicURLInvalid
	}
	if change.RevokeOperatorID != "" && !opaqueid.Valid(change.RevokeOperatorID, opaqueid.IPPolicyEntryPrefix) {
		return PublicURL{}, nil, ErrPublicURLInvalid
	}
	if err := d.requireOpen(); err != nil {
		return PublicURL{}, nil, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return PublicURL{}, nil, err
	}
	defer rollback(ctx, tx, "change live IP policy", &retErr)()
	queries := controlstatedb.New(tx)
	if _, err := queries.LockLocalTeamForMutation(ctx, change.TeamID); errors.Is(err, pgx.ErrNoRows) {
		return PublicURL{}, nil, ErrPublicURLAccess
	} else if err != nil {
		return PublicURL{}, nil, err
	}
	route, err := queries.LockPublicURLForRun(ctx, change.PublicURLID)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && route.TeamID != change.TeamID {
		return PublicURL{}, nil, ErrPublicURLNotFound
	}
	if err != nil {
		return PublicURL{}, nil, err
	}
	if route.LifecycleState != string(PublicURLLifecycleEnabled) || route.Purpose != string(PublicURLPurposeApp) || route.Ephemeral {
		return PublicURL{}, nil, ErrPublicURLNotEnabled
	}
	if !matchesPositiveInt64(route.MutationRevision, change.ExpectedMutationRevision) {
		return PublicURL{}, nil, ErrPublicURLMutationStale
	}
	if route.PolicyRevision > positive(change.PolicyRevision) {
		return PublicURL{}, nil, ErrPublicURLAuthority
	}
	membership, err := queries.GetActivePublishRunMembership(ctx, controlstatedb.GetActivePublishRunMembershipParams{
		TeamID: change.TeamID, IdentityID: change.ActingIdentityID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return PublicURL{}, nil, ErrPublicURLAccess
	}
	if err != nil {
		return PublicURL{}, nil, err
	}
	if membership.PolicyRevision != positive(change.PolicyRevision) ||
		route.PublicURLScope == string(PublicURLScopeMember) && (!route.MembershipID.Valid || route.MembershipID.String != membership.ID) ||
		route.PublicURLScope == string(PublicURLScopeShared) && membership.Role != "admin" && membership.Role != "owner" {
		return PublicURL{}, nil, ErrPublicURLAccess
	}
	policy, err := d.openSavedIPPolicy(route.ID, route.AllowedIpPolicyStorageKeyID.String, route.AllowedIpPolicyCiphertext)
	if err != nil {
		return PublicURL{}, nil, err
	}
	operator := make([]operatorIPEntry, 0, len(policy.Operator))
	for _, entry := range policy.Operator {
		if entry.ExpiresAt.After(now) {
			operator = append(operator, entry)
		}
	}
	if change.Source != nil {
		policy.Source, err = authorization.CanonicalizeIPPrefixes(*change.Source)
		if err != nil {
			return PublicURL{}, nil, ErrPublicURLInvalid
		}
		if len(policy.Source) == 0 {
			operator = nil
		}
	}
	if change.AddOperator != "" {
		if len(policy.Source) == 0 || len(operator) >= maximumOperatorIPEntries {
			return PublicURL{}, nil, ErrPublicURLInvalid
		}
		canonical, parseErr := authorization.CanonicalizeIPPrefixes([]string{change.AddOperator})
		if parseErr != nil {
			return PublicURL{}, nil, ErrPublicURLInvalid
		}
		for _, entry := range operator {
			if entry.Prefix == canonical[0] && entry.OwnerID == change.ActingIdentityID {
				return PublicURL{}, nil, ErrPublicURLConflict
			}
		}
		id, newErr := opaqueid.New(opaqueid.IPPolicyEntryPrefix)
		if newErr != nil {
			return PublicURL{}, nil, newErr
		}
		until := now.Add(change.OperatorLifetime).UTC()
		operator = append(operator, operatorIPEntry{ID: id, Prefix: canonical[0], OwnerID: change.ActingIdentityID, ExpiresAt: until})
		issued = &OperatorIPGrant{ID: id, Prefix: canonical[0], OwnerID: change.ActingIdentityID, ExpiresAt: until}
	}
	if change.RevokeOperatorID != "" {
		index := slices.IndexFunc(operator, func(entry operatorIPEntry) bool { return entry.ID == change.RevokeOperatorID })
		if index == -1 {
			return PublicURL{}, nil, ErrPublicURLNotFound
		}
		if operator[index].OwnerID != change.ActingIdentityID && membership.Role != "owner" && membership.Role != "admin" {
			return PublicURL{}, nil, ErrPublicURLAccess
		}
		operator = slices.Delete(operator, index, index+1)
	}
	source := make([]netip.Prefix, len(policy.Source))
	for i, value := range policy.Source {
		source[i], err = parseStoredIPPrefix(value)
		if err != nil {
			return PublicURL{}, nil, err
		}
	}
	ciphertext, hashes, keyID, err := d.storeIPPolicyWithOperator(route.ID, source, operator, false)
	if err != nil {
		return PublicURL{}, nil, err
	}
	storageKeyID := ""
	if len(ciphertext) != 0 {
		storageKeyID = d.storageKey.CurrentID()
	}
	updated, err := queries.UpdateLivePublicURLIPPolicy(ctx, controlstatedb.UpdateLivePublicURLIPPolicyParams{
		PublicURLID: route.ID, ExpectedMutationRevision: positive(change.ExpectedMutationRevision),
		PolicyRevision: positive(change.PolicyRevision), IpPolicy: string(routeIPPolicy(source)),
		AllowedIpPolicyCiphertext: ciphertext, AllowedIpPolicyStorageKeyID: nullableText(storageKeyID),
		AllowedIpHashes: hashes, AllowedIpHashKeyID: nullableText(keyID),
		NextOperatorIpExpiry: nextOperatorIPExpiry(operator), UpdatedAt: timestamptz(now),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return PublicURL{}, nil, ErrPublicURLMutationStale
	}
	if err != nil {
		return PublicURL{}, nil, fmt.Errorf("controlstate: change live IP policy: %w", err)
	}
	if err := d.publishLiveIPPolicy(ctx, queries, updated, now); err != nil {
		return PublicURL{}, nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return PublicURL{}, nil, err
	}
	result = publicURLFromModel(updated, "")
	result.AllowedIPPrefixes, err = d.openIPPolicy(updated.ID, storageKeyID, ciphertext)
	return result, issued, err
}

func (d *Database) ListOperatorIPEntries(ctx context.Context, publicURLID string, now time.Time) ([]OperatorIPGrant, error) {
	if !validStateText(publicURLID) {
		return nil, ErrPublicURLInvalid
	}
	if err := d.requireOpen(); err != nil {
		return nil, err
	}
	stored, err := controlstatedb.New(d.pool).GetOperatorIPPolicy(ctx, publicURLID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrPublicURLNotFound
	}
	if err != nil {
		return nil, err
	}
	policy, err := d.openSavedIPPolicy(publicURLID, stored.AllowedIpPolicyStorageKeyID.String, stored.AllowedIpPolicyCiphertext)
	if err != nil {
		return nil, err
	}
	result := make([]OperatorIPGrant, 0, len(policy.Operator))
	for _, entry := range policy.Operator {
		if entry.ExpiresAt.After(now) {
			result = append(result, OperatorIPGrant(entry))
		}
	}
	return result, nil
}

func (d *Database) publishLiveIPPolicy(ctx context.Context, queries *controlstatedb.Queries, route controlstatedb.ControlPublicUrl, now time.Time) error {
	session, err := queries.GetOpenPublishRun(ctx, route.ID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if !session.ReadyAt.Valid || !session.PublisherExpiresAt.Time.After(now) {
		return nil
	}
	connections, err := validReadyPublisherConnections(ctx, queries, session.ID, now)
	if err != nil {
		return err
	}
	pending := pendingIngressRoutingTableEvents{}
	if _, err := pending.addRouteEvent(ctx, queries, route, session, connections,
		publicURLRoutingTableEventKind(len(connections) != 0), now); err != nil {
		return err
	}
	return pending.publish(ctx, queries)
}

// ExpireOperatorIPEntries removes expired grants in bounded URL batches. ingress
// checks each grant deadline locally even when this cleanup is delayed.
func (d *Database) ExpireOperatorIPEntries(ctx context.Context, now time.Time) (count int, retErr error) {
	if err := d.requireOpen(); err != nil {
		return 0, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return 0, err
	}
	defer rollback(ctx, tx, "expire operator IP entries", &retErr)()
	queries := controlstatedb.New(tx)
	routes, err := queries.LockDueOperatorIPPublicURLs(ctx, controlstatedb.LockDueOperatorIPPublicURLsParams{
		Now: timestamptz(now), BatchSize: operatorIPExpiryBatch,
	})
	if err != nil {
		return 0, err
	}
	for _, route := range routes {
		policy, err := d.openSavedIPPolicy(route.ID, route.AllowedIpPolicyStorageKeyID.String, route.AllowedIpPolicyCiphertext)
		if err != nil {
			return 0, err
		}
		source := make([]netip.Prefix, len(policy.Source))
		for i, value := range policy.Source {
			source[i], err = parseStoredIPPrefix(value)
			if err != nil {
				return 0, err
			}
		}
		operator := make([]operatorIPEntry, 0, len(policy.Operator))
		for _, entry := range policy.Operator {
			if entry.ExpiresAt.After(now) {
				operator = append(operator, entry)
			} else {
				count++
			}
		}
		ciphertext, hashes, keyID, err := d.storeIPPolicyWithOperator(route.ID, source, operator, false)
		if err != nil {
			return 0, err
		}
		storageKeyID := ""
		if len(ciphertext) != 0 {
			storageKeyID = d.storageKey.CurrentID()
		}
		updated, err := queries.UpdateLivePublicURLIPPolicy(ctx, controlstatedb.UpdateLivePublicURLIPPolicyParams{
			PublicURLID: route.ID, ExpectedMutationRevision: route.MutationRevision,
			PolicyRevision: route.PolicyRevision, IpPolicy: string(routeIPPolicy(source)),
			AllowedIpPolicyCiphertext: ciphertext, AllowedIpPolicyStorageKeyID: nullableText(storageKeyID),
			AllowedIpHashes: hashes, AllowedIpHashKeyID: nullableText(keyID),
			NextOperatorIpExpiry: nextOperatorIPExpiry(operator), UpdatedAt: timestamptz(now),
		})
		if err != nil {
			return 0, err
		}
		if err := d.publishLiveIPPolicy(ctx, queries, updated, now); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return count, nil
}
