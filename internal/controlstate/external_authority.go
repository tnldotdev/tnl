package controlstate

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
)

var ErrExternalAuthorityPrincipal = errors.New("controlstate: external authority principal is invalid")

// EnsureExternalAuthorityPrincipal records only the server-local principal ID
// needed by stored route and audit state and returns the shared retry secret.
func (d *Database) EnsureExternalAuthorityPrincipal(
	ctx context.Context,
	identityID string,
	now time.Time,
) (result [32]byte, retErr error) {
	if !validStateText(identityID) {
		return result, ErrExternalAuthorityPrincipal
	}
	if err := d.requireOpen(); err != nil {
		return result, err
	}
	candidate := make([]byte, len(result))
	if _, err := rand.Read(candidate); err != nil {
		return result, fmt.Errorf("controlstate: create external retry master key: %w", err)
	}
	candidateCiphertext, err := d.sealSecret(externalRetryMasterKeyContext(), candidate)
	if err != nil {
		return result, fmt.Errorf("controlstate: encrypt external retry master key: %w", err)
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return result, fmt.Errorf("controlstate: ensure external authority principal: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "ensure external authority principal", &retErr)()
	queries := controlstatedb.New(tx)
	if _, err := queries.EnsureExternalAuthorityPrincipal(ctx, controlstatedb.EnsureExternalAuthorityPrincipalParams{
		IdentityID: identityID, CreatedAt: timestamptz(now),
	}); errors.Is(err, pgx.ErrNoRows) {
		return result, ErrExternalAuthorityPrincipal
	} else if err != nil {
		return result, fmt.Errorf("controlstate: ensure external authority principal: %w", err)
	}
	stored, err := queries.EnsureExternalRetryMasterKey(ctx, controlstatedb.EnsureExternalRetryMasterKeyParams{
		ExternalRetryMasterKeyCiphertext: candidateCiphertext, CreatedAt: timestamptz(now),
		ExternalRetryMasterKeyStorageKeyID: d.storageKey.CurrentID(),
	})
	if err != nil {
		return result, fmt.Errorf("controlstate: ensure external retry master key: %w", err)
	}
	key, previous, err := d.openSecret(stored.ExternalRetryMasterKeyStorageKeyID, externalRetryMasterKeyContext(), stored.ExternalRetryMasterKeyCiphertext)
	if err != nil || len(key) != len(result) {
		return result, errors.New("controlstate: external retry master key is invalid")
	}
	if previous {
		rotated, err := d.sealSecret(externalRetryMasterKeyContext(), key)
		if err != nil {
			return result, fmt.Errorf("controlstate: re-encrypt external retry master key: %w", err)
		}
		if err := queries.RotateExternalRetryMasterKey(ctx, controlstatedb.RotateExternalRetryMasterKeyParams{
			ExternalRetryMasterKeyCiphertext: rotated, ExternalRetryMasterKeyStorageKeyID: d.storageKey.CurrentID(),
			PreviousKeyID: stored.ExternalRetryMasterKeyStorageKeyID, PreviousCiphertext: stored.ExternalRetryMasterKeyCiphertext,
		}); err != nil {
			return result, fmt.Errorf("controlstate: store re-encrypted external retry master key: %w", err)
		}
	}
	copy(result[:], key)
	if err := tx.Commit(ctx); err != nil {
		return result, fmt.Errorf("controlstate: ensure external authority principal: commit: %w", err)
	}
	return result, nil
}

// GetRouteForAuthorization returns stored route data for an authority request.
// Callers must not expose the result before the authority approves it.
func (d *Database) GetRouteForAuthorization(ctx context.Context, routeID string) (Route, error) {
	return d.getRouteForAuthorization(ctx, routeID, "")
}

// GetRouteForSessionAuthorization returns the route version from an earlier
// matching route-session request, or the next version for a new request.
func (d *Database) GetRouteForSessionAuthorization(
	ctx context.Context,
	routeID, idempotencyKey string,
) (Route, error) {
	if !validStateText(idempotencyKey) || len(idempotencyKey) > 128 {
		return Route{}, ErrRouteInvalid
	}
	return d.getRouteForAuthorization(ctx, routeID, idempotencyKey)
}

func (d *Database) getRouteForAuthorization(ctx context.Context, routeID, routeSessionIdempotencyKey string) (Route, error) {
	if !validStateText(routeID) {
		return Route{}, ErrRouteInvalid
	}
	if err := d.requireOpen(); err != nil {
		return Route{}, err
	}
	row, err := controlstatedb.New(d.pool).GetExternalAuthorityRoute(ctx, controlstatedb.GetExternalAuthorityRouteParams{
		RouteID: routeID, RouteSessionIdempotencyKey: routeSessionIdempotencyKey,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Route{}, ErrRouteNotFound
	}
	if err != nil {
		return Route{}, fmt.Errorf("controlstate: get route for authorization: %w", err)
	}
	result := routeFromValues(
		row.ID, row.TeamID, row.DomainID, row.MembershipID, row.CanonicalHostname, row.Target,
		row.RouteScope, row.PolicyRevision, row.LifecycleState, row.DnsAuthorityReference, row.DnsState, row.AllowedIpPrefixes,
		row.NextRouteVersion, row.MutationRevision, row.Ephemeral, row.ExpiresAt, row.AttachedSessionID, row.CreatedAt, row.UpdatedAt,
	)
	result.AuthorizationRouteVersion = uint64(row.AuthorizationRouteVersion)
	return result, nil
}
