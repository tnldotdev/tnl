package controlstate

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

const (
	routePageSize                     = 100
	ephemeralRouteGracePeriod         = 2 * time.Minute
	maximumExpiredEphemeralRouteBatch = 100
)

var (
	ErrRouteAccess        = errors.New("controlstate: route access denied")
	ErrRouteConflict      = errors.New("controlstate: route hostname is already in use")
	ErrRouteCreationGated = errors.New("controlstate: route creation is disabled")
	ErrRouteIdempotency   = errors.New("controlstate: route idempotency conflict")
	ErrRouteInvalid       = errors.New("controlstate: route request is invalid")
	ErrRouteSessionOpen   = errors.New("controlstate: route has an open route session")
	ErrRouteMutationStale = errors.New("controlstate: authorized route state changed")
)

type Route struct {
	ID                        string
	TeamID                    string
	DomainID                  string
	MembershipID              string
	CanonicalHostname         string
	Target                    string
	RouteScope                RouteScope
	PolicyRevision            int64
	LifecycleState            RouteLifecycleState
	DNSAuthorityReference     string
	DNSState                  RouteDNSState
	AllowedIPPrefixes         []netip.Prefix
	NextRouteVersion          int64
	MutationRevision          uint64
	AuthorizationRouteVersion uint64
	Ephemeral                 bool
	ExpiresAt                 *time.Time
	OpenRouteSessionID        string
	CreatedAt                 time.Time
	UpdatedAt                 time.Time
}

type CreateRouteRequest struct {
	TeamID                string
	DomainID              string
	MembershipID          string
	ActingIdentityID      string
	IdempotencyKey        string
	RequestDigest         [32]byte
	CanonicalHostname     string
	Target                string
	RouteScope            RouteScope
	AllowedIPPrefixes     []string
	DNSState              RouteDNSState
	DNSAuthorityReference string
	AuthorityIssuer       string
	PolicyRevision        uint64
	Ephemeral             bool
}

type AuthorizedRouteUpdateRequest struct {
	RouteID                  string
	TeamID                   string
	ActingIdentityID         string
	Target                   string
	AllowedIPPrefixes        []string
	AuthorityIssuer          string
	PolicyRevision           uint64
	ExpectedMutationRevision uint64
}

type AuthorizedRouteDeleteRequest struct {
	RouteID                  string
	TeamID                   string
	ActingIdentityID         string
	AuthorityIssuer          string
	PolicyRevision           uint64
	ExpectedMutationRevision uint64
}

type RoutePage struct {
	Routes     []Route
	NextCursor string
}

func (d *Database) CreateRoute(ctx context.Context, request CreateRouteRequest, now time.Time) (result Route, retErr error) {
	prefixes, err := validateCreateRouteRequest(request)
	if err != nil {
		return Route{}, err
	}
	if err := d.requireOpen(); err != nil {
		return Route{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return Route{}, fmt.Errorf("controlstate: create route: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "create route", &retErr)()
	queries := controlstatedb.New(tx)
	if request.AuthorityIssuer == "" {
		if _, err := queries.LockLocalTeamForMutation(ctx, request.TeamID); errors.Is(err, pgx.ErrNoRows) {
			return Route{}, ErrRouteAccess
		} else if err != nil {
			return Route{}, fmt.Errorf("controlstate: create route: lock team: %w", err)
		}
	}
	if _, err := queries.LockRouteCreator(ctx, request.ActingIdentityID); errors.Is(err, pgx.ErrNoRows) {
		return Route{}, ErrRouteAccess
	} else if err != nil {
		return Route{}, fmt.Errorf("controlstate: create route: lock creator: %w", err)
	}
	policyRevision := int64(0)
	if request.AuthorityIssuer != "" {
		policyRevision = positive(request.PolicyRevision)
		if _, err := queries.ObserveAuthorityRevision(ctx, controlstatedb.ObserveAuthorityRevisionParams{
			Issuer: request.AuthorityIssuer, TeamID: request.TeamID,
			PolicyRevision: policyRevision, UpdatedAt: timestamptz(now),
		}); errors.Is(err, pgx.ErrNoRows) {
			return Route{}, ErrRouteAuthority
		} else if err != nil {
			return Route{}, fmt.Errorf("controlstate: create route: observe authority revision: %w", err)
		}
	}

	existing, err := queries.GetRouteByCreatorIdempotency(ctx, controlstatedb.GetRouteByCreatorIdempotencyParams{
		IdentityID: request.ActingIdentityID, IdempotencyKey: request.IdempotencyKey,
	})
	if err == nil {
		if RouteLifecycleState(existing.LifecycleState) == RouteLifecycleDeleted || subtle.ConstantTimeCompare(existing.RequestDigest, request.RequestDigest[:]) != 1 {
			return Route{}, ErrRouteIdempotency
		}
		if err := tx.Commit(ctx); err != nil {
			return Route{}, fmt.Errorf("controlstate: create route: commit retry: %w", err)
		}
		return routeFromIdempotencyRow(existing), nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Route{}, fmt.Errorf("controlstate: create route: read idempotent route: %w", err)
	}

	enabled, err := queries.LockRouteCreationControl(ctx)
	if err != nil {
		return Route{}, fmt.Errorf("controlstate: create route: read maintenance control: %w", err)
	}
	if !enabled {
		return Route{}, ErrRouteCreationGated
	}
	if request.AuthorityIssuer == "" {
		creation, err := queries.GetRouteCreationContext(ctx, controlstatedb.GetRouteCreationContextParams{
			IdentityID: request.ActingIdentityID, DomainID: request.DomainID, TeamID: request.TeamID,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return Route{}, ErrRouteAccess
		}
		if err != nil {
			return Route{}, fmt.Errorf("controlstate: create route: read authority context: %w", err)
		}
		labels, err := queries.ListTeamMemberNamespaceLabels(ctx, request.TeamID)
		if err != nil {
			return Route{}, fmt.Errorf("controlstate: create route: read member namespaces: %w", err)
		}
		if err := authorizeRouteCreation(request, creation, labels); err != nil {
			return Route{}, err
		}
		policyRevision = creation.PolicyRevision
	}

	routeID, err := opaqueid.New("route_")
	if err != nil {
		return Route{}, fmt.Errorf("controlstate: create route: generate route ID: %w", err)
	}
	membershipID := pgtype.Text{}
	if request.MembershipID != "" {
		membershipID = text(request.MembershipID)
	}
	row, err := queries.InsertRoute(ctx, controlstatedb.InsertRouteParams{
		ID: routeID, TeamID: request.TeamID, DomainID: request.DomainID, MembershipID: membershipID,
		CreatedByIdentityID: request.ActingIdentityID, IdempotencyKey: request.IdempotencyKey,
		RequestDigest: request.RequestDigest[:], CanonicalHostname: request.CanonicalHostname, Target: request.Target,
		RouteScope: string(request.RouteScope), PolicyRevision: policyRevision, IpPolicy: routeIPPolicy(prefixes),
		AllowedIpPrefixes: prefixes, DnsAuthorityReference: nullableText(request.DNSAuthorityReference),
		DnsState: string(request.DNSState), Ephemeral: request.Ephemeral,
		ExpiresAt: ephemeralRouteExpiry(request.Ephemeral, now), CreatedAt: timestamptz(now),
	})
	if err != nil {
		var postgresError *pgconn.PgError
		if errors.As(err, &postgresError) && postgresError.Code == "23505" {
			switch postgresError.ConstraintName {
			case "routes_current_hostname":
				return Route{}, ErrRouteConflict
			case "routes_creator_idempotency":
				return Route{}, ErrRouteIdempotency
			}
		}
		return Route{}, fmt.Errorf("controlstate: create route: insert route: %w", err)
	}
	if err := queries.InsertRouteCreateAuditEvent(ctx, controlstatedb.InsertRouteCreateAuditEventParams{
		ActorIdentityID: text(request.ActingIdentityID), RequestID: request.IdempotencyKey,
		RouteID: routeID, OccurredAt: timestamptz(now),
	}); err != nil {
		return Route{}, fmt.Errorf("controlstate: create route: insert audit event: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Route{}, fmt.Errorf("controlstate: create route: commit: %w", err)
	}
	return routeFromModel(row, ""), nil
}

func (d *Database) UpdateAuthorizedRoute(
	ctx context.Context,
	request AuthorizedRouteUpdateRequest,
	now time.Time,
) (result Route, retErr error) {
	prefixes, err := validateAuthorizedRouteUpdateRequest(request)
	if err != nil {
		return Route{}, err
	}
	if err := d.requireOpen(); err != nil {
		return Route{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return Route{}, fmt.Errorf("controlstate: update route: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "update route", &retErr)()
	queries := controlstatedb.New(tx)
	pendingEvents := pendingIngressRoutingTableEvents{}
	policyRevision := positive(request.PolicyRevision)
	if request.AuthorityIssuer == "" {
		if _, err := queries.LockLocalTeamForMutation(ctx, request.TeamID); errors.Is(err, pgx.ErrNoRows) {
			return Route{}, ErrRouteAccess
		} else if err != nil {
			return Route{}, fmt.Errorf("controlstate: update route: lock team: %w", err)
		}
	} else if _, err := queries.ObserveAuthorityRevision(ctx, controlstatedb.ObserveAuthorityRevisionParams{
		Issuer: request.AuthorityIssuer, TeamID: request.TeamID,
		PolicyRevision: policyRevision, UpdatedAt: timestamptz(now),
	}); errors.Is(err, pgx.ErrNoRows) {
		return Route{}, ErrRouteAuthority
	} else if err != nil {
		return Route{}, fmt.Errorf("controlstate: update route: observe authority revision: %w", err)
	}
	route, err := queries.LockRouteForSession(ctx, request.RouteID)
	if errors.Is(err, pgx.ErrNoRows) || err == nil &&
		(route.TeamID != request.TeamID || RouteLifecycleState(route.LifecycleState) == RouteLifecycleDeleted) {
		return Route{}, ErrRouteNotFound
	}
	if err != nil {
		return Route{}, fmt.Errorf("controlstate: update route: lock route: %w", err)
	}
	if RouteLifecycleState(route.LifecycleState) != RouteLifecycleEnabled {
		return Route{}, ErrRouteNotEnabled
	}
	if !matchesPositiveInt64(route.MutationRevision, request.ExpectedMutationRevision) {
		return Route{}, ErrRouteMutationStale
	}
	if route.PolicyRevision > policyRevision {
		return Route{}, ErrRouteAuthority
	}
	hasOpenSession, err := expireStaleOpenRouteSession(ctx, queries, &pendingEvents, route, now)
	if err != nil {
		return Route{}, err
	}
	if hasOpenSession {
		return Route{}, ErrRouteSessionOpen
	}
	if request.AuthorityIssuer == "" {
		membership, err := queries.GetActiveRouteSessionMembership(ctx, controlstatedb.GetActiveRouteSessionMembershipParams{
			TeamID: request.TeamID, IdentityID: request.ActingIdentityID,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return Route{}, ErrRouteAccess
		}
		if err != nil {
			return Route{}, fmt.Errorf("controlstate: update route: read membership: %w", err)
		}
		if membership.PolicyRevision != policyRevision ||
			route.RouteScope == string(RouteScopeMember) && (!route.MembershipID.Valid || route.MembershipID.String != membership.ID) ||
			route.RouteScope == string(RouteScopeShared) && membership.Role != "admin" && membership.Role != "owner" {
			return Route{}, ErrRouteAccess
		}
	}
	updated, err := queries.UpdateRoute(ctx, controlstatedb.UpdateRouteParams{
		Target: request.Target, PolicyRevision: policyRevision, IpPolicy: routeIPPolicy(prefixes),
		AllowedIpPrefixes: prefixes, UpdatedAt: timestamptz(now), RouteID: request.RouteID,
		ExpectedMutationRevision: positive(request.ExpectedMutationRevision),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Route{}, ErrRouteMutationStale
	}
	if err != nil {
		return Route{}, fmt.Errorf("controlstate: update route: update route: %w", err)
	}
	requestID, err := opaqueid.New("request_")
	if err != nil {
		return Route{}, fmt.Errorf("controlstate: update route: generate request ID: %w", err)
	}
	if err := queries.InsertRouteUpdateAuditEvent(ctx, controlstatedb.InsertRouteUpdateAuditEventParams{
		ActorIdentityID: text(request.ActingIdentityID), RequestID: requestID,
		RouteID: request.RouteID, OccurredAt: timestamptz(now),
	}); err != nil {
		return Route{}, fmt.Errorf("controlstate: update route: insert audit event: %w", err)
	}
	if err := pendingEvents.publish(ctx, queries); err != nil {
		return Route{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Route{}, fmt.Errorf("controlstate: update route: commit: %w", err)
	}
	return routeFromModel(updated, ""), nil
}

// DeleteExpiredEphemeralRoutes removes a limited batch of expired routes. It
// uses the same route-session, routing-table, and DNS cleanup as explicit
// deletion.
func (d *Database) DeleteExpiredEphemeralRoutes(ctx context.Context, now time.Time) (count int, retErr error) {
	if err := d.requireOpen(); err != nil {
		return 0, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return 0, fmt.Errorf("controlstate: delete expired ephemeral routes: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "delete expired ephemeral routes", &retErr)()
	queries := controlstatedb.New(tx)
	pendingEvents := pendingIngressRoutingTableEvents{}
	routes, err := queries.LockExpiredEphemeralRoutes(ctx, controlstatedb.LockExpiredEphemeralRoutesParams{
		Now: timestamptz(now), BatchSize: maximumExpiredEphemeralRouteBatch,
	})
	if err != nil {
		return 0, fmt.Errorf("controlstate: delete expired ephemeral routes: lock routes: %w", err)
	}
	for _, route := range routes {
		hasOpenSession, err := expireStaleOpenRouteSession(ctx, queries, &pendingEvents, route, now)
		if err != nil {
			return 0, err
		}
		if hasOpenSession {
			continue
		}
		updated, err := queries.DeleteRoute(ctx, controlstatedb.DeleteRouteParams{
			DeletedAt: timestamptz(now), RouteID: route.ID, ExpectedMutationRevision: route.MutationRevision,
		})
		if err != nil {
			return 0, fmt.Errorf("controlstate: delete expired ephemeral routes: update route: %w", err)
		}
		if updated != 1 {
			return 0, ErrRouteNotFound
		}
		if err := queries.InsertExpiredEphemeralRouteDeleteAuditEvent(
			ctx,
			controlstatedb.InsertExpiredEphemeralRouteDeleteAuditEventParams{
				RequestID: "ephemeral_expiry/" + route.ID, RouteID: route.ID, OccurredAt: timestamptz(now),
			},
		); err != nil {
			return 0, fmt.Errorf("controlstate: delete expired ephemeral routes: insert audit event: %w", err)
		}
		count++
	}
	if err := pendingEvents.publish(ctx, queries); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("controlstate: delete expired ephemeral routes: commit: %w", err)
	}
	return count, nil
}

func (d *Database) ListRoutes(ctx context.Context, identityID, teamID, cursor string) (RoutePage, error) {
	if !validStateText(identityID) || !validStateText(teamID) || cursor != "" && !validStateText(cursor) {
		return RoutePage{}, ErrRouteInvalid
	}
	if err := d.requireOpen(); err != nil {
		return RoutePage{}, err
	}
	rows, err := controlstatedb.New(d.pool).ListIdentityRoutes(ctx, controlstatedb.ListIdentityRoutesParams{
		TeamID: teamID, Cursor: nullableText(cursor), IdentityID: identityID,
	})
	if err != nil {
		return RoutePage{}, fmt.Errorf("controlstate: list routes: %w", err)
	}
	if len(rows) == 0 {
		if _, err := d.GetTeam(ctx, identityID, teamID); err != nil {
			return RoutePage{}, err
		}
	}
	page := RoutePage{Routes: make([]Route, min(len(rows), routePageSize))}
	for index := range page.Routes {
		page.Routes[index] = routeFromListRow(rows[index])
	}
	if len(rows) > routePageSize {
		page.NextCursor = rows[routePageSize-1].ID
	}
	return page, nil
}

// ListAuthorizedRoutes returns one team page after the caller has obtained a
// current authorization decision. It deliberately does not consult local memberships.
func (d *Database) ListAuthorizedRoutes(ctx context.Context, teamID, cursor string) (RoutePage, error) {
	if !validStateText(teamID) || cursor != "" && !validStateText(cursor) {
		return RoutePage{}, ErrRouteInvalid
	}
	if err := d.requireOpen(); err != nil {
		return RoutePage{}, err
	}
	rows, err := controlstatedb.New(d.pool).ListExternalAuthorityRoutes(
		ctx,
		controlstatedb.ListExternalAuthorityRoutesParams{TeamID: teamID, Cursor: nullableText(cursor)},
	)
	if err != nil {
		return RoutePage{}, fmt.Errorf("controlstate: list authorized routes: %w", err)
	}
	page := RoutePage{Routes: make([]Route, min(len(rows), routePageSize))}
	for index := range page.Routes {
		page.Routes[index] = routeFromExternalAuthorityListRow(rows[index])
	}
	if len(rows) > routePageSize {
		page.NextCursor = rows[routePageSize-1].ID
	}
	return page, nil
}

// GetAuthorizedRouteByHostname reads one non-deleted route after a current
// team-read authorization decision, using the existing hostname index.
func (d *Database) GetAuthorizedRouteByHostname(ctx context.Context, teamID, hostname string) (Route, error) {
	canonical, err := naming.CanonicalizeHostname(hostname)
	if !validStateText(teamID) || err != nil || canonical != hostname {
		return Route{}, ErrRouteInvalid
	}
	if err := d.requireOpen(); err != nil {
		return Route{}, err
	}
	row, err := controlstatedb.New(d.pool).GetAuthorizedRouteByHostname(ctx, controlstatedb.GetAuthorizedRouteByHostnameParams{
		TeamID: teamID, CanonicalHostname: hostname,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Route{}, ErrRouteNotFound
	}
	if err != nil {
		return Route{}, fmt.Errorf("controlstate: get authorized route by hostname: %w", err)
	}
	return routeFromExternalAuthorityListRow(controlstatedb.ListExternalAuthorityRoutesRow(row)), nil
}

func (d *Database) GetRoute(ctx context.Context, identityID, routeID string) (Route, error) {
	if !validStateText(identityID) || !validStateText(routeID) {
		return Route{}, ErrRouteInvalid
	}
	if err := d.requireOpen(); err != nil {
		return Route{}, err
	}
	row, err := controlstatedb.New(d.pool).GetIdentityRoute(ctx, controlstatedb.GetIdentityRouteParams{
		RouteID: routeID, IdentityID: identityID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Route{}, ErrRouteNotFound
	}
	if err != nil {
		return Route{}, fmt.Errorf("controlstate: get route: %w", err)
	}
	return routeFromIdentityRow(row), nil
}

func (d *Database) DeleteRoute(ctx context.Context, identityID, routeID string, now time.Time) (retErr error) {
	return d.deleteRoute(ctx, AuthorizedRouteDeleteRequest{RouteID: routeID, ActingIdentityID: identityID}, now)
}

func (d *Database) DeleteAuthorizedRoute(
	ctx context.Context,
	request AuthorizedRouteDeleteRequest,
	now time.Time,
) error {
	return d.deleteRoute(ctx, request, now)
}

func (d *Database) deleteRoute(ctx context.Context, request AuthorizedRouteDeleteRequest, now time.Time) (retErr error) {
	identityID := request.ActingIdentityID
	routeID := request.RouteID
	if !validStateText(identityID) || !validStateText(routeID) {
		return ErrRouteInvalid
	}
	if request.AuthorityIssuer != "" && (!validStateText(request.AuthorityIssuer) || !validStateText(request.TeamID) ||
		request.PolicyRevision == 0 || request.ExpectedMutationRevision == 0) {
		return ErrRouteInvalid
	}
	if err := d.requireOpen(); err != nil {
		return err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fmt.Errorf("controlstate: delete route: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "delete route", &retErr)()
	queries := controlstatedb.New(tx)
	pendingEvents := pendingIngressRoutingTableEvents{}
	var route controlstatedb.ControlRoute
	if request.AuthorityIssuer == "" {
		if _, err := queries.LockLocalRouteTeamForMutation(ctx, routeID); errors.Is(err, pgx.ErrNoRows) {
			return ErrRouteNotFound
		} else if err != nil {
			return fmt.Errorf("controlstate: delete route: lock team: %w", err)
		}
		row, err := queries.LockIdentityRouteForDelete(ctx, controlstatedb.LockIdentityRouteForDeleteParams{
			IdentityID: identityID, RouteID: routeID,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrRouteNotFound
		}
		if err != nil {
			return fmt.Errorf("controlstate: delete route: lock route: %w", err)
		}
		if row.ActorRole == "member" && (!row.MembershipID.Valid || row.MembershipID.String != row.ActorMembershipID) {
			return ErrRouteAccess
		}
		route = routeModelFromDeleteRow(row)
	} else {
		if _, err := queries.ObserveAuthorityRevision(ctx, controlstatedb.ObserveAuthorityRevisionParams{
			Issuer: request.AuthorityIssuer, TeamID: request.TeamID,
			PolicyRevision: positive(request.PolicyRevision), UpdatedAt: timestamptz(now),
		}); errors.Is(err, pgx.ErrNoRows) {
			return ErrRouteAuthority
		} else if err != nil {
			return fmt.Errorf("controlstate: delete route: observe authority revision: %w", err)
		}
		var err error
		route, err = queries.LockRouteForSession(ctx, routeID)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && route.TeamID != request.TeamID {
			return ErrRouteNotFound
		}
		if err != nil {
			return fmt.Errorf("controlstate: delete route: lock route: %w", err)
		}
		if !matchesPositiveInt64(route.MutationRevision, request.ExpectedMutationRevision) {
			return ErrRouteMutationStale
		}
	}
	expectedMutationRevision := route.MutationRevision
	if request.ExpectedMutationRevision != 0 {
		if !matchesPositiveInt64(route.MutationRevision, request.ExpectedMutationRevision) {
			return ErrRouteMutationStale
		}
		expectedMutationRevision = positive(request.ExpectedMutationRevision)
	}
	if err := closeOpenRouteSession(ctx, queries, &pendingEvents, route, now, "route_deleted"); err != nil {
		return err
	}
	updated, err := queries.DeleteRoute(ctx, controlstatedb.DeleteRouteParams{
		DeletedAt: timestamptz(now), RouteID: routeID, ExpectedMutationRevision: expectedMutationRevision,
	})
	if err != nil {
		return fmt.Errorf("controlstate: delete route: update route: %w", err)
	}
	if updated != 1 {
		return ErrRouteNotFound
	}
	requestID, err := opaqueid.New("request_")
	if err != nil {
		return fmt.Errorf("controlstate: delete route: generate request ID: %w", err)
	}
	if err := queries.InsertRouteDeleteAuditEvent(ctx, controlstatedb.InsertRouteDeleteAuditEventParams{
		ActorIdentityID: text(identityID), RequestID: requestID, RouteID: routeID, OccurredAt: timestamptz(now),
	}); err != nil {
		return fmt.Errorf("controlstate: delete route: insert audit event: %w", err)
	}
	if err := pendingEvents.publish(ctx, queries); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("controlstate: delete route: commit: %w", err)
	}
	return nil
}

func (d *Database) CloseRouteSession(ctx context.Context, routeSessionID string, token credentials.RouteSessionToken, now time.Time) (retErr error) {
	if !validStateText(routeSessionID) {
		return ErrRouteSessionCredential
	}
	tokenID, tokenHash, err := credentials.ParseRouteSessionToken(token)
	if err != nil {
		return ErrRouteSessionCredential
	}
	if err := d.requireOpen(); err != nil {
		return err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fmt.Errorf("controlstate: close route session: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "close route session", &retErr)()
	queries := controlstatedb.New(tx)
	pendingEvents := pendingIngressRoutingTableEvents{}
	before, err := queries.GetRouteSession(ctx, routeSessionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrRouteSessionCredential
	}
	if err != nil {
		return fmt.Errorf("controlstate: close route session: read session: %w", err)
	}
	route, err := queries.LockRouteForSession(ctx, before.RouteID)
	if err != nil {
		return fmt.Errorf("controlstate: close route session: lock route: %w", err)
	}
	session, err := queries.LockRouteSession(ctx, routeSessionID)
	if err != nil {
		return fmt.Errorf("controlstate: close route session: lock session: %w", err)
	}
	if tokenID.String() != session.SessionTokenID || !credentials.SecretHashMatches(session.SessionTokenDigest, tokenHash) {
		return ErrRouteSessionCredential
	}
	if session.ClosedAt.Valid {
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("controlstate: close route session: commit retry: %w", err)
		}
		return nil
	}
	if err := closeRouteSession(ctx, queries, &pendingEvents, route, session, RouteSessionClosed, now, "publisher_closed"); err != nil {
		return err
	}
	if err := pendingEvents.publish(ctx, queries); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("controlstate: close route session: commit: %w", err)
	}
	return nil
}

func closeOpenRouteSession(
	ctx context.Context,
	queries *controlstatedb.Queries,
	pendingEvents *pendingIngressRoutingTableEvents,
	route controlstatedb.ControlRoute,
	now time.Time,
	reason string,
) error {
	session, err := queries.GetOpenRouteSession(ctx, route.ID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("controlstate: close route session: read open session: %w", err)
	}
	return closeRouteSession(ctx, queries, pendingEvents, route, session, RouteSessionClosed, now, reason)
}

// expireStaleOpenRouteSession returns whether a live session remains. The caller
// holds the route row through commit, so that answer stays valid in its transaction.
func expireStaleOpenRouteSession(
	ctx context.Context,
	queries *controlstatedb.Queries,
	pendingEvents *pendingIngressRoutingTableEvents,
	route controlstatedb.ControlRoute,
	now time.Time,
) (bool, error) {
	session, err := queries.GetOpenRouteSession(ctx, route.ID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("controlstate: expire route session: read open session: %w", err)
	}
	closedAt := now
	if session.PublisherExpiresAt.Valid {
		if session.PublisherExpiresAt.Time.After(now) {
			return true, nil
		}
		closedAt = session.PublisherExpiresAt.Time
	}
	return false, closeRouteSession(ctx, queries, pendingEvents, route, session, RouteSessionExpired, closedAt, "publisher_expired")
}

func closeRouteSession(
	ctx context.Context,
	queries *controlstatedb.Queries,
	pendingEvents *pendingIngressRoutingTableEvents,
	route controlstatedb.ControlRoute,
	session controlstatedb.ControlRouteSession,
	state RouteSessionState,
	now time.Time,
	reason string,
) error {
	if challengeExpiresAt, active, err := activeRouteSessionChallengeExpiry(ctx, queries, session.ID, now); err != nil {
		return err
	} else if active {
		entryRevision, err := queries.LatestIngressRoutingEntryRevision(ctx, controlstatedb.LatestIngressRoutingEntryRevisionParams{
			RouteID: route.ID, RouteVersion: session.RouteVersion,
		})
		if err != nil {
			return fmt.Errorf("controlstate: close route session: read ingress routing-table entry revision: %w", err)
		}
		if entryRevision > 0 {
			if _, err := pendingEvents.addChallengeEvent(
				ctx, queries, route, session, nil, "challenge_tombstone", challengeExpiresAt, now,
			); err != nil {
				return err
			}
		}
	}
	if session.ReadyAt.Valid {
		if _, err := pendingEvents.addRouteEvent(ctx, queries, route, session, nil, "route_tombstone", now); err != nil {
			return err
		}
	}
	if err := queries.CancelRouteSessionACMEOrders(ctx, controlstatedb.CancelRouteSessionACMEOrdersParams{
		CanceledAt: timestamptz(now), RouteSessionID: session.ID,
	}); err != nil {
		return fmt.Errorf("controlstate: close route session: cancel certificate orders: %w", err)
	}
	if err := queries.CancelRouteSessionACMEAuthorizations(ctx, controlstatedb.CancelRouteSessionACMEAuthorizationsParams{
		CanceledAt: timestamptz(now), RouteSessionID: session.ID,
	}); err != nil {
		return fmt.Errorf("controlstate: close route session: cancel certificate authorizations: %w", err)
	}
	if _, err := queries.CancelOpenRouteRecoveryEpisode(ctx, controlstatedb.CancelOpenRouteRecoveryEpisodeParams{
		CanceledAt: timestamptz(now), RouteID: route.ID, RouteVersion: session.RouteVersion,
	}); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("controlstate: close route session: cancel recovery episode: %w", err)
	}
	if err := queries.CloseRouteSessionConnections(ctx, controlstatedb.CloseRouteSessionConnectionsParams{
		ClosedAt: timestamptz(now), RouteSessionID: session.ID,
	}); err != nil {
		return fmt.Errorf("controlstate: close route session: close publisher connections: %w", err)
	}
	if _, err := queries.CloseRouteSession(ctx, controlstatedb.CloseRouteSessionParams{
		State: string(state), ClosedAt: timestamptz(now), CloseReason: text(reason), RouteSessionID: session.ID,
	}); err != nil {
		return fmt.Errorf("controlstate: close route session: update session: %w", err)
	}
	return nil
}

func validateCreateRouteRequest(request CreateRouteRequest) ([]netip.Prefix, error) {
	for _, value := range []string{
		request.TeamID, request.DomainID, request.ActingIdentityID, request.IdempotencyKey,
		request.CanonicalHostname, request.Target, string(request.RouteScope), string(request.DNSState),
	} {
		if !validStateText(value) {
			return nil, ErrRouteInvalid
		}
	}
	if len(request.IdempotencyKey) > 128 || request.MembershipID != "" && !validStateText(request.MembershipID) ||
		request.DNSAuthorityReference != "" && !validStateText(request.DNSAuthorityReference) ||
		request.DNSState == RouteDNSUnmanaged && request.DNSAuthorityReference != "" ||
		request.RouteScope != RouteScopeMember && request.RouteScope != RouteScopeShared ||
		request.DNSState != RouteDNSUnmanaged && request.DNSState != RouteDNSPending {
		return nil, ErrRouteInvalid
	}
	if request.AuthorityIssuer != "" && (!validStateText(request.AuthorityIssuer) || request.PolicyRevision == 0) {
		return nil, ErrRouteInvalid
	}
	canonical, err := naming.CanonicalizeHostname(request.CanonicalHostname)
	if err != nil || canonical != request.CanonicalHostname {
		return nil, ErrRouteInvalid
	}
	if err := authorization.ValidateRouteTarget(request.Target); err != nil {
		return nil, ErrRouteInvalid
	}
	canonicalPrefixes, err := authorization.CanonicalizeIPPrefixes(request.AllowedIPPrefixes)
	if err != nil || !slices.Equal(canonicalPrefixes, request.AllowedIPPrefixes) {
		return nil, ErrRouteInvalid
	}
	prefixes := make([]netip.Prefix, len(canonicalPrefixes))
	for index, value := range canonicalPrefixes {
		prefixes[index], _ = netip.ParsePrefix(value)
	}
	return prefixes, nil
}

func validateAuthorizedRouteUpdateRequest(request AuthorizedRouteUpdateRequest) ([]netip.Prefix, error) {
	for _, value := range []string{request.RouteID, request.TeamID, request.ActingIdentityID, request.Target} {
		if !validStateText(value) {
			return nil, ErrRouteInvalid
		}
	}
	if request.PolicyRevision == 0 || request.ExpectedMutationRevision == 0 ||
		request.AuthorityIssuer != "" && !validStateText(request.AuthorityIssuer) ||
		authorization.ValidateRouteTarget(request.Target) != nil {
		return nil, ErrRouteInvalid
	}
	canonicalPrefixes, err := authorization.CanonicalizeIPPrefixes(request.AllowedIPPrefixes)
	if err != nil || request.AllowedIPPrefixes == nil || !slices.Equal(canonicalPrefixes, request.AllowedIPPrefixes) {
		return nil, ErrRouteInvalid
	}
	return prefixValues(canonicalPrefixes), nil
}

func ephemeralRouteExpiry(ephemeral bool, now time.Time) pgtype.Timestamptz {
	if !ephemeral {
		return pgtype.Timestamptz{}
	}
	return timestamptz(now.Add(ephemeralRouteGracePeriod))
}

func authorizeRouteCreation(
	request CreateRouteRequest,
	context controlstatedb.GetRouteCreationContextRow,
	labels []controlstatedb.ListTeamMemberNamespaceLabelsRow,
) error {
	if context.DomainState != "ready" || context.DomainKind == "claimed" && context.DomainTeamID.String != request.TeamID ||
		context.DomainKind == "managed" && context.DomainTeamID.Valid || !hostnameWithin(request.CanonicalHostname, context.CanonicalDomain) {
		return ErrRouteAccess
	}
	if request.DNSState == RouteDNSPending && request.DNSAuthorityReference != context.DnsAuthorityReference.String {
		return ErrRouteAccess
	}
	actorLabel := context.ActorMemberSlug
	if context.DomainKind == "managed" {
		actorLabel = context.ActorManagedLabel
	}
	actorNamespace := actorLabel + "." + context.CanonicalDomain
	if request.RouteScope == "member" {
		if request.MembershipID != context.ActorMembershipID ||
			request.CanonicalHostname != actorNamespace && !oneLabelBeneath(request.CanonicalHostname, actorNamespace) {
			return ErrRouteAccess
		}
		return nil
	}
	if request.MembershipID != "" || context.ActorRole != "admin" && context.ActorRole != "owner" {
		return ErrRouteAccess
	}
	if context.DomainKind == "managed" {
		if context.TeamKind != "personal" || context.IdentityKind != "builtin" ||
			context.TeamCreatorIdentityID != request.ActingIdentityID ||
			!oneLabelBeneath(request.CanonicalHostname, context.CanonicalDomain) {
			return ErrRouteAccess
		}
		return nil
	}
	for _, label := range labels {
		namespace := label.MemberSlug + "." + context.CanonicalDomain
		if request.CanonicalHostname == namespace || strings.HasSuffix(request.CanonicalHostname, "."+namespace) {
			return ErrRouteAccess
		}
	}
	return nil
}

func hostnameWithin(hostname, domain string) bool {
	return hostname == domain || strings.HasSuffix(hostname, "."+domain)
}

func oneLabelBeneath(hostname, domain string) bool {
	suffix := "." + domain
	if !strings.HasSuffix(hostname, suffix) {
		return false
	}
	label := strings.TrimSuffix(hostname, suffix)
	return label != "" && !strings.Contains(label, ".")
}

func routeIPPolicy(prefixes []netip.Prefix) string {
	if len(prefixes) == 0 {
		return "allow_all"
	}
	return "allowlist"
}

func nullableText(value string) pgtype.Text {
	if value == "" {
		return pgtype.Text{}
	}
	return text(value)
}

func routeFromModel(row controlstatedb.ControlRoute, openRouteSessionID string) Route {
	return routeFromValues(
		row.ID, row.TeamID, row.DomainID, row.MembershipID, row.CanonicalHostname, row.Target,
		row.RouteScope, row.PolicyRevision, row.LifecycleState, row.DnsAuthorityReference, row.DnsState, row.AllowedIpPrefixes,
		row.NextRouteVersion, row.MutationRevision, row.Ephemeral, row.ExpiresAt, openRouteSessionID, row.CreatedAt, row.UpdatedAt,
	)
}

func routeFromIdempotencyRow(row controlstatedb.GetRouteByCreatorIdempotencyRow) Route {
	return routeFromValues(
		row.ID, row.TeamID, row.DomainID, row.MembershipID, row.CanonicalHostname, row.Target,
		row.RouteScope, row.PolicyRevision, row.LifecycleState, row.DnsAuthorityReference, row.DnsState, row.AllowedIpPrefixes,
		row.NextRouteVersion, row.MutationRevision, row.Ephemeral, row.ExpiresAt, row.OpenRouteSessionID, row.CreatedAt, row.UpdatedAt,
	)
}

func routeFromIdentityRow(row controlstatedb.GetIdentityRouteRow) Route {
	return routeFromValues(
		row.ID, row.TeamID, row.DomainID, row.MembershipID, row.CanonicalHostname, row.Target,
		row.RouteScope, row.PolicyRevision, row.LifecycleState, row.DnsAuthorityReference, row.DnsState, row.AllowedIpPrefixes,
		row.NextRouteVersion, row.MutationRevision, row.Ephemeral, row.ExpiresAt, row.OpenRouteSessionID, row.CreatedAt, row.UpdatedAt,
	)
}

func routeFromListRow(row controlstatedb.ListIdentityRoutesRow) Route {
	return routeFromValues(
		row.ID, row.TeamID, row.DomainID, row.MembershipID, row.CanonicalHostname, row.Target,
		row.RouteScope, row.PolicyRevision, row.LifecycleState, row.DnsAuthorityReference, row.DnsState, row.AllowedIpPrefixes,
		row.NextRouteVersion, row.MutationRevision, row.Ephemeral, row.ExpiresAt, row.OpenRouteSessionID, row.CreatedAt, row.UpdatedAt,
	)
}

func routeFromExternalAuthorityListRow(row controlstatedb.ListExternalAuthorityRoutesRow) Route {
	return routeFromValues(
		row.ID, row.TeamID, row.DomainID, row.MembershipID, row.CanonicalHostname, row.Target,
		row.RouteScope, row.PolicyRevision, row.LifecycleState, row.DnsAuthorityReference, row.DnsState, row.AllowedIpPrefixes,
		row.NextRouteVersion, row.MutationRevision, row.Ephemeral, row.ExpiresAt, row.OpenRouteSessionID, row.CreatedAt, row.UpdatedAt,
	)
}

func routeFromValues(
	id, teamID, domainID string,
	membershipID pgtype.Text,
	canonicalHostname, target, routeScope string,
	policyRevision int64,
	lifecycleState string,
	dnsAuthorityReference pgtype.Text,
	dnsState string,
	allowedIPPrefixes []netip.Prefix,
	nextRouteVersion int64,
	mutationRevision int64,
	ephemeral bool,
	expiresAt pgtype.Timestamptz,
	openRouteSessionID string,
	createdAt, updatedAt pgtype.Timestamptz,
) Route {
	result := Route{
		ID: id, TeamID: teamID, DomainID: domainID, MembershipID: membershipID.String,
		CanonicalHostname: canonicalHostname, Target: target, RouteScope: RouteScope(routeScope),
		PolicyRevision: policyRevision, LifecycleState: RouteLifecycleState(lifecycleState),
		DNSAuthorityReference: dnsAuthorityReference.String, DNSState: RouteDNSState(dnsState),
		AllowedIPPrefixes: append([]netip.Prefix(nil), allowedIPPrefixes...), NextRouteVersion: nextRouteVersion,
		MutationRevision: uint64(mutationRevision), AuthorizationRouteVersion: uint64(nextRouteVersion),
		Ephemeral:          ephemeral,
		OpenRouteSessionID: openRouteSessionID, CreatedAt: createdAt.Time, UpdatedAt: updatedAt.Time,
	}
	if expiresAt.Valid {
		value := expiresAt.Time
		result.ExpiresAt = &value
	}
	return result
}

func routeModelFromDeleteRow(row controlstatedb.LockIdentityRouteForDeleteRow) controlstatedb.ControlRoute {
	return controlstatedb.ControlRoute{
		ID: row.ID, TeamID: row.TeamID, DomainID: row.DomainID, MembershipID: row.MembershipID,
		CreatedByIdentityID: row.CreatedByIdentityID, IdempotencyKey: row.IdempotencyKey,
		RequestDigest: row.RequestDigest, CanonicalHostname: row.CanonicalHostname, Target: row.Target,
		RouteScope: row.RouteScope, PolicyRevision: row.PolicyRevision, IpPolicy: row.IpPolicy,
		AllowedIpPrefixes: row.AllowedIpPrefixes, LifecycleState: row.LifecycleState,
		Ephemeral: row.Ephemeral, ExpiresAt: row.ExpiresAt,
		DnsAuthorityReference: row.DnsAuthorityReference, DnsState: row.DnsState,
		DnsRevision: row.DnsRevision, NextRouteVersion: row.NextRouteVersion, MutationRevision: row.MutationRevision,
		SuspensionRevision: row.SuspensionRevision, SuspensionReason: row.SuspensionReason,
		CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt, SuspendedAt: row.SuspendedAt, DeletedAt: row.DeletedAt,
	}
}
