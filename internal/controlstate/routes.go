package controlstate

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
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

const routePageSize = 100

var (
	ErrRouteAccess        = errors.New("controlstate: route access denied")
	ErrRouteConflict      = errors.New("controlstate: route hostname is already in use")
	ErrRouteCreationGated = errors.New("controlstate: route creation is disabled")
	ErrRouteIdempotency   = errors.New("controlstate: route idempotency conflict")
	ErrRouteInvalid       = errors.New("controlstate: route request is invalid")
)

type Route struct {
	ID                    string
	TeamID                string
	DomainID              string
	MembershipID          string
	CanonicalHostname     string
	Target                string
	RouteScope            RouteScope
	PolicyRevision        int64
	LifecycleState        RouteLifecycleState
	DNSAuthorityReference string
	DNSState              RouteDNSState
	AllowedIPPrefixes     []netip.Prefix
	NextRouteVersion      int64
	AttachedSessionID     string
	CreatedAt             time.Time
	UpdatedAt             time.Time
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
}

type AuthorizedRouteDeleteRequest struct {
	RouteID          string
	TeamID           string
	ActingIdentityID string
	AuthorityIssuer  string
	PolicyRevision   uint64
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
		DnsState: string(request.DNSState), CreatedAt: timestamptz(now),
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
	if request.AuthorityIssuer != "" && (!validStateText(request.AuthorityIssuer) || !validStateText(request.TeamID) || request.PolicyRevision == 0) {
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
	var route controlstatedb.ControlRoute
	if request.AuthorityIssuer == "" {
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
		var err error
		route, err = queries.LockRouteForSession(ctx, routeID)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && route.TeamID != request.TeamID {
			return ErrRouteNotFound
		}
		if err != nil {
			return fmt.Errorf("controlstate: delete route: lock route: %w", err)
		}
		if _, err := queries.ObserveAuthorityRevision(ctx, controlstatedb.ObserveAuthorityRevisionParams{
			Issuer: request.AuthorityIssuer, TeamID: request.TeamID,
			PolicyRevision: positive(request.PolicyRevision), UpdatedAt: timestamptz(now),
		}); errors.Is(err, pgx.ErrNoRows) {
			return ErrRouteAuthority
		} else if err != nil {
			return fmt.Errorf("controlstate: delete route: observe authority revision: %w", err)
		}
	}
	if err := closeOpenRouteSession(ctx, queries, route, now, "route_deleted"); err != nil {
		return err
	}
	updated, err := queries.DeleteRoute(ctx, controlstatedb.DeleteRouteParams{DeletedAt: timestamptz(now), RouteID: routeID})
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
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("controlstate: delete route: commit: %w", err)
	}
	return nil
}

func (d *Database) CloseRouteSession(ctx context.Context, routeSessionID string, token credentials.SessionToken, now time.Time) (retErr error) {
	if !validStateText(routeSessionID) {
		return ErrRouteSessionCredential
	}
	tokenID, tokenHash, err := credentials.ParseSessionToken(token)
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
	if err := closeRouteSession(ctx, queries, route, session, now, "publisher_closed"); err != nil {
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
	return closeRouteSession(ctx, queries, route, session, now, reason)
}

func closeRouteSession(
	ctx context.Context,
	queries *controlstatedb.Queries,
	route controlstatedb.ControlRoute,
	session controlstatedb.ControlRouteSession,
	now time.Time,
	reason string,
) error {
	if challengeExpiresAt, active, err := activeRouteSessionChallengeExpiry(ctx, queries, session.ID, now); err != nil {
		return err
	} else if active {
		if _, _, err := emitChallengeRoutingTableEvent(
			ctx, queries, route, session, nil, "challenge_tombstone", challengeExpiresAt, now,
		); err != nil {
			return err
		}
	}
	if session.ReadyAt.Valid {
		if _, _, err := emitRouteRoutingTableEvent(ctx, queries, route, session, nil, "route_tombstone", now); err != nil {
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
		ClosedAt: timestamptz(now), CloseReason: text(reason), RouteSessionID: session.ID,
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
	parsedTarget, err := url.Parse(request.Target)
	if err != nil || parsedTarget.Scheme != "http" || parsedTarget.User != nil || parsedTarget.RawQuery != "" ||
		parsedTarget.Fragment != "" || parsedTarget.Path != "" || parsedTarget.Port() == "" {
		return nil, ErrRouteInvalid
	}
	targetAddress, err := netip.ParseAddr(parsedTarget.Hostname())
	if err != nil || !targetAddress.IsLoopback() || targetAddress.Zone() != "" {
		return nil, ErrRouteInvalid
	}
	canonicalPrefixes, err := authorization.CanonicalizeIPPrefixes(request.AllowedIPPrefixes)
	if err != nil {
		return nil, ErrRouteInvalid
	}
	prefixes := make([]netip.Prefix, len(canonicalPrefixes))
	for index, value := range canonicalPrefixes {
		prefixes[index], _ = netip.ParsePrefix(value)
	}
	return prefixes, nil
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

func routeFromModel(row controlstatedb.ControlRoute, attachedSessionID string) Route {
	return routeFromValues(
		row.ID, row.TeamID, row.DomainID, row.MembershipID, row.CanonicalHostname, row.Target,
		row.RouteScope, row.PolicyRevision, row.LifecycleState, row.DnsAuthorityReference, row.DnsState, row.AllowedIpPrefixes,
		row.NextRouteVersion, attachedSessionID, row.CreatedAt, row.UpdatedAt,
	)
}

func routeFromIdempotencyRow(row controlstatedb.GetRouteByCreatorIdempotencyRow) Route {
	return routeFromValues(
		row.ID, row.TeamID, row.DomainID, row.MembershipID, row.CanonicalHostname, row.Target,
		row.RouteScope, row.PolicyRevision, row.LifecycleState, row.DnsAuthorityReference, row.DnsState, row.AllowedIpPrefixes,
		row.NextRouteVersion, row.AttachedSessionID, row.CreatedAt, row.UpdatedAt,
	)
}

func routeFromIdentityRow(row controlstatedb.GetIdentityRouteRow) Route {
	return routeFromValues(
		row.ID, row.TeamID, row.DomainID, row.MembershipID, row.CanonicalHostname, row.Target,
		row.RouteScope, row.PolicyRevision, row.LifecycleState, row.DnsAuthorityReference, row.DnsState, row.AllowedIpPrefixes,
		row.NextRouteVersion, row.AttachedSessionID, row.CreatedAt, row.UpdatedAt,
	)
}

func routeFromListRow(row controlstatedb.ListIdentityRoutesRow) Route {
	return routeFromValues(
		row.ID, row.TeamID, row.DomainID, row.MembershipID, row.CanonicalHostname, row.Target,
		row.RouteScope, row.PolicyRevision, row.LifecycleState, row.DnsAuthorityReference, row.DnsState, row.AllowedIpPrefixes,
		row.NextRouteVersion, row.AttachedSessionID, row.CreatedAt, row.UpdatedAt,
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
	attachedSessionID string,
	createdAt, updatedAt pgtype.Timestamptz,
) Route {
	return Route{
		ID: id, TeamID: teamID, DomainID: domainID, MembershipID: membershipID.String,
		CanonicalHostname: canonicalHostname, Target: target, RouteScope: RouteScope(routeScope),
		PolicyRevision: policyRevision, LifecycleState: RouteLifecycleState(lifecycleState),
		DNSAuthorityReference: dnsAuthorityReference.String, DNSState: RouteDNSState(dnsState),
		AllowedIPPrefixes: append([]netip.Prefix(nil), allowedIPPrefixes...), NextRouteVersion: nextRouteVersion,
		AttachedSessionID: attachedSessionID, CreatedAt: createdAt.Time, UpdatedAt: updatedAt.Time,
	}
}

func routeModelFromDeleteRow(row controlstatedb.LockIdentityRouteForDeleteRow) controlstatedb.ControlRoute {
	return controlstatedb.ControlRoute{
		ID: row.ID, TeamID: row.TeamID, DomainID: row.DomainID, MembershipID: row.MembershipID,
		CreatedByIdentityID: row.CreatedByIdentityID, IdempotencyKey: row.IdempotencyKey,
		RequestDigest: row.RequestDigest, CanonicalHostname: row.CanonicalHostname, Target: row.Target,
		RouteScope: row.RouteScope, PolicyRevision: row.PolicyRevision, IpPolicy: row.IpPolicy,
		AllowedIpPrefixes: row.AllowedIpPrefixes, LifecycleState: row.LifecycleState,
		DnsAuthorityReference: row.DnsAuthorityReference, DnsState: row.DnsState,
		DnsRevision: row.DnsRevision, NextRouteVersion: row.NextRouteVersion,
		SuspensionRevision: row.SuspensionRevision, SuspensionReason: row.SuspensionReason,
		CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt, SuspendedAt: row.SuspendedAt, DeletedAt: row.DeletedAt,
	}
}
