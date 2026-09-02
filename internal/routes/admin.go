package routes

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/state/statedb"
)

const AdminPageSize = 100

func (s *Store) ListAdminRoutes(ctx context.Context, cursor string) ([]Route, string, error) {
	stored, err := s.queries.ListAdminRoutes(ctx, statedb.ListAdminRoutesParams{Cursor: cursor, Limit: AdminPageSize + 1})
	if err != nil {
		return nil, "", fmt.Errorf("routes: admin list routes: %w", err)
	}
	result := make([]Route, 0, min(len(stored), AdminPageSize))
	for _, route := range stored[:min(len(stored), AdminPageSize)] {
		result = append(result, routeFromDB(route))
	}
	next := ""
	if len(stored) > AdminPageSize {
		next = stored[AdminPageSize-1].ID
	}
	return result, next, nil
}

func (s *Store) GetAdminRoute(ctx context.Context, routeID string) (Route, error) {
	route, err := s.queries.GetAdminRoute(ctx, routeID)
	if errors.Is(err, sql.ErrNoRows) {
		return Route{}, ErrNotFound
	}
	if err != nil {
		return Route{}, fmt.Errorf("routes: admin get route: %w", err)
	}
	return routeFromDB(route), nil
}

func (s *Store) SuspendAdminRoute(
	ctx context.Context,
	routeID string,
	revision uint64,
	reason, actor, requestID string,
) (Route, error) {
	if revision == 0 || revision > math.MaxInt64 || !validAdminText(reason, 256) {
		return Route{}, ErrInvalidArgument
	}
	now := time.Unix(0, s.now().UnixNano()).UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Route{}, fmt.Errorf("routes: begin admin suspension: %w", err)
	}
	defer tx.Rollback()
	queries := s.queries.WithTx(tx)
	count, err := queries.SuspendAdminRoute(ctx, statedb.SuspendAdminRouteParams{
		Revision: int64(revision), Reason: nullableAdminString(reason), SuspendedAt: nullableAdminTime(now), RouteID: routeID,
	})
	if err != nil {
		return Route{}, fmt.Errorf("routes: suspend route: %w", err)
	}
	if count == 0 {
		if _, readErr := queries.GetAdminRoute(ctx, routeID); errors.Is(readErr, sql.ErrNoRows) {
			return Route{}, ErrNotFound
		}
		return Route{}, ErrInvalidStatus
	}
	if err := queries.ExpireRouteSessions(ctx, routeID); err != nil {
		return Route{}, fmt.Errorf("routes: expire suspended sessions: %w", err)
	}
	route, err := queries.GetAdminRoute(ctx, routeID)
	if err != nil {
		return Route{}, fmt.Errorf("routes: read suspended route: %w", err)
	}
	if err := s.recordLifecycle(ctx, queries, routeID, uint64(route.Version), now, LifecycleDisconnected); err != nil {
		return Route{}, err
	}
	if err := insertAdminAudit(ctx, queries, actor, requestID, "route.suspend", routeID, now); err != nil {
		return Route{}, err
	}
	if err := tx.Commit(); err != nil {
		return Route{}, fmt.Errorf("routes: commit admin suspension: %w", err)
	}
	return routeFromDB(route), nil
}

func (s *Store) ResumeAdminRoute(
	ctx context.Context,
	routeID string,
	revision uint64,
	actor, requestID string,
) (Route, error) {
	if revision == 0 || revision > math.MaxInt64 {
		return Route{}, ErrInvalidArgument
	}
	now := time.Unix(0, s.now().UnixNano()).UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Route{}, fmt.Errorf("routes: begin admin resume: %w", err)
	}
	defer tx.Rollback()
	queries := s.queries.WithTx(tx)
	count, err := queries.ResumeAdminRoute(ctx, statedb.ResumeAdminRouteParams{Revision: int64(revision), RouteID: routeID})
	if err != nil {
		return Route{}, fmt.Errorf("routes: resume route: %w", err)
	}
	if count == 0 {
		if _, readErr := queries.GetAdminRoute(ctx, routeID); errors.Is(readErr, sql.ErrNoRows) {
			return Route{}, ErrNotFound
		}
		return Route{}, ErrInvalidStatus
	}
	if err := queries.ExpireRouteSessions(ctx, routeID); err != nil {
		return Route{}, fmt.Errorf("routes: fence resumed sessions: %w", err)
	}
	route, err := queries.GetAdminRoute(ctx, routeID)
	if err != nil {
		return Route{}, fmt.Errorf("routes: read resumed route: %w", err)
	}
	if err := insertAdminAudit(ctx, queries, actor, requestID, "route.resume", routeID, now); err != nil {
		return Route{}, err
	}
	if err := tx.Commit(); err != nil {
		return Route{}, fmt.Errorf("routes: commit admin resume: %w", err)
	}
	return routeFromDB(route), nil
}

func (s *Store) ListAdminHostnames(ctx context.Context, cursor string) ([]Hostname, string, error) {
	stored, err := s.queries.ListAdminHostnames(ctx, statedb.ListAdminHostnamesParams{Cursor: cursor, Limit: AdminPageSize + 1})
	if err != nil {
		return nil, "", fmt.Errorf("routes: admin list hostnames: %w", err)
	}
	result := make([]Hostname, 0, min(len(stored), AdminPageSize))
	for _, hostname := range stored[:min(len(stored), AdminPageSize)] {
		result = append(result, hostnameFromDB(hostname))
	}
	next := ""
	if len(stored) > AdminPageSize {
		next = stored[AdminPageSize-1].ID
	}
	return result, next, nil
}

func (s *Store) GetAdminHostname(ctx context.Context, hostnameID string) (Hostname, error) {
	hostname, err := s.queries.GetAdminHostname(ctx, hostnameID)
	if errors.Is(err, sql.ErrNoRows) {
		return Hostname{}, ErrNotFound
	}
	if err != nil {
		return Hostname{}, fmt.Errorf("routes: admin get hostname: %w", err)
	}
	return hostnameFromDB(hostname), nil
}

func (s *Store) ListCurrentAdminHostnameRouteIDs(ctx context.Context, hostnameID string) ([]string, error) {
	rows, err := s.queries.ListCurrentRoutesForAdminHostname(ctx, nullableAdminString(hostnameID))
	if err != nil {
		return nil, fmt.Errorf("routes: list current admin hostname routes: %w", err)
	}
	result := make([]string, 0, len(rows))
	for _, row := range rows {
		result = append(result, row.ID)
	}
	return result, nil
}

func (s *Store) RemoveAdminHostname(
	ctx context.Context,
	hostnameID, actor, requestID string,
) ([]string, error) {
	now := time.Unix(0, s.now().UnixNano()).UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("routes: begin admin hostname removal: %w", err)
	}
	defer tx.Rollback()
	queries := s.queries.WithTx(tx)
	routeRows, err := queries.ListCurrentRoutesForAdminHostname(ctx, nullableAdminString(hostnameID))
	if err != nil {
		return nil, fmt.Errorf("routes: list admin hostname routes: %w", err)
	}
	count, err := queries.RemoveAdminHostname(ctx, statedb.RemoveAdminHostnameParams{
		DeactivatedAt: nullableAdminTime(now), HostnameID: hostnameID,
	})
	if err != nil {
		return nil, fmt.Errorf("routes: remove admin hostname: %w", err)
	}
	if count == 0 {
		if _, readErr := queries.GetAdminHostname(ctx, hostnameID); errors.Is(readErr, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, ErrInvalidStatus
	}
	if err := queries.DeleteHostnameRoutes(ctx, statedb.DeleteHostnameRoutesParams{
		DeletedAt: now.UnixNano(), HostnameID: nullableAdminString(hostnameID),
	}); err != nil {
		return nil, fmt.Errorf("routes: delete admin hostname routes: %w", err)
	}
	if err := queries.RevokeHostnameRouteCredentials(ctx, statedb.RevokeHostnameRouteCredentialsParams{
		RevokedAt: now.UnixNano(), HostnameID: nullableAdminString(hostnameID),
	}); err != nil {
		return nil, fmt.Errorf("routes: revoke admin hostname credentials: %w", err)
	}
	if err := queries.ExpireHostnameRouteSessions(ctx, nullableAdminString(hostnameID)); err != nil {
		return nil, fmt.Errorf("routes: expire admin hostname sessions: %w", err)
	}
	result := make([]string, 0, len(routeRows))
	for _, route := range routeRows {
		result = append(result, route.ID)
		if route.Status == "active" {
			if err := s.recordLifecycle(ctx, queries, route.ID, uint64(route.Version), now, LifecycleDisconnected); err != nil {
				return nil, err
			}
		}
		if err := s.recordLifecycle(ctx, queries, route.ID, uint64(route.Version), now, LifecycleDeleted); err != nil {
			return nil, err
		}
	}
	if err := insertAdminAudit(ctx, queries, actor, requestID, "hostname.remove", hostnameID, now); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("routes: commit admin hostname removal: %w", err)
	}
	return result, nil
}

func (s *Store) QuarantineAdminHostname(
	ctx context.Context,
	hostnameID, reason, actor, requestID string,
) ([]string, error) {
	if !validAdminText(reason, 256) {
		return nil, ErrInvalidArgument
	}
	now := time.Unix(0, s.now().UnixNano()).UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("routes: begin hostname quarantine: %w", err)
	}
	defer tx.Rollback()
	queries := s.queries.WithTx(tx)
	routeRows, err := queries.ListCurrentRoutesForAdminHostname(ctx, nullableAdminString(hostnameID))
	if err != nil {
		return nil, fmt.Errorf("routes: list quarantined hostname routes: %w", err)
	}
	count, err := queries.QuarantineAdminHostname(ctx, statedb.QuarantineAdminHostnameParams{
		Reason: nullableAdminString(reason), QuarantinedAt: nullableAdminTime(now), HostnameID: hostnameID,
	})
	if err != nil {
		return nil, fmt.Errorf("routes: quarantine hostname: %w", err)
	}
	if count == 0 {
		if _, readErr := queries.GetAdminHostname(ctx, hostnameID); errors.Is(readErr, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, ErrInvalidStatus
	}
	routeReason := "hostname quarantined: " + reason
	if len(routeReason) > 256 {
		routeReason = routeReason[:256]
	}
	if err := queries.SuspendAdminHostnameRoutes(ctx, statedb.SuspendAdminHostnameRoutesParams{
		Reason: nullableAdminString(routeReason), SuspendedAt: nullableAdminTime(now), HostnameID: nullableAdminString(hostnameID),
	}); err != nil {
		return nil, fmt.Errorf("routes: suspend quarantined hostname routes: %w", err)
	}
	if err := queries.ExpireHostnameRouteSessions(ctx, nullableAdminString(hostnameID)); err != nil {
		return nil, fmt.Errorf("routes: expire quarantined hostname sessions: %w", err)
	}
	result := make([]string, 0, len(routeRows))
	for _, route := range routeRows {
		result = append(result, route.ID)
		if route.Status == "active" {
			if err := s.recordLifecycle(ctx, queries, route.ID, uint64(route.Version), now, LifecycleDisconnected); err != nil {
				return nil, err
			}
		}
	}
	if err := insertAdminAudit(ctx, queries, actor, requestID, "hostname.quarantine", hostnameID, now); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("routes: commit hostname quarantine: %w", err)
	}
	return result, nil
}

func insertAdminAudit(
	ctx context.Context,
	queries *statedb.Queries,
	actor, requestID, operation, target string,
	at time.Time,
) error {
	if !validAdminText(actor, 256) || !validAdminText(requestID, 68) || !validAdminText(target, 256) {
		return ErrInvalidArgument
	}
	if err := queries.InsertAdminAuditEvent(ctx, statedb.InsertAdminAuditEventParams{
		Actor: actor, RequestID: requestID, Operation: operation, Target: target, OccurredAt: at.UnixNano(),
	}); err != nil {
		return fmt.Errorf("routes: record admin audit event: %w", err)
	}
	return nil
}

func validAdminText(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && strings.TrimSpace(value) == value
}

func nullableAdminString(value string) sql.NullString {
	return sql.NullString{String: value, Valid: value != ""}
}

func nullableAdminTime(value time.Time) sql.NullInt64 {
	return sql.NullInt64{Int64: value.UnixNano(), Valid: !value.IsZero()}
}
