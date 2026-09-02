// Package admin implements the concrete self-hosted Core administration operations.
package admin

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/routes"
	"github.com/tnldotdev/tnl/internal/state/statedb"
)

const PageSize = 100

type SwitchName string

const (
	SwitchNewRoutes           SwitchName = "new_routes"
	SwitchNewSessions         SwitchName = "new_sessions"
	SwitchCertificateIssuance SwitchName = "certificate_issuance"
)

var (
	ErrNotFound              = errors.New("admin: not found")
	ErrInvalidArgument       = errors.New("admin: invalid argument")
	ErrStatusConflict        = errors.New("admin: status conflict")
	ErrOperationallyDisabled = errors.New("admin: operation disabled")
)

type ServerStatus struct {
	Mode             string
	StartedAt        time.Time
	CurrentTime      time.Time
	ActiveRoutes     int64
	SuspendedRoutes  int64
	Provisioning     int
	ConnectedWorkers int
}

type Credential struct {
	ID        string
	RouteID   string
	CreatedAt time.Time
	RevokedAt time.Time
}

type ControlSession struct {
	ID                   string
	IdentityID           string
	AuthenticationMethod string
	Grants               []string
	CreatedAt            time.Time
	AccessExpiresAt      time.Time
	RefreshExpiresAt     time.Time
	RevokedAt            time.Time
}

type OperationalSwitch struct {
	Name      SwitchName
	Enabled   bool
	Revision  uint64
	UpdatedAt time.Time
	UpdatedBy string
}

type Service struct {
	db           *sql.DB
	routes       *routes.Coordinator
	mode         string
	startedAt    time.Time
	drainTimeout time.Duration
	now          func() time.Time
}

func NewService(db *sql.DB, coordinator *routes.Coordinator, mode string, drainTimeout time.Duration) (*Service, error) {
	if db == nil || coordinator == nil || strings.TrimSpace(mode) == "" || drainTimeout <= 0 {
		return nil, errors.New("admin: incomplete service configuration")
	}
	return &Service{
		db: db, routes: coordinator, mode: mode, startedAt: time.Now().UTC(),
		drainTimeout: drainTimeout, now: time.Now,
	}, nil
}

func (s *Service) Status(ctx context.Context) (ServerStatus, error) {
	if err := s.db.PingContext(ctx); err != nil {
		return ServerStatus{}, fmt.Errorf("admin: ping state: %w", err)
	}
	queries := statedb.New(s.db)
	active, err := queries.CountAdminRoutesByStatus(ctx, "active")
	if err != nil {
		return ServerStatus{}, fmt.Errorf("admin: count active routes: %w", err)
	}
	suspended, err := queries.CountAdminRoutesByStatus(ctx, "suspended")
	if err != nil {
		return ServerStatus{}, fmt.Errorf("admin: count suspended routes: %w", err)
	}
	health := s.routes.HealthStats()
	return ServerStatus{
		Mode: s.mode, StartedAt: s.startedAt, CurrentTime: s.now().UTC(),
		ActiveRoutes: active, SuspendedRoutes: suspended, Provisioning: health.Provisioning,
		ConnectedWorkers: health.ConnectedWorkers,
	}, nil
}

func (s *Service) ListRoutes(ctx context.Context, cursor string) ([]routes.Route, string, error) {
	return s.routes.ListAdminRoutes(ctx, cursor)
}

func (s *Service) Route(ctx context.Context, routeID string) (routes.Route, error) {
	return s.routes.GetAdminRoute(ctx, routeID)
}

func (s *Service) SuspendRoute(
	ctx context.Context,
	routeID string,
	revision uint64,
	reason, actor, requestID string,
) (routes.Route, error) {
	drainCtx, cancel := context.WithTimeout(ctx, s.drainTimeout)
	defer cancel()
	return s.routes.SuspendAdminRoute(drainCtx, routeID, revision, reason, actor, requestID)
}

func (s *Service) ResumeRoute(
	ctx context.Context,
	routeID string,
	revision uint64,
	actor, requestID string,
) (routes.Route, error) {
	return s.routes.ResumeAdminRoute(ctx, routeID, revision, actor, requestID)
}

func (s *Service) ListHostnames(ctx context.Context, cursor string) ([]routes.Hostname, string, error) {
	return s.routes.ListAdminHostnames(ctx, cursor)
}

func (s *Service) Hostname(ctx context.Context, hostnameID string) (routes.Hostname, error) {
	return s.routes.GetAdminHostname(ctx, hostnameID)
}

func (s *Service) RemoveHostname(ctx context.Context, hostnameID, actor, requestID string) error {
	drainCtx, cancel := context.WithTimeout(ctx, s.drainTimeout)
	defer cancel()
	return s.routes.RemoveAdminHostname(drainCtx, hostnameID, actor, requestID)
}

func (s *Service) QuarantineHostname(
	ctx context.Context,
	hostnameID, reason, actor, requestID string,
) error {
	drainCtx, cancel := context.WithTimeout(ctx, s.drainTimeout)
	defer cancel()
	return s.routes.QuarantineAdminHostname(drainCtx, hostnameID, reason, actor, requestID)
}

func (s *Service) ListCredentials(ctx context.Context, cursor string) ([]Credential, string, error) {
	rows, err := statedb.New(s.db).ListAdminCredentials(ctx, statedb.ListAdminCredentialsParams{
		Cursor: cursor, Limit: PageSize + 1,
	})
	if err != nil {
		return nil, "", fmt.Errorf("admin: list credentials: %w", err)
	}
	result := make([]Credential, 0, min(len(rows), PageSize))
	for _, row := range rows[:min(len(rows), PageSize)] {
		credential := Credential{ID: row.ID, RouteID: row.RouteID, CreatedAt: time.Unix(0, row.CreatedAt).UTC()}
		if row.RevokedAt.Valid {
			credential.RevokedAt = time.Unix(0, row.RevokedAt.Int64).UTC()
		}
		result = append(result, credential)
	}
	next := ""
	if len(rows) > PageSize {
		next = rows[PageSize-1].ID
	}
	return result, next, nil
}

func (s *Service) RevokeCredential(ctx context.Context, credentialID, actor, requestID string) error {
	now := time.Unix(0, s.now().UnixNano()).UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("admin: begin credential revocation: %w", err)
	}
	defer tx.Rollback()
	queries := statedb.New(tx)
	if _, err := queries.GetAdminCredentialRoute(ctx, credentialID); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return fmt.Errorf("admin: read credential: %w", err)
	}
	count, err := queries.RevokeAdminCredential(ctx, statedb.RevokeAdminCredentialParams{
		RevokedAt: nullableTime(now), CredentialID: credentialID,
	})
	if err != nil {
		return fmt.Errorf("admin: revoke credential: %w", err)
	}
	if count == 0 {
		return ErrStatusConflict
	}
	if err := insertAudit(ctx, queries, actor, requestID, "credential.revoke", credentialID, now); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("admin: commit credential revocation: %w", err)
	}
	return nil
}

func (s *Service) ListControlSessions(ctx context.Context, cursor string) ([]ControlSession, string, error) {
	rows, err := statedb.New(s.db).ListAdminControlSessions(ctx, statedb.ListAdminControlSessionsParams{
		Cursor: cursor, Limit: PageSize + 1,
	})
	if err != nil {
		return nil, "", fmt.Errorf("admin: list control sessions: %w", err)
	}
	result := make([]ControlSession, 0, min(len(rows), PageSize))
	for _, row := range rows[:min(len(rows), PageSize)] {
		session := ControlSession{
			ID: row.ID, IdentityID: row.IdentityID, AuthenticationMethod: row.AuthenticationMethod,
			Grants: strings.Split(row.Grants, ","), CreatedAt: time.Unix(0, row.CreatedAt).UTC(),
			AccessExpiresAt:  time.Unix(0, row.AccessExpiresAt).UTC(),
			RefreshExpiresAt: time.Unix(0, row.RefreshExpiresAt).UTC(),
		}
		if row.RevokedAt.Valid {
			session.RevokedAt = time.Unix(0, row.RevokedAt.Int64).UTC()
		}
		result = append(result, session)
	}
	next := ""
	if len(rows) > PageSize {
		next = rows[PageSize-1].ID
	}
	return result, next, nil
}

func (s *Service) RevokeControlSession(ctx context.Context, sessionID, actor, requestID string) error {
	now := time.Unix(0, s.now().UnixNano()).UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("admin: begin control-session revocation: %w", err)
	}
	defer tx.Rollback()
	queries := statedb.New(tx)
	count, err := queries.RevokeAdminControlSession(ctx, statedb.RevokeAdminControlSessionParams{
		RevokedAt: nullableTime(now), SessionID: sessionID,
	})
	if err != nil {
		return fmt.Errorf("admin: revoke control session: %w", err)
	}
	if count == 0 {
		return ErrNotFound
	}
	if err := queries.DeleteInactiveControlSessionRefreshTokens(ctx, now.UnixNano()); err != nil {
		return fmt.Errorf("admin: prune revoked control session credentials: %w", err)
	}
	if err := insertAudit(ctx, queries, actor, requestID, "control_session.revoke", sessionID, now); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("admin: commit control-session revocation: %w", err)
	}
	return nil
}

func (s *Service) Switches(ctx context.Context) ([]OperationalSwitch, error) {
	rows, err := statedb.New(s.db).ListOperationalSwitches(ctx)
	if err != nil {
		return nil, fmt.Errorf("admin: list operational switches: %w", err)
	}
	result := make([]OperationalSwitch, 0, len(rows))
	for _, row := range rows {
		result = append(result, operationalSwitch(row))
	}
	return result, nil
}

func (s *Service) SetSwitch(
	ctx context.Context,
	name SwitchName,
	enabled bool,
	actor, requestID string,
) (OperationalSwitch, error) {
	if !validSwitch(name) {
		return OperationalSwitch{}, ErrInvalidArgument
	}
	now := time.Unix(0, s.now().UnixNano()).UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return OperationalSwitch{}, fmt.Errorf("admin: begin switch update: %w", err)
	}
	defer tx.Rollback()
	queries := statedb.New(tx)
	value := int64(0)
	if enabled {
		value = 1
	}
	count, err := queries.SetOperationalSwitch(ctx, statedb.SetOperationalSwitchParams{
		Enabled: value, UpdatedAt: now.UnixNano(), UpdatedBy: actor, Name: string(name),
	})
	if err != nil {
		return OperationalSwitch{}, fmt.Errorf("admin: set operational switch: %w", err)
	}
	if count == 0 {
		return OperationalSwitch{}, ErrNotFound
	}
	if err := insertAudit(ctx, queries, actor, requestID, "switch.set", string(name), now); err != nil {
		return OperationalSwitch{}, err
	}
	row, err := queries.GetOperationalSwitch(ctx, string(name))
	if err != nil {
		return OperationalSwitch{}, fmt.Errorf("admin: read updated switch: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return OperationalSwitch{}, fmt.Errorf("admin: commit switch update: %w", err)
	}
	return operationalSwitch(row), nil
}

func (s *Service) RequireEnabled(ctx context.Context, name SwitchName) error {
	if !validSwitch(name) {
		return ErrInvalidArgument
	}
	value, err := statedb.New(s.db).GetOperationalSwitch(ctx, string(name))
	if err != nil {
		return fmt.Errorf("admin: read operational switch: %w", err)
	}
	if value.Enabled == 0 {
		return fmt.Errorf("%w: %s", ErrOperationallyDisabled, name)
	}
	return nil
}

func operationalSwitch(row statedb.OperationalSwitch) OperationalSwitch {
	return OperationalSwitch{
		Name: SwitchName(row.Name), Enabled: row.Enabled != 0, Revision: uint64(row.Revision),
		UpdatedAt: time.Unix(0, row.UpdatedAt).UTC(), UpdatedBy: row.UpdatedBy,
	}
}

func validSwitch(name SwitchName) bool {
	return name == SwitchNewRoutes || name == SwitchNewSessions || name == SwitchCertificateIssuance
}

func insertAudit(
	ctx context.Context,
	queries *statedb.Queries,
	actor, requestID, operation, target string,
	at time.Time,
) error {
	if !validText(actor, 256) || !validText(requestID, 68) || !validText(target, 256) {
		return ErrInvalidArgument
	}
	if err := queries.InsertAdminAuditEvent(ctx, statedb.InsertAdminAuditEventParams{
		Actor: actor, RequestID: requestID, Operation: operation, Target: target, OccurredAt: at.UnixNano(),
	}); err != nil {
		return fmt.Errorf("admin: record audit event: %w", err)
	}
	return nil
}

func validText(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && strings.TrimSpace(value) == value
}

func nullableTime(value time.Time) sql.NullInt64 {
	return sql.NullInt64{Int64: value.UnixNano(), Valid: !value.IsZero()}
}
