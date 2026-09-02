package admin

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/auth"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/routes"
	"github.com/tnldotdev/tnl/internal/state"
	"github.com/tnldotdev/tnl/internal/state/statedb"
)

func TestMaintenanceControlIsDurableAndAudited(t *testing.T) {
	db, err := state.Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	now := time.Unix(1_700_000_000, 0).UTC()
	service := &Service{db: db, now: func() time.Time { return now }}

	values, err := service.ListMaintenanceControls(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 3 {
		t.Fatalf("maintenance controls = %#v", values)
	}
	for _, value := range values {
		if !value.Enabled || value.Revision != 1 || value.UpdatedBy != "system" {
			t.Fatalf("initial maintenance control = %#v", value)
		}
	}
	updated, err := service.SetMaintenanceControl(
		t.Context(), MaintenanceControlRouteSessionCreation, false, "identity_local", "req_disable_sessions",
	)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Enabled || updated.Revision != 2 || updated.UpdatedBy != "identity_local" || !updated.UpdatedAt.Equal(now) {
		t.Fatalf("updated maintenance control = %#v", updated)
	}
	if err := service.RequireEnabled(t.Context(), MaintenanceControlRouteSessionCreation); !errors.Is(err, ErrMaintenanceControlDisabled) {
		t.Fatalf("disabled maintenance control error = %v", err)
	}
	if count, err := statedb.New(db).CountAdminAuditEvents(t.Context()); err != nil || count != 1 {
		t.Fatalf("audit count = %d, %v", count, err)
	}
}

func TestCredentialAndControlSessionRevocationAreImmediateAndAudited(t *testing.T) {
	db, err := state.Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	login, err := credentials.NewLoginToken()
	if err != nil {
		t.Fatal(err)
	}
	authentication, err := auth.NewService(db, auth.ServiceConfig{
		LoginToken: login, LoginTokenRevision: 1,
		AccessLifetime: auth.DefaultAccessTokenLifetime, RefreshLifetime: auth.DefaultRefreshTokenLifetime,
	})
	if err != nil {
		t.Fatal(err)
	}
	control, err := authentication.Exchange(t.Context(), login)
	if err != nil {
		t.Fatal(err)
	}
	store, err := routes.NewStore(db, "example")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimManagedHostname(t.Context(), "identity_local", "route", "admin-revoke"); err != nil {
		t.Fatal(err)
	}
	routeToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.Create(
		t.Context(), "identity_local", "route.example", "localhost:3000", "instance", routeToken, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{db: db, now: time.Now}

	sessions, _, err := service.ListControlSessions(t.Context(), "")
	if err != nil || len(sessions) != 1 || sessions[0].ID != control.SessionID {
		t.Fatalf("control sessions = %#v, %v", sessions, err)
	}
	listed, _, err := service.ListCredentials(t.Context(), "")
	if err != nil || len(listed) != 1 || listed[0].RouteID != created.Route.ID {
		t.Fatalf("credentials = %#v, %v", listed, err)
	}
	if err := service.RevokeCredential(
		t.Context(), listed[0].ID, "identity_local", "req_revoke_credential",
	); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateSession(
		t.Context(), "identity_local", created.Route.ID, "instance", routeToken, nil,
	); !errors.Is(err, routes.ErrUnauthenticated) {
		t.Fatalf("revoked credential error = %v", err)
	}
	if err := service.RevokeControlSession(
		t.Context(), control.SessionID, "identity_local", "req_revoke_control",
	); err != nil {
		t.Fatal(err)
	}
	if _, err := authentication.Authenticate(t.Context(), control.AccessToken); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("revoked control session error = %v", err)
	}
	if count, err := statedb.New(db).CountAdminAuditEvents(t.Context()); err != nil || count != 2 {
		t.Fatalf("audit count = %d, %v", count, err)
	}
}
