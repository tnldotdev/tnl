package controlapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestAdminHandlersExposeDurableState(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	deadline := now.Add(time.Minute)
	store := &adminStoreStub{
		principal: controlstate.ControlPrincipal{IdentityID: "identity_admin", Administrator: true},
		counts: controlstate.AdminRuntimeCounts{
			EnabledRoutes: 1, SuspendedRoutes: 2, StartingRouteSessions: 3,
			ReadyRouteSessions: 4, IngressLeases: 5, RelayLeases: 6,
		},
		relayPage: controlstate.AdminRelayPage{
			Relays: []controlstate.RelayLease{{
				RelayLeaseIdentity: controlstate.RelayLeaseIdentity{
					RelayServiceID: "relay_service", RelayID: "relay_1", RelayRunID: "run_1", RelayLeaseRevision: 7,
				},
				ProtocolVersion: 1, RelayAddress: "relay.example:443", TLSServerName: "relay.example",
				InternalRelayAddress: "relay.internal:9443", ConnectionCapacity: 10, StreamCapacity: 20,
				RenewedAt: now, LeaseExpiresAt: deadline,
			}},
			NextCursor: "relay_1",
		},
		controls: []controlstate.MaintenanceControl{{
			Name: controlstate.MaintenanceControlRouteCreation, Allowed: true, Revision: 1,
			UpdatedAt: now, UpdatedBy: "identity_admin",
		}},
	}
	store.drained = store.relayPage.Relays[0]
	store.drained.Draining = true
	store.drained.DrainDeadline = &deadline
	handler := NewHandler(Config{Role: "control", StartedAt: now.Add(-time.Hour)}, store, store, func(context.Context) error { return nil })

	status := serveAdminRequest(handler, http.MethodGet, "/v1/admin/status", "")
	if status.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", status.Code, status.Body.String())
	}
	var statusBody controlv1.AdminServerStatus
	if err := json.Unmarshal(status.Body.Bytes(), &statusBody); err != nil || statusBody.RelayLeases != 6 || statusBody.Role != controlv1.Control {
		t.Fatalf("status body = %#v, %v", statusBody, err)
	}

	relays := serveAdminRequest(handler, http.MethodGet, "/v1/admin/relays?cursor=relay_0", "")
	if relays.Code != http.StatusOK || store.relayCursor != "relay_0" || !strings.Contains(relays.Body.String(), `"next_cursor":"relay_1"`) {
		t.Fatalf("relay page = %d, cursor %q: %s", relays.Code, store.relayCursor, relays.Body.String())
	}

	drainBody := `{"relay_run_id":"run_1","relay_lease_revision":7,"deadline":"` + deadline.Format(time.RFC3339) + `"}`
	drain := serveAdminRequest(handler, http.MethodPost, "/v1/admin/relays/relay_1/drain", drainBody)
	if drain.Code != http.StatusOK || store.drainIdentity.RelayID != "relay_1" ||
		store.drainIdentity.RelayRunID != "run_1" || store.drainActor != "identity_admin" || store.drainRequestID == "" {
		t.Fatalf("drain = %d, identity %#v, actor %q: %s", drain.Code, store.drainIdentity, store.drainActor, drain.Body.String())
	}

	controls := serveAdminRequest(handler, http.MethodGet, "/v1/admin/maintenance-controls", "")
	if controls.Code != http.StatusOK || !strings.Contains(controls.Body.String(), `"name":"route_creation"`) {
		t.Fatalf("maintenance controls = %d: %s", controls.Code, controls.Body.String())
	}
	set := serveAdminRequest(handler, http.MethodPut, "/v1/admin/maintenance-controls/route_creation", `{"allowed":false}`)
	if set.Code != http.StatusOK || store.setName != controlstate.MaintenanceControlRouteCreation ||
		store.setAllowed || store.setActor != "identity_admin" || store.setRequestID == "" {
		t.Fatalf("set maintenance control = %d, %q, %t: %s", set.Code, store.setName, store.setAllowed, set.Body.String())
	}
}

func TestAdminHandlersRejectNonAdministrators(t *testing.T) {
	store := &adminStoreStub{principal: controlstate.ControlPrincipal{IdentityID: "identity_user"}}
	handler := NewHandler(Config{}, store, store, func(context.Context) error { return nil })
	response := serveAdminRequest(handler, http.MethodGet, "/v1/admin/status", "")
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
}

func serveAdminRequest(handler http.Handler, method, path, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer access-token")
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

type adminStoreStub struct {
	Store
	BuiltinAuthorizationStore
	principal      controlstate.ControlPrincipal
	counts         controlstate.AdminRuntimeCounts
	relayPage      controlstate.AdminRelayPage
	relayCursor    string
	drained        controlstate.RelayLease
	drainIdentity  controlstate.RelayLeaseIdentity
	drainActor     string
	drainRequestID string
	controls       []controlstate.MaintenanceControl
	setName        controlstate.MaintenanceControlName
	setAllowed     bool
	setActor       string
	setRequestID   string
}

func (s *adminStoreStub) AuthenticateAccessToken(context.Context, credentials.AccessToken, int64, time.Time) (controlstate.ControlPrincipal, error) {
	return s.principal, nil
}

func (s *adminStoreStub) IdentityContext(context.Context, string) (controlstate.IdentityContext, error) {
	return controlstate.IdentityContext{}, nil
}

func (s *adminStoreStub) AdminRuntimeCounts(context.Context, time.Time) (controlstate.AdminRuntimeCounts, error) {
	return s.counts, nil
}

func (s *adminStoreStub) ListAdminRelayLeases(_ context.Context, cursor string, _ time.Time) (controlstate.AdminRelayPage, error) {
	s.relayCursor = cursor
	return s.relayPage, nil
}

func (s *adminStoreStub) BeginAdminRelayDrain(
	_ context.Context,
	identity controlstate.RelayLeaseIdentity,
	actorIdentityID, requestID string,
	_, _ time.Time,
) (controlstate.RelayLease, error) {
	s.drainIdentity, s.drainActor, s.drainRequestID = identity, actorIdentityID, requestID
	return s.drained, nil
}

func (s *adminStoreStub) ListMaintenanceControls(context.Context) ([]controlstate.MaintenanceControl, error) {
	return s.controls, nil
}

func (s *adminStoreStub) SetMaintenanceControl(
	_ context.Context,
	name controlstate.MaintenanceControlName,
	allowed bool,
	actorIdentityID, requestID string,
	_ time.Time,
) (controlstate.MaintenanceControl, error) {
	s.setName, s.setAllowed, s.setActor, s.setRequestID = name, allowed, actorIdentityID, requestID
	return controlstate.MaintenanceControl{
		Name: name, Allowed: allowed, Revision: 2, UpdatedAt: time.Now(), UpdatedBy: actorIdentityID,
	}, nil
}
