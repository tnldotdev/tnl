package public

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestAdminHandlersExposeDurableState(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	deadline := now.Add(time.Minute)
	store := &adminStoreStub{
		principal: controlstate.ControlPrincipal{IdentityID: "identity_admin", Administrator: true},
		counts: controlstate.AdminRuntimeCounts{
			EnabledServices: 1, SuspendedServices: 2, StartingServiceRuns: 3,
			ReadyServiceRuns: 4, IngressLeases: 5, RelayLeases: 6,
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
			Name: controlstate.MaintenanceControlServiceCreation, Allowed: true, Revision: 1,
			UpdatedAt: now, UpdatedBy: "identity_admin",
		}},
	}
	store.drained = store.relayPage.Relays[0]
	store.drained.Draining = true
	store.drained.DrainDeadline = &deadline
	handler := testHandler(t, Config{Role: "control", StartedAt: now.Add(-time.Hour)}, store, store, func(context.Context) error { return nil })

	status := serveAdminRequest(handler, http.MethodGet, "/v1/admin/status", "")
	if status.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", status.Code, status.Body.String())
	}
	var statusBody controlv1.AdminServerStatus
	if err := json.Unmarshal(status.Body.Bytes(), &statusBody); err != nil || statusBody.Role != controlv1.Control ||
		statusBody.EnabledServices != 1 || statusBody.SuspendedServices != 2 ||
		statusBody.StartingServiceRuns != 3 || statusBody.ReadyServiceRuns != 4 ||
		statusBody.IngressLeases != 5 || statusBody.RelayLeases != 6 {
		t.Fatalf("status body = %#v, %v", statusBody, err)
	}
	var statusFields map[string]json.RawMessage
	if err := json.Unmarshal(status.Body.Bytes(), &statusFields); err != nil {
		t.Fatal(err)
	}
	for field, want := range map[string]string{
		"enabled_services": "1", "suspended_services": "2", "starting_service_runs": "3", "ready_service_runs": "4",
	} {
		if string(statusFields[field]) != want {
			t.Fatalf("status field %s = %s; want %s", field, statusFields[field], want)
		}
	}
	for _, field := range []string{"enabled_public_urls", "suspended_public_urls", "starting_publish_runs", "ready_publish_runs"} {
		if _, exists := statusFields[field]; exists {
			t.Fatalf("status included retired field %s", field)
		}
	}

	relays := serveAdminRequest(handler, http.MethodGet, "/v1/admin/relays?cursor=relay_0", "")
	if relays.Code != http.StatusOK || store.relayCursor != "relay_0" || !strings.Contains(relays.Body.String(), `"next_cursor":"relay_1"`) {
		t.Fatalf("relay page = %d, cursor %q: %s", relays.Code, store.relayCursor, relays.Body.String())
	}

	drainBody := `{"relay_run_id":"run_1","relay_lease_revision":"7","deadline":"` + deadline.Format(time.RFC3339) + `"}`
	drain := serveAdminRequest(handler, http.MethodPost, "/v1/admin/relays/relay_1/drain", drainBody)
	if drain.Code != http.StatusOK || store.drainIdentity.RelayID != "relay_1" ||
		store.drainIdentity.RelayRunID != "run_1" || store.drainActor != "identity_admin" || store.drainRequestID == "" {
		t.Fatalf("drain = %d, identity %#v, actor %q: %s", drain.Code, store.drainIdentity, store.drainActor, drain.Body.String())
	}

	controls := serveAdminRequest(handler, http.MethodGet, "/v1/admin/maintenance-controls", "")
	if controls.Code != http.StatusOK || !strings.Contains(controls.Body.String(), `"name":"service_creation"`) {
		t.Fatalf("maintenance controls = %d: %s", controls.Code, controls.Body.String())
	}
	set := serveAdminRequest(handler, http.MethodPut, "/v1/admin/maintenance-controls/service_creation", `{"allowed":false}`)
	if set.Code != http.StatusOK || store.setName != controlstate.MaintenanceControlServiceCreation ||
		store.setAllowed || store.setActor != "identity_admin" || store.setRequestID == "" {
		t.Fatalf("set maintenance control = %d, %q, %t: %s", set.Code, store.setName, store.setAllowed, set.Body.String())
	}
}

func TestAdminHandlersRejectNonAdministrators(t *testing.T) {
	store := &adminStoreStub{principal: controlstate.ControlPrincipal{IdentityID: "identity_user"}}
	handler := testHandler(t, Config{}, store, store, func(context.Context) error { return nil })
	response := serveAdminRequest(handler, http.MethodGet, "/v1/admin/status", "")
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
}

func TestAdminStatusRejectsNegativeCounters(t *testing.T) {
	for name, counts := range map[string]controlstate.AdminRuntimeCounts{
		"enabled_services":      {EnabledServices: -1},
		"suspended_services":    {SuspendedServices: -1},
		"starting_service_runs": {StartingServiceRuns: -1},
		"ready_service_runs":    {ReadyServiceRuns: -1},
		"ingress_leases":        {IngressLeases: -1},
		"relay_leases":          {RelayLeases: -1},
	} {
		t.Run(name, func(t *testing.T) {
			store := &adminStoreStub{
				principal: controlstate.ControlPrincipal{IdentityID: "identity_admin", Administrator: true},
				counts:    counts,
			}
			handler := testHandler(t, Config{}, store, store, func(context.Context) error { return nil })
			response := serveAdminRequest(handler, http.MethodGet, "/v1/admin/status", "")
			if response.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d: %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestAdminMaintenanceGateProblemsRemainUnavailable(t *testing.T) {
	for _, gate := range []error{
		controlstate.ErrServiceCreationGated, controlstate.ErrServiceRunCreationGated, controlstate.ErrCertificateIssuanceGated,
	} {
		t.Run(gate.Error(), func(t *testing.T) {
			response := httptest.NewRecorder()
			serviceVisitorError(t.Context(), response, "admit service work", fmt.Errorf("admit: %w", gate))
			var body controlv1.Problem
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if response.Code != http.StatusServiceUnavailable || body.Code != controlv1.Unavailable ||
				body.Title != "operation is disabled" {
				t.Fatalf("maintenance problem = %d: %s", response.Code, response.Body.String())
			}
		})
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
	AdminStore
	AuthorizationStore
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

func (s *adminStoreStub) AuthenticateAccessToken(context.Context, credentials.AccessToken, time.Time) (controlstate.ControlPrincipal, error) {
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
