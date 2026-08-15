package controlapi

import (
	"errors"
	"log"
	"math"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (h *handler) GetAdminServerStatus(response http.ResponseWriter, request *http.Request) {
	if _, ok := h.authorizeAdministrator(response, request); !ok {
		return
	}
	now := time.Now().UTC()
	if h.store == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "control unavailable")
		return
	}
	counts, err := h.store.AdminRuntimeCounts(request.Context(), now)
	if err != nil {
		log.Printf("read admin server status: %v", err)
		writeProblem(response, http.StatusInternalServerError, controlv1.Internal, "internal server error")
		return
	}
	values := []int64{
		counts.EnabledRoutes, counts.SuspendedRoutes, counts.StartingRouteSessions,
		counts.ReadyRouteSessions, counts.IngressLeases, counts.RelayLeases,
	}
	converted := make([]int, len(values))
	for index, value := range values {
		if value < 0 || uint64(value) > uint64(math.MaxInt) {
			writeProblem(response, http.StatusInternalServerError, controlv1.Internal, "internal server error")
			return
		}
		converted[index] = int(value)
	}
	writeJSON(response, http.StatusOK, controlv1.AdminServerStatus{
		Role: controlv1.AdminServerStatusRole(h.config.Role), StartedAt: h.config.StartedAt,
		CurrentTime: now, EnabledRoutes: converted[0], SuspendedRoutes: converted[1],
		StartingRouteSessions: converted[2], ReadyRouteSessions: converted[3],
		IngressLeases: converted[4], RelayLeases: converted[5],
	})
}

func (h *handler) ListAdminRelays(
	response http.ResponseWriter,
	request *http.Request,
	params controlv1.ListAdminRelaysParams,
) {
	if _, ok := h.authorizeAdministrator(response, request); !ok {
		return
	}
	if h.store == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "control unavailable")
		return
	}
	cursor := ""
	if params.Cursor != nil {
		cursor = *params.Cursor
	}
	page, err := h.store.ListAdminRelayLeases(request.Context(), cursor, time.Now().UTC())
	if err != nil {
		h.writeAdminStateError(response, "list admin relays", err)
		return
	}
	body := controlv1.AdminRelayPage{Relays: make([]controlv1.AdminRelayLease, len(page.Relays))}
	for index, lease := range page.Relays {
		body.Relays[index] = adminRelayLease(lease)
	}
	if page.NextCursor != "" {
		next := controlv1.RelayID(page.NextCursor)
		body.NextCursor = &next
	}
	writeJSON(response, http.StatusOK, body)
}

func (h *handler) DrainAdminRelay(response http.ResponseWriter, request *http.Request, relayID controlv1.RelayID) {
	principal, ok := h.authorizeAdministrator(response, request)
	if !ok {
		return
	}
	var body controlv1.AdminDrainRelayRequest
	if err := decodeJSON(response, request, &body); err != nil || body.RelayLeaseRevision < 1 {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid request")
		return
	}
	now := time.Now().UTC()
	if !body.Deadline.After(now) {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid request")
		return
	}
	if h.store == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "control unavailable")
		return
	}
	lease, err := h.store.BeginAdminRelayDrain(request.Context(), controlstate.RelayLeaseIdentity{
		RelayID: string(relayID), RelayRunID: body.RelayRunId,
		RelayLeaseRevision: uint64(body.RelayLeaseRevision),
	}, principal.identityID, newRequestID(), now, body.Deadline.UTC())
	if err != nil {
		h.writeAdminStateError(response, "drain admin relay", err)
		return
	}
	writeJSON(response, http.StatusOK, adminRelayLease(lease))
}

func (h *handler) ListMaintenanceControls(response http.ResponseWriter, request *http.Request) {
	if _, ok := h.authorizeAdministrator(response, request); !ok {
		return
	}
	if h.store == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "control unavailable")
		return
	}
	controls, err := h.store.ListMaintenanceControls(request.Context())
	if err != nil {
		h.writeAdminStateError(response, "list maintenance controls", err)
		return
	}
	body := make([]controlv1.MaintenanceControl, len(controls))
	for index, control := range controls {
		body[index] = maintenanceControl(control)
	}
	writeJSON(response, http.StatusOK, body)
}

func (h *handler) SetMaintenanceControl(
	response http.ResponseWriter,
	request *http.Request,
	name controlv1.MaintenanceControlName,
) {
	principal, ok := h.authorizeAdministrator(response, request)
	if !ok {
		return
	}
	var body controlv1.SetMaintenanceControlRequest
	if err := decodeJSON(response, request, &body); err != nil {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid request")
		return
	}
	if h.store == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "control unavailable")
		return
	}
	control, err := h.store.SetMaintenanceControl(
		request.Context(), controlstate.MaintenanceControlName(name), body.Allowed,
		principal.identityID, newRequestID(), time.Now().UTC(),
	)
	if err != nil {
		h.writeAdminStateError(response, "set maintenance control", err)
		return
	}
	writeJSON(response, http.StatusOK, maintenanceControl(control))
}

func (h *handler) authorizeAdministrator(
	response http.ResponseWriter,
	request *http.Request,
) (routeReadPrincipal, bool) {
	principal, ok := h.authorizeRouteReads(response, request)
	if !ok {
		return routeReadPrincipal{}, false
	}
	if !principal.administrator {
		writeProblem(response, http.StatusForbidden, controlv1.Forbidden, "operation is not authorized")
		return routeReadPrincipal{}, false
	}
	return principal, true
}

func (h *handler) writeAdminStateError(response http.ResponseWriter, operation string, err error) {
	switch {
	case errors.Is(err, controlstate.ErrAdminInvalid):
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid request")
	case errors.Is(err, controlstate.ErrMaintenanceControlNotFound):
		writeProblem(response, http.StatusNotFound, controlv1.NotFound, "resource not found")
	case errors.Is(err, controlstate.ErrRelayLeaseStale):
		writeProblem(response, http.StatusConflict, controlv1.Conflict, "relay lease is stale")
	default:
		log.Printf("%s: %v", operation, err)
		writeProblem(response, http.StatusInternalServerError, controlv1.Internal, "internal server error")
	}
}

func adminRelayLease(lease controlstate.RelayLease) controlv1.AdminRelayLease {
	result := controlv1.AdminRelayLease{
		RelayServiceId: lease.RelayServiceID, RelayId: lease.RelayID, RelayRunId: lease.RelayRunID,
		RelayLeaseRevision: int64(lease.RelayLeaseRevision), ProtocolVersion: int64(lease.ProtocolVersion),
		RelayAddress: lease.RelayAddress, TlsServerName: lease.TLSServerName,
		InternalRelayAddress: lease.InternalRelayAddress, ConnectionCapacity: int64(lease.ConnectionCapacity),
		StreamCapacity: int64(lease.StreamCapacity), ReportedConnections: int64(lease.ReportedConnections),
		ReportedStreams: int64(lease.ReportedStreams), Draining: lease.Draining,
		RenewedAt: lease.RenewedAt, LeaseExpiresAt: lease.LeaseExpiresAt,
	}
	if lease.DrainDeadline != nil {
		deadline := *lease.DrainDeadline
		result.DrainDeadline = &deadline
	}
	return result
}

func maintenanceControl(control controlstate.MaintenanceControl) controlv1.MaintenanceControl {
	return controlv1.MaintenanceControl{
		Name: controlv1.MaintenanceControlName(control.Name), Allowed: control.Allowed,
		Revision: int64(control.Revision), UpdatedAt: control.UpdatedAt, UpdatedBy: control.UpdatedBy,
	}
}
