package api

import (
	"errors"
	"net/http"
	"strings"

	adminservice "github.com/tnldotdev/tnl/internal/admin"
	"github.com/tnldotdev/tnl/internal/auth"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/routes"
	"github.com/tnldotdev/tnl/pkg/protocol/serverv1"
)

func adminPathParts(path string) ([]string, bool) {
	remainder, ok := strings.CutPrefix(path, "/v1/admin/")
	if !ok || remainder == "" || strings.HasSuffix(remainder, "/") {
		return nil, false
	}
	parts := strings.Split(remainder, "/")
	if len(parts) > 3 {
		return nil, false
	}
	for _, part := range parts {
		if part == "" {
			return nil, false
		}
	}
	return parts, true
}

func (h *handler) serveAdminEndpoint(
	w http.ResponseWriter,
	r *http.Request,
	requestID string,
	serve func(auth.Principal),
) {
	principal, ok := h.authenticateAdmin(w, r, requestID)
	if !ok {
		return
	}
	if h.admin == nil {
		writeUnsupported(w, requestID)
		return
	}

	serve(principal)
}

func (h *handler) authenticateAdmin(
	w http.ResponseWriter,
	r *http.Request,
	requestID string,
) (auth.Principal, bool) {
	principal, ok := h.authenticatePrincipal(w, r, requestID)
	if !ok {
		return auth.Principal{}, false
	}
	if !principal.HasGrant(auth.GrantAdmin) {
		writeProblem(w, requestID, http.StatusForbidden, serverv1.PermissionDenied, "Permission denied", "permission-denied")
		return auth.Principal{}, false
	}
	return principal, true
}

func (h *handler) serveAdminStatus(w http.ResponseWriter, r *http.Request, requestID string, _ auth.Principal) {
	status, err := h.admin.Status(r.Context())
	if err != nil {
		writeAdminError(w, requestID, err)
		return
	}
	writeModel(w, requestID, http.StatusOK, serverv1.AdminServerStatus{
		Mode: serverv1.AdminServerStatusMode(status.Mode), StartedAt: status.StartedAt,
		CurrentTime: status.CurrentTime, EnabledRoutes: int(status.EnabledRoutes),
		SuspendedRoutes: int(status.SuspendedRoutes), ProvisioningRoutes: status.Provisioning,
		ConnectedWorkers: status.ConnectedWorkers,
	})
}

func (h *handler) serveAdminRoutesList(
	w http.ResponseWriter,
	r *http.Request,
	requestID string,
	_ auth.Principal,
) {
	cursor, ok := adminCursor(r, validRouteID)
	if !ok {
		writeInvalidRequest(w, requestID)
		return
	}
	values, next, err := h.admin.ListRoutes(r.Context(), cursor)
	if err != nil {
		writeAdminError(w, requestID, err)
		return
	}
	response := serverv1.AdminRoutePage{Routes: make([]serverv1.AdminRoute, 0, len(values))}
	for _, value := range values {
		response.Routes = append(response.Routes, adminRouteResponse(value))
	}
	if next != "" {
		value := serverv1.RouteID(next)
		response.NextCursor = &value
	}
	writeModel(w, requestID, http.StatusOK, response)
}

func (h *handler) serveAdminRoute(
	w http.ResponseWriter,
	r *http.Request,
	requestID string,
	_ auth.Principal,
	routeID string,
) {
	value, err := h.admin.Route(r.Context(), routeID)
	if err != nil {
		writeAdminError(w, requestID, err)
		return
	}
	writeModel(w, requestID, http.StatusOK, adminRouteResponse(value))
}

func (h *handler) serveAdminRouteSuspend(
	w http.ResponseWriter,
	r *http.Request,
	requestID string,
	principal auth.Principal,
	routeID string,
) {
	var request serverv1.SuspendAdminRouteRequest
	if !decodeRequest(w, r, requestID, &request) {
		return
	}
	if request.Revision <= 0 || !validAdminReason(request.Reason) {
		writeInvalidRequest(w, requestID)
		return
	}
	value, err := h.admin.SuspendRoute(
		r.Context(), routeID, uint64(request.Revision), request.Reason, principal.Identity.ID, requestID,
	)
	if err != nil {
		writeAdminError(w, requestID, err)
		return
	}
	writeModel(w, requestID, http.StatusOK, adminRouteResponse(value))
}

func (h *handler) serveAdminRouteResume(
	w http.ResponseWriter,
	r *http.Request,
	requestID string,
	principal auth.Principal,
	routeID string,
) {
	var request serverv1.ResumeAdminRouteRequest
	if !decodeRequest(w, r, requestID, &request) {
		return
	}
	if request.Revision <= 0 {
		writeInvalidRequest(w, requestID)
		return
	}
	value, err := h.admin.ResumeRoute(
		r.Context(), routeID, uint64(request.Revision), principal.Identity.ID, requestID,
	)
	if err != nil {
		writeAdminError(w, requestID, err)
		return
	}
	writeModel(w, requestID, http.StatusOK, adminRouteResponse(value))
}

func (h *handler) serveAdminHostnamesList(
	w http.ResponseWriter,
	r *http.Request,
	requestID string,
	_ auth.Principal,
) {
	cursor, ok := adminCursor(r, validHostnameID)
	if !ok {
		writeInvalidRequest(w, requestID)
		return
	}
	values, next, err := h.admin.ListHostnames(r.Context(), cursor)
	if err != nil {
		writeAdminError(w, requestID, err)
		return
	}
	response := serverv1.AdminHostnamePage{Hostnames: make([]serverv1.AdminHostname, 0, len(values))}
	for _, value := range values {
		response.Hostnames = append(response.Hostnames, adminHostnameResponse(value))
	}
	if next != "" {
		value := serverv1.HostnameID(next)
		response.NextCursor = &value
	}
	writeModel(w, requestID, http.StatusOK, response)
}

func (h *handler) serveAdminHostname(
	w http.ResponseWriter,
	r *http.Request,
	requestID string,
	_ auth.Principal,
	hostnameID string,
) {
	value, err := h.admin.Hostname(r.Context(), hostnameID)
	if err != nil {
		writeAdminError(w, requestID, err)
		return
	}
	writeModel(w, requestID, http.StatusOK, adminHostnameResponse(value))
}

func (h *handler) serveAdminHostnameRemove(
	w http.ResponseWriter,
	r *http.Request,
	requestID string,
	principal auth.Principal,
	hostnameID string,
) {
	if err := h.admin.RemoveHostname(r.Context(), hostnameID, principal.Identity.ID, requestID); err != nil {
		writeAdminError(w, requestID, err)
		return
	}
	writeNoContent(w)
}

func (h *handler) serveAdminHostnameQuarantine(
	w http.ResponseWriter,
	r *http.Request,
	requestID string,
	principal auth.Principal,
	hostnameID string,
) {
	var request serverv1.AdminReasonRequest
	if !decodeRequest(w, r, requestID, &request) {
		return
	}
	if !validAdminReason(request.Reason) {
		writeInvalidRequest(w, requestID)
		return
	}
	if err := h.admin.QuarantineHostname(
		r.Context(), hostnameID, request.Reason, principal.Identity.ID, requestID,
	); err != nil {
		writeAdminError(w, requestID, err)
		return
	}
	writeNoContent(w)
}

func (h *handler) serveAdminCredentialsList(
	w http.ResponseWriter,
	r *http.Request,
	requestID string,
	_ auth.Principal,
) {
	cursor, ok := adminCursor(r, validCredentialID)
	if !ok {
		writeInvalidRequest(w, requestID)
		return
	}
	values, next, err := h.admin.ListCredentials(r.Context(), cursor)
	if err != nil {
		writeAdminError(w, requestID, err)
		return
	}
	response := serverv1.AdminCredentialPage{Credentials: make([]serverv1.AdminCredential, 0, len(values))}
	for _, value := range values {
		item := serverv1.AdminCredential{
			Id: serverv1.CredentialID(value.ID), RouteId: serverv1.RouteID(value.RouteID), CreatedAt: value.CreatedAt,
		}
		if !value.RevokedAt.IsZero() {
			item.RevokedAt = &value.RevokedAt
		}
		response.Credentials = append(response.Credentials, item)
	}
	if next != "" {
		value := serverv1.CredentialID(next)
		response.NextCursor = &value
	}
	writeModel(w, requestID, http.StatusOK, response)
}

func (h *handler) serveAdminCredentialRevoke(
	w http.ResponseWriter,
	r *http.Request,
	requestID string,
	principal auth.Principal,
	credentialID string,
) {
	if err := h.admin.RevokeCredential(r.Context(), credentialID, principal.Identity.ID, requestID); err != nil {
		writeAdminError(w, requestID, err)
		return
	}
	writeNoContent(w)
}

func (h *handler) serveAdminControlSessionsList(
	w http.ResponseWriter,
	r *http.Request,
	requestID string,
	_ auth.Principal,
) {
	cursor, ok := adminCursor(r, validControlSessionID)
	if !ok {
		writeInvalidRequest(w, requestID)
		return
	}
	values, next, err := h.admin.ListControlSessions(r.Context(), cursor)
	if err != nil {
		writeAdminError(w, requestID, err)
		return
	}
	response := serverv1.AdminControlSessionPage{ControlSessions: make([]serverv1.AdminControlSession, 0, len(values))}
	for _, value := range values {
		grants := make([]serverv1.Grant, len(value.Grants))
		for index, grant := range value.Grants {
			grants[index] = serverv1.Grant(grant)
		}
		item := serverv1.AdminControlSession{
			Id: serverv1.ControlSessionID(value.ID), IdentityId: value.IdentityID,
			AuthenticationMethod: value.AuthenticationMethod, Grants: grants, CreatedAt: value.CreatedAt,
			AccessExpiresAt: value.AccessExpiresAt, RefreshExpiresAt: value.RefreshExpiresAt,
		}
		if !value.RevokedAt.IsZero() {
			item.RevokedAt = &value.RevokedAt
		}
		response.ControlSessions = append(response.ControlSessions, item)
	}
	if next != "" {
		value := serverv1.ControlSessionID(next)
		response.NextCursor = &value
	}
	writeModel(w, requestID, http.StatusOK, response)
}

func (h *handler) serveAdminControlSessionRevoke(
	w http.ResponseWriter,
	r *http.Request,
	requestID string,
	principal auth.Principal,
	controlSessionID string,
) {
	if err := h.admin.RevokeControlSession(r.Context(), controlSessionID, principal.Identity.ID, requestID); err != nil {
		writeAdminError(w, requestID, err)
		return
	}
	writeNoContent(w)
}

func (h *handler) serveAdminMaintenanceControlsList(
	w http.ResponseWriter,
	r *http.Request,
	requestID string,
	_ auth.Principal,
) {
	values, err := h.admin.ListMaintenanceControls(r.Context())
	if err != nil {
		writeAdminError(w, requestID, err)
		return
	}
	response := make([]serverv1.AdminMaintenanceControl, 0, len(values))
	for _, value := range values {
		response = append(response, adminMaintenanceControlResponse(value))
	}
	writeModel(w, requestID, http.StatusOK, response)
}

func (h *handler) serveAdminMaintenanceControlSet(
	w http.ResponseWriter,
	r *http.Request,
	requestID string,
	principal auth.Principal,
	name string,
) {
	var request serverv1.SetAdminMaintenanceControlRequest
	if !decodeRequest(w, r, requestID, &request) {
		return
	}
	value, err := h.admin.SetMaintenanceControl(
		r.Context(), adminservice.MaintenanceControlName(name), request.Enabled, principal.Identity.ID, requestID,
	)
	if err != nil {
		writeAdminError(w, requestID, err)
		return
	}
	writeModel(w, requestID, http.StatusOK, adminMaintenanceControlResponse(value))
}

func (h *handler) requireMaintenanceControl(
	w http.ResponseWriter,
	r *http.Request,
	requestID string,
	name adminservice.MaintenanceControlName,
) bool {
	if h.admin == nil {
		return true
	}
	err := h.admin.RequireEnabled(r.Context(), name)
	if errors.Is(err, adminservice.ErrMaintenanceControlDisabled) {
		writeProblem(
			w, requestID, http.StatusServiceUnavailable, serverv1.TemporarilyUnavailable,
			"Maintenance control disabled", "maintenance-control-disabled",
		)
		return false
	}
	if err != nil {
		writeInternalError(w, requestID, err)
		return false
	}
	return true
}

func adminRouteResponse(route routes.Route) serverv1.AdminRoute {
	result := serverv1.AdminRoute{
		Id: serverv1.RouteID(route.ID), Hostname: route.Hostname, LocalTarget: route.LocalTarget,
		Status: serverv1.AdminRouteStatus(route.Status), RouteVersion: int(route.RouteVersion),
		SuspensionRevision: int(route.SuspensionRevision), CreatedAt: route.CreatedAt,
	}
	if route.IdentityID != "" {
		result.IdentityId = &route.IdentityID
	}
	if route.SuspensionReason != "" {
		result.SuspensionReason = &route.SuspensionReason
	}
	if !route.SuspendedAt.IsZero() {
		result.SuspendedAt = &route.SuspendedAt
	}
	if !route.DeletedAt.IsZero() {
		result.DeletedAt = &route.DeletedAt
	}
	return result
}

func adminHostnameResponse(hostname routes.Hostname) serverv1.AdminHostname {
	result := serverv1.AdminHostname{
		Id: serverv1.HostnameID(hostname.ID), Hostname: hostname.Hostname,
		Kind: serverv1.AdminHostnameKind(hostname.Kind), Status: serverv1.AdminHostnameStatus(hostname.Status),
		Source: string(hostname.Source), CreatedAt: hostname.CreatedAt,
	}
	if hostname.IdentityID != "" {
		result.IdentityId = &hostname.IdentityID
	}
	if !hostname.ActivatedAt.IsZero() {
		result.ActivatedAt = &hostname.ActivatedAt
	}
	if !hostname.DeactivatedAt.IsZero() {
		result.DeactivatedAt = &hostname.DeactivatedAt
	}
	if hostname.QuarantineReason != "" {
		result.QuarantineReason = &hostname.QuarantineReason
	}
	if !hostname.QuarantinedAt.IsZero() {
		result.QuarantinedAt = &hostname.QuarantinedAt
	}
	return result
}

func adminMaintenanceControlResponse(value adminservice.MaintenanceControl) serverv1.AdminMaintenanceControl {
	return serverv1.AdminMaintenanceControl{
		Name: serverv1.MaintenanceControlName(value.Name), Enabled: value.Enabled,
		Revision: int(value.Revision), UpdatedAt: value.UpdatedAt, UpdatedBy: value.UpdatedBy,
	}
}

func adminCursor(r *http.Request, valid func(string) bool) (string, bool) {
	query := r.URL.Query()
	if len(query) == 0 {
		return "", true
	}
	values, ok := query["cursor"]
	if !ok || len(query) != 1 || len(values) != 1 || !valid(values[0]) {
		return "", false
	}
	return values[0], true
}

func validAdminReason(value string) bool {
	return value != "" && len(value) <= 256 && strings.TrimSpace(value) == value
}

func validRouteID(value string) bool {
	return opaqueid.Valid(value, "route_")
}

func validControlSessionID(value string) bool {
	return opaqueid.Valid(value, "control_session_")
}

func validCredentialID(value string) bool {
	_, err := credentials.ParseCredentialID(value)
	return err == nil
}

func validAdminMaintenanceControl(value string) bool {
	name := adminservice.MaintenanceControlName(value)
	return name == adminservice.MaintenanceControlRouteCreation ||
		name == adminservice.MaintenanceControlRouteSessionCreation ||
		name == adminservice.MaintenanceControlCertificateIssuance
}

func writeUnsupported(w http.ResponseWriter, requestID string) {
	writeProblem(w, requestID, http.StatusNotImplemented, serverv1.Unsupported, "Unsupported", "unsupported")
}

func writeAdminError(w http.ResponseWriter, requestID string, err error) {
	switch {
	case errors.Is(err, routes.ErrNotFound), errors.Is(err, adminservice.ErrNotFound):
		writeNotFound(w, requestID)
	case errors.Is(err, routes.ErrInvalidArgument), errors.Is(err, adminservice.ErrInvalidArgument):
		writeInvalidRequest(w, requestID)
	case errors.Is(err, routes.ErrInvalidStatus), errors.Is(err, adminservice.ErrStatusConflict):
		writeProblem(w, requestID, http.StatusConflict, serverv1.StatusConflict, "Status conflict", "status-conflict")
	default:
		writeInternalError(w, requestID, err)
	}
}
