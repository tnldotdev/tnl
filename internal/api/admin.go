package api

import (
	"errors"
	"net/http"
	"strings"

	coreadmin "github.com/tnldotdev/tnl/internal/admin"
	"github.com/tnldotdev/tnl/internal/auth"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/routes"
	"github.com/tnldotdev/tnl/pkg/protocol/serverv1"
)

func adminOperationForRequest(method, path string) Operation {
	parts, ok := adminPathParts(path)
	if !ok {
		return OperationUnknown
	}
	switch {
	case len(parts) == 1 && parts[0] == "status" && method == http.MethodGet:
		return OperationAdminServerStatus
	case len(parts) == 1 && parts[0] == "routes" && method == http.MethodGet:
		return OperationAdminRoutesList
	case len(parts) == 2 && parts[0] == "routes" && method == http.MethodGet:
		return OperationAdminRouteShow
	case len(parts) == 3 && parts[0] == "routes" && parts[2] == "suspend" && method == http.MethodPost:
		return OperationAdminRouteSuspend
	case len(parts) == 3 && parts[0] == "routes" && parts[2] == "resume" && method == http.MethodPost:
		return OperationAdminRouteResume
	case len(parts) == 1 && parts[0] == "hostnames" && method == http.MethodGet:
		return OperationAdminHostnamesList
	case len(parts) == 2 && parts[0] == "hostnames" && method == http.MethodGet:
		return OperationAdminHostnameShow
	case len(parts) == 2 && parts[0] == "hostnames" && method == http.MethodDelete:
		return OperationAdminHostnameRemove
	case len(parts) == 3 && parts[0] == "hostnames" && parts[2] == "quarantine" && method == http.MethodPost:
		return OperationAdminHostnameQuarantine
	case len(parts) == 1 && parts[0] == "credentials" && method == http.MethodGet:
		return OperationAdminCredentialsList
	case len(parts) == 2 && parts[0] == "credentials" && method == http.MethodDelete:
		return OperationAdminCredentialRevoke
	case len(parts) == 1 && parts[0] == "control-sessions" && method == http.MethodGet:
		return OperationAdminControlSessionsList
	case len(parts) == 2 && parts[0] == "control-sessions" && method == http.MethodDelete:
		return OperationAdminControlSessionRevoke
	case len(parts) == 1 && parts[0] == "switches" && method == http.MethodGet:
		return OperationAdminSwitchesList
	case len(parts) == 2 && parts[0] == "switches" && method == http.MethodPut:
		return OperationAdminSwitchSet
	default:
		return OperationUnknown
	}
}

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

func (h *handler) serveAdmin(w http.ResponseWriter, r *http.Request, requestID string) {
	parts, ok := adminPathParts(r.URL.Path)
	if !ok {
		writeNotFound(w, requestID)
		return
	}
	principal, ok := h.authenticateAdmin(w, r, requestID)
	if !ok {
		return
	}
	if h.admin == nil {
		writeUnsupported(w, requestID)
		return
	}

	switch parts[0] {
	case "status":
		if len(parts) != 1 || r.Method != http.MethodGet {
			writeMethodOrNotFound(w, r.Method, requestID, len(parts) == 1, http.MethodGet)
			return
		}
		h.serveAdminStatus(w, r, requestID)
	case "routes":
		h.serveAdminRoutes(w, r, requestID, principal, parts[1:])
	case "hostnames":
		h.serveAdminHostnames(w, r, requestID, principal, parts[1:])
	case "credentials":
		h.serveAdminCredentials(w, r, requestID, principal, parts[1:])
	case "control-sessions":
		h.serveAdminControlSessions(w, r, requestID, principal, parts[1:])
	case "switches":
		h.serveAdminSwitches(w, r, requestID, principal, parts[1:])
	default:
		writeNotFound(w, requestID)
	}
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

func (h *handler) serveAdminStatus(w http.ResponseWriter, r *http.Request, requestID string) {
	status, err := h.admin.Status(r.Context())
	if err != nil {
		writeAdminError(w, requestID, err)
		return
	}
	writeModel(w, requestID, http.StatusOK, serverv1.AdminServerStatus{
		Mode: serverv1.AdminServerStatusMode(status.Mode), StartedAt: status.StartedAt,
		CurrentTime: status.CurrentTime, ActiveRoutes: int(status.ActiveRoutes),
		SuspendedRoutes: int(status.SuspendedRoutes), ProvisioningRoutes: status.Provisioning,
		ConnectedWorkers: status.ConnectedWorkers,
	})
}

func (h *handler) serveAdminRoutes(
	w http.ResponseWriter,
	r *http.Request,
	requestID string,
	principal auth.Principal,
	parts []string,
) {
	if len(parts) == 0 {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, requestID, http.MethodGet)
			return
		}
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
		return
	}
	if !validRouteID(parts[0]) {
		writeNotFound(w, requestID)
		return
	}
	if len(parts) == 1 {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, requestID, http.MethodGet)
			return
		}
		value, err := h.admin.Route(r.Context(), parts[0])
		if err != nil {
			writeAdminError(w, requestID, err)
			return
		}
		writeModel(w, requestID, http.StatusOK, adminRouteResponse(value))
		return
	}
	if len(parts) != 2 || (parts[1] != "suspend" && parts[1] != "resume") {
		writeNotFound(w, requestID)
		return
	}
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, requestID, http.MethodPost)
		return
	}
	var value routes.Route
	var err error
	if parts[1] == "suspend" {
		var request serverv1.SuspendAdminRouteRequest
		if !decodeRequest(w, r, requestID, &request) {
			return
		}
		if request.Revision <= 0 || !validAdminReason(request.Reason) {
			writeInvalidRequest(w, requestID)
			return
		}
		value, err = h.admin.SuspendRoute(
			r.Context(), parts[0], uint64(request.Revision), request.Reason, principal.Identity.ID, requestID,
		)
	} else {
		var request serverv1.ResumeAdminRouteRequest
		if !decodeRequest(w, r, requestID, &request) {
			return
		}
		if request.Revision <= 0 {
			writeInvalidRequest(w, requestID)
			return
		}
		value, err = h.admin.ResumeRoute(r.Context(), parts[0], uint64(request.Revision), principal.Identity.ID, requestID)
	}
	if err != nil {
		writeAdminError(w, requestID, err)
		return
	}
	writeModel(w, requestID, http.StatusOK, adminRouteResponse(value))
}

func (h *handler) serveAdminHostnames(
	w http.ResponseWriter,
	r *http.Request,
	requestID string,
	principal auth.Principal,
	parts []string,
) {
	if len(parts) == 0 {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, requestID, http.MethodGet)
			return
		}
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
		return
	}
	if !validHostnameID(parts[0]) {
		writeNotFound(w, requestID)
		return
	}
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			value, err := h.admin.Hostname(r.Context(), parts[0])
			if err != nil {
				writeAdminError(w, requestID, err)
				return
			}
			writeModel(w, requestID, http.StatusOK, adminHostnameResponse(value))
		case http.MethodDelete:
			if err := h.admin.RemoveHostname(r.Context(), parts[0], principal.Identity.ID, requestID); err != nil {
				writeAdminError(w, requestID, err)
				return
			}
			writeNoContent(w)
		default:
			writeMethodNotAllowed(w, requestID, http.MethodGet+", "+http.MethodDelete)
		}
		return
	}
	if len(parts) != 2 || parts[1] != "quarantine" {
		writeNotFound(w, requestID)
		return
	}
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, requestID, http.MethodPost)
		return
	}
	var request serverv1.AdminReasonRequest
	if !decodeRequest(w, r, requestID, &request) {
		return
	}
	if !validAdminReason(request.Reason) {
		writeInvalidRequest(w, requestID)
		return
	}
	if err := h.admin.QuarantineHostname(
		r.Context(), parts[0], request.Reason, principal.Identity.ID, requestID,
	); err != nil {
		writeAdminError(w, requestID, err)
		return
	}
	writeNoContent(w)
}

func (h *handler) serveAdminCredentials(
	w http.ResponseWriter,
	r *http.Request,
	requestID string,
	principal auth.Principal,
	parts []string,
) {
	if len(parts) == 0 {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, requestID, http.MethodGet)
			return
		}
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
		return
	}
	if len(parts) != 1 || !validCredentialID(parts[0]) {
		writeNotFound(w, requestID)
		return
	}
	if r.Method != http.MethodDelete {
		writeMethodNotAllowed(w, requestID, http.MethodDelete)
		return
	}
	if err := h.admin.RevokeCredential(r.Context(), parts[0], principal.Identity.ID, requestID); err != nil {
		writeAdminError(w, requestID, err)
		return
	}
	writeNoContent(w)
}

func (h *handler) serveAdminControlSessions(
	w http.ResponseWriter,
	r *http.Request,
	requestID string,
	principal auth.Principal,
	parts []string,
) {
	if len(parts) == 0 {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, requestID, http.MethodGet)
			return
		}
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
		return
	}
	if len(parts) != 1 || !validControlSessionID(parts[0]) {
		writeNotFound(w, requestID)
		return
	}
	if r.Method != http.MethodDelete {
		writeMethodNotAllowed(w, requestID, http.MethodDelete)
		return
	}
	if err := h.admin.RevokeControlSession(r.Context(), parts[0], principal.Identity.ID, requestID); err != nil {
		writeAdminError(w, requestID, err)
		return
	}
	writeNoContent(w)
}

func (h *handler) serveAdminSwitches(
	w http.ResponseWriter,
	r *http.Request,
	requestID string,
	principal auth.Principal,
	parts []string,
) {
	if len(parts) == 0 {
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, requestID, http.MethodGet)
			return
		}
		values, err := h.admin.Switches(r.Context())
		if err != nil {
			writeAdminError(w, requestID, err)
			return
		}
		response := make([]serverv1.AdminOperationalSwitch, 0, len(values))
		for _, value := range values {
			response = append(response, adminSwitchResponse(value))
		}
		writeModel(w, requestID, http.StatusOK, response)
		return
	}
	if len(parts) != 1 || !validAdminSwitch(parts[0]) {
		writeNotFound(w, requestID)
		return
	}
	if r.Method != http.MethodPut {
		writeMethodNotAllowed(w, requestID, http.MethodPut)
		return
	}
	var request serverv1.SetAdminSwitchRequest
	if !decodeRequest(w, r, requestID, &request) {
		return
	}
	value, err := h.admin.SetSwitch(
		r.Context(), coreadmin.SwitchName(parts[0]), request.Enabled, principal.Identity.ID, requestID,
	)
	if err != nil {
		writeAdminError(w, requestID, err)
		return
	}
	writeModel(w, requestID, http.StatusOK, adminSwitchResponse(value))
}

func (h *handler) requireOperationalSwitch(
	w http.ResponseWriter,
	r *http.Request,
	requestID string,
	name coreadmin.SwitchName,
) bool {
	if h.admin == nil {
		return true
	}
	err := h.admin.RequireEnabled(r.Context(), name)
	if errors.Is(err, coreadmin.ErrOperationallyDisabled) {
		writeProblem(
			w, requestID, http.StatusServiceUnavailable, serverv1.TemporarilyUnavailable,
			"Operation disabled", "operation-disabled",
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
		Status: serverv1.AdminRouteStatus(route.Status), Version: int(route.Version),
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

func adminSwitchResponse(value coreadmin.OperationalSwitch) serverv1.AdminOperationalSwitch {
	return serverv1.AdminOperationalSwitch{
		Name: serverv1.OperationalSwitchName(value.Name), Enabled: value.Enabled,
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
	const prefix = "route_"
	return len(value) == len(prefix)+32 && strings.HasPrefix(value, prefix) && validLowerHex(value[len(prefix):])
}

func validControlSessionID(value string) bool {
	const prefix = "control_session_"
	return len(value) == len(prefix)+32 && strings.HasPrefix(value, prefix) && validLowerHex(value[len(prefix):])
}

func validLowerHex(value string) bool {
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return value != ""
}

func validCredentialID(value string) bool {
	_, err := credentials.ParseCredentialID(value)
	return err == nil
}

func validAdminSwitch(value string) bool {
	name := coreadmin.SwitchName(value)
	return name == coreadmin.SwitchNewRoutes || name == coreadmin.SwitchNewSessions || name == coreadmin.SwitchCertificateIssuance
}

func writeMethodOrNotFound(w http.ResponseWriter, method, requestID string, found bool, allowed string) {
	if !found {
		writeNotFound(w, requestID)
		return
	}
	if method != allowed {
		writeMethodNotAllowed(w, requestID, allowed)
	}
}

func writeUnsupported(w http.ResponseWriter, requestID string) {
	writeProblem(w, requestID, http.StatusNotImplemented, serverv1.Unsupported, "Unsupported", "unsupported")
}

func writeAdminError(w http.ResponseWriter, requestID string, err error) {
	switch {
	case errors.Is(err, routes.ErrNotFound), errors.Is(err, coreadmin.ErrNotFound):
		writeNotFound(w, requestID)
	case errors.Is(err, routes.ErrInvalidArgument), errors.Is(err, coreadmin.ErrInvalidArgument):
		writeInvalidRequest(w, requestID)
	case errors.Is(err, routes.ErrInvalidStatus), errors.Is(err, coreadmin.ErrStatusConflict):
		writeProblem(w, requestID, http.StatusConflict, serverv1.StatusConflict, "Status conflict", "status-conflict")
	default:
		writeInternalError(w, requestID, err)
	}
}
