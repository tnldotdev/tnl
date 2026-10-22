package public

import (
	"context"
	"errors"
	"net/http"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/policy/httpsubject"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type serviceHTTPStore interface {
	ServiceHTTPBrowserTeam(context.Context, httpsubject.Subject, time.Time) (string, error)
	BeginServiceBrowserLogin(context.Context, httpsubject.Subject, string, string, string, []byte, *controlstate.CompanyLoginIntent, time.Time) (string, error)
	AuthorizeServiceHTTPVisitor(context.Context, controlstate.ServiceHTTPRun, controlv1.ServiceHTTPVisitorRequest, time.Time) (controlstate.ServiceVisitorValidity, error)
	RedeemServiceBrowserHandoff(context.Context, controlstate.ServiceHTTPRun, string, time.Time) (controlv1.BrowserHandoffResponse, error)
	ServiceBrowserSession(context.Context, controlstate.ServiceHTTPRun, string, bool, time.Time) (controlstate.VisitorPermission, error)
	CreateServiceHTTPGrant(context.Context, string, string, controlv1.CreateServiceHTTPGrantRequest, time.Time) (controlv1.ServiceHTTPGrant, error)
	RevokeServiceHTTPGrant(context.Context, string, string, string, time.Time) error
}

func (h *handler) serviceHTTP(w http.ResponseWriter, r *http.Request) (serviceHTTPStore, string, bool) {
	w.Header().Set("Cache-Control", "no-store")
	token, ok := requestBearerToken(r)
	if !ok {
		writeBearerProblem(w)
		return nil, "", false
	}
	store, ok := h.store.(serviceHTTPStore)
	if !ok {
		writeProblem(w, 503, controlv1.Unavailable, "service HTTP authorization is unavailable")
	}
	return store, token, ok
}

func serviceHTTPRun(service, run, token string, number int64) controlstate.ServiceHTTPRun {
	return controlstate.ServiceHTTPRun{Subject: httpsubject.Subject{Kind: httpsubject.Service, ID: service}, RunID: run, Number: number, Token: credentials.ServiceRunToken(token)}
}

func (h *handler) AuthorizeServiceHTTPVisitor(w http.ResponseWriter, r *http.Request, service controlv1.ServiceID, run controlv1.ServiceRunID) {
	store, token, ok := h.serviceHTTP(w, r)
	if !ok {
		return
	}
	var body controlv1.ServiceHTTPVisitorRequest
	if decodeJSONLimited(w, r, &body, 32<<10) != nil || body.RunNumber < 1 || !validVisitorSource(body.SourceIp) {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid service HTTP decision")
		return
	}
	result, err := store.AuthorizeServiceHTTPVisitor(r.Context(), serviceHTTPRun(service, run, token, body.RunNumber), body, time.Now())
	if err != nil {
		writeManagedCertificateProblem(w, "authorize service HTTP visitor", err)
		return
	}
	observability.AuthorizationAdmission(r.Context(), "service_http_visitor", result.Allowed, result.Admitted)
	writeJSON(w, 200, controlv1.ServiceClientCertificateDecision{Allowed: result.Allowed, Admitted: result.Admitted, ValidUntil: result.ValidUntil})
}

func (h *handler) RedeemServiceBrowserHandoff(w http.ResponseWriter, r *http.Request, service controlv1.ServiceID, run controlv1.ServiceRunID) {
	store, token, ok := h.serviceHTTP(w, r)
	if !ok {
		return
	}
	var body controlv1.ServiceBrowserRequest
	if decodeJSONLimited(w, r, &body, 4096) != nil || body.RunNumber < 1 {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid managed browser handoff")
		return
	}
	result, err := store.RedeemServiceBrowserHandoff(r.Context(), serviceHTTPRun(service, run, token, body.RunNumber), body.Secret, time.Now())
	if err != nil {
		writeServiceHTTPBrowserProblem(w, err)
		return
	}
	writeJSON(w, 200, result)
}

func writeServiceHTTPBrowserProblem(w http.ResponseWriter, err error) {
	if errors.Is(err, controlstate.ErrVisitorSignIn) || errors.Is(err, controlstate.ErrPreviewAccess) {
		writeBearerProblem(w)
		return
	}
	writeManagedCertificateProblem(w, "authorize managed browser", err)
}

func (h *handler) CheckServiceBrowserSession(w http.ResponseWriter, r *http.Request, service controlv1.ServiceID, run controlv1.ServiceRunID) {
	h.serviceBrowserSession(w, r, service, run, false)
}
func (h *handler) RevokeServiceBrowserSession(w http.ResponseWriter, r *http.Request, service controlv1.ServiceID, run controlv1.ServiceRunID) {
	h.serviceBrowserSession(w, r, service, run, true)
}
func (h *handler) serviceBrowserSession(w http.ResponseWriter, r *http.Request, service, run string, revoke bool) {
	store, token, ok := h.serviceHTTP(w, r)
	if !ok {
		return
	}
	var body controlv1.ServiceBrowserRequest
	if decodeJSONLimited(w, r, &body, 4096) != nil || body.RunNumber < 1 {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid managed browser session")
		return
	}
	result, err := store.ServiceBrowserSession(r.Context(), serviceHTTPRun(service, run, token, body.RunNumber), body.Secret, revoke, time.Now())
	if err != nil {
		writeServiceHTTPBrowserProblem(w, err)
		return
	}
	if revoke {
		w.WriteHeader(204)
		return
	}
	observability.AuthorizationDecision(r.Context(), "service_browser_session", result.VisitAllowed)
	writeJSON(w, 200, controlv1.BrowserAccessResponse{IdentityId: result.IdentityID, DisplayName: result.DisplayName, VisitAllowed: result.VisitAllowed, TeamMember: result.TeamMember})
}

func (h *handler) CreateServiceHTTPGrant(w http.ResponseWriter, r *http.Request, service controlv1.ServiceID) {
	store, _, ok := h.serviceHTTP(w, r)
	if !ok {
		return
	}
	actor, ok := h.authorizeRouteReads(w, r)
	if !ok {
		return
	}
	var body controlv1.CreateServiceHTTPGrantRequest
	if decodeJSONLimited(w, r, &body, 4096) != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid service HTTP grant")
		return
	}
	result, err := store.CreateServiceHTTPGrant(r.Context(), service, actor.identityID, body, time.Now())
	if err != nil {
		writeManagedCertificateProblem(w, "create service HTTP grant", err)
		return
	}
	writeJSON(w, 201, result)
}

func (h *handler) RevokeServiceHTTPGrant(w http.ResponseWriter, r *http.Request, service controlv1.ServiceID, grant string) {
	store, _, ok := h.serviceHTTP(w, r)
	if !ok {
		return
	}
	actor, ok := h.authorizeRouteReads(w, r)
	if !ok {
		return
	}
	if err := store.RevokeServiceHTTPGrant(r.Context(), service, actor.identityID, grant, time.Now()); err != nil {
		writeManagedCertificateProblem(w, "revoke service HTTP grant", err)
		return
	}
	w.WriteHeader(204)
}

func (h *handler) ListServiceHTTPGrants(w http.ResponseWriter, r *http.Request, service controlv1.ServiceID) {
	w.Header().Set("Cache-Control", "no-store")
	actor, ok := h.authorizeRouteReads(w, r)
	if !ok {
		return
	}
	store, ok := h.store.(interface {
		ListServiceHTTPGrants(context.Context, string, string, time.Time) ([]controlv1.ServiceHTTPGrantSummary, error)
	})
	if !ok {
		writeProblem(w, 503, controlv1.Unavailable, "service HTTP grants are unavailable")
		return
	}
	result, err := store.ListServiceHTTPGrants(r.Context(), service, actor.identityID, time.Now())
	if err != nil {
		privateVisitorError(w, "list service HTTP grants", err)
		return
	}
	writeJSON(w, 200, result)
}
