package controlapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/policy/httpsubject"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type managedHTTPStore interface {
	ManagedHTTPBrowserTeam(context.Context, httpsubject.Subject, time.Time) (string, error)
	BeginManagedBrowserLogin(context.Context, httpsubject.Subject, string, string, string, []byte, *controlstate.CompanyLoginIntent, time.Time) (string, error)
	AuthorizeManagedHTTPVisitor(context.Context, controlstate.ManagedHTTPRun, controlv1.ManagedHTTPVisitorRequest, time.Time) (controlstate.PrivateVisitorValidity, error)
	RedeemManagedBrowserHandoff(context.Context, controlstate.ManagedHTTPRun, string, time.Time) (controlv1.BrowserHandoffResponse, error)
	ManagedBrowserSession(context.Context, controlstate.ManagedHTTPRun, string, bool, time.Time) (controlstate.VisitorPermission, error)
	CreateManagedHTTPGrant(context.Context, string, string, controlv1.CreateManagedHTTPGrantRequest, time.Time) (controlv1.ManagedHTTPGrant, error)
	RevokeManagedHTTPGrant(context.Context, string, string, string, time.Time) error
}

func (h *handler) managedHTTP(w http.ResponseWriter, r *http.Request) (managedHTTPStore, string, bool) {
	w.Header().Set("Cache-Control", "no-store")
	token, ok := requestBearerToken(r)
	if !ok {
		writeBearerProblem(w)
		return nil, "", false
	}
	store, ok := h.store.(managedHTTPStore)
	if !ok {
		writeProblem(w, 503, controlv1.Unavailable, "managed HTTP authorization is unavailable")
	}
	return store, token, ok
}

func managedHTTPRun(service, run, token string, number int64) controlstate.ManagedHTTPRun {
	return controlstate.ManagedHTTPRun{Subject: httpsubject.Subject{Kind: httpsubject.ManagedService, ID: service}, RunID: run, Number: number, Token: credentials.ManagedRunToken(token)}
}

func (h *handler) AuthorizeManagedHTTPVisitor(w http.ResponseWriter, r *http.Request, service controlv1.PrivateServiceID, run controlv1.PrivateRunID) {
	store, token, ok := h.managedHTTP(w, r)
	if !ok {
		return
	}
	var body controlv1.ManagedHTTPVisitorRequest
	if decodeJSONLimited(w, r, &body, 32<<10) != nil || body.RunNumber < 1 || !validVisitorSource(body.SourceIp) {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid managed HTTP decision")
		return
	}
	result, err := store.AuthorizeManagedHTTPVisitor(r.Context(), managedHTTPRun(service, run, token, body.RunNumber), body, time.Now())
	if err != nil {
		writeManagedCertificateProblem(w, "authorize managed HTTP visitor", err)
		return
	}
	observability.AuthorizationAdmission(r.Context(), "managed_http_visitor", result.Allowed, result.Admitted)
	writeJSON(w, 200, controlv1.ServiceClientCertificateDecision{Allowed: result.Allowed, Admitted: result.Admitted, ValidUntil: result.ValidUntil})
}

func (h *handler) RedeemManagedBrowserHandoff(w http.ResponseWriter, r *http.Request, service controlv1.PrivateServiceID, run controlv1.PrivateRunID) {
	store, token, ok := h.managedHTTP(w, r)
	if !ok {
		return
	}
	var body controlv1.ManagedBrowserRequest
	if decodeJSONLimited(w, r, &body, 4096) != nil || body.RunNumber < 1 {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid managed browser handoff")
		return
	}
	result, err := store.RedeemManagedBrowserHandoff(r.Context(), managedHTTPRun(service, run, token, body.RunNumber), body.Secret, time.Now())
	if err != nil {
		writeManagedHTTPBrowserProblem(w, err)
		return
	}
	writeJSON(w, 200, result)
}

func writeManagedHTTPBrowserProblem(w http.ResponseWriter, err error) {
	if errors.Is(err, controlstate.ErrVisitorSignIn) || errors.Is(err, controlstate.ErrPreviewAccess) {
		writeBearerProblem(w)
		return
	}
	writeManagedCertificateProblem(w, "authorize managed browser", err)
}

func (h *handler) CheckManagedBrowserSession(w http.ResponseWriter, r *http.Request, service controlv1.PrivateServiceID, run controlv1.PrivateRunID) {
	h.managedBrowserSession(w, r, service, run, false)
}
func (h *handler) RevokeManagedBrowserSession(w http.ResponseWriter, r *http.Request, service controlv1.PrivateServiceID, run controlv1.PrivateRunID) {
	h.managedBrowserSession(w, r, service, run, true)
}
func (h *handler) managedBrowserSession(w http.ResponseWriter, r *http.Request, service, run string, revoke bool) {
	store, token, ok := h.managedHTTP(w, r)
	if !ok {
		return
	}
	var body controlv1.ManagedBrowserRequest
	if decodeJSONLimited(w, r, &body, 4096) != nil || body.RunNumber < 1 {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid managed browser session")
		return
	}
	result, err := store.ManagedBrowserSession(r.Context(), managedHTTPRun(service, run, token, body.RunNumber), body.Secret, revoke, time.Now())
	if err != nil {
		writeManagedHTTPBrowserProblem(w, err)
		return
	}
	if revoke {
		w.WriteHeader(204)
		return
	}
	observability.AuthorizationDecision(r.Context(), "managed_browser_session", result.VisitAllowed)
	writeJSON(w, 200, controlv1.BrowserAccessResponse{IdentityId: result.IdentityID, DisplayName: result.DisplayName, VisitAllowed: result.VisitAllowed, TeamMember: result.TeamMember})
}

func (h *handler) CreateManagedHTTPGrant(w http.ResponseWriter, r *http.Request, service controlv1.PrivateServiceID) {
	store, _, ok := h.managedHTTP(w, r)
	if !ok {
		return
	}
	actor, ok := h.authorizeRouteReads(w, r)
	if !ok {
		return
	}
	var body controlv1.CreateManagedHTTPGrantRequest
	if decodeJSONLimited(w, r, &body, 4096) != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid managed HTTP grant")
		return
	}
	result, err := store.CreateManagedHTTPGrant(r.Context(), service, actor.identityID, body, time.Now())
	if err != nil {
		writeManagedCertificateProblem(w, "create managed HTTP grant", err)
		return
	}
	writeJSON(w, 201, result)
}

func (h *handler) RevokeManagedHTTPGrant(w http.ResponseWriter, r *http.Request, service controlv1.PrivateServiceID, grant string) {
	store, _, ok := h.managedHTTP(w, r)
	if !ok {
		return
	}
	actor, ok := h.authorizeRouteReads(w, r)
	if !ok {
		return
	}
	if err := store.RevokeManagedHTTPGrant(r.Context(), service, actor.identityID, grant, time.Now()); err != nil {
		writeManagedCertificateProblem(w, "revoke managed HTTP grant", err)
		return
	}
	w.WriteHeader(204)
}

func (h *handler) ListManagedHTTPGrants(w http.ResponseWriter, r *http.Request, service controlv1.PrivateServiceID) {
	w.Header().Set("Cache-Control", "no-store")
	actor, ok := h.authorizeRouteReads(w, r)
	if !ok {
		return
	}
	store, ok := h.store.(interface {
		ListManagedHTTPGrants(context.Context, string, string, time.Time) ([]controlv1.ManagedHTTPGrantSummary, error)
	})
	if !ok {
		writeProblem(w, 503, controlv1.Unavailable, "managed HTTP grants are unavailable")
		return
	}
	result, err := store.ListManagedHTTPGrants(r.Context(), service, actor.identityID, time.Now())
	if err != nil {
		privateVisitorError(w, "list managed HTTP grants", err)
		return
	}
	writeJSON(w, 200, result)
}
