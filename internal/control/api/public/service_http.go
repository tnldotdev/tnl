package public

import (
	"context"
	"errors"
	"net/http"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type serviceHTTPStore interface {
	ServiceHTTPBrowserTeam(context.Context, visitorscope.Scope, time.Time) (string, error)
	BeginServiceBrowserLogin(context.Context, visitorscope.Scope, string, string, string, []byte, *controlstate.CompanyLoginIntent, time.Time) (string, error)
	RedeemServiceBrowserHandoff(context.Context, controlstate.ServiceHTTPRun, string, string, time.Time) (controlstate.ServiceBrowserHandoffRedemption, error)
	ServiceBrowserSession(context.Context, controlstate.ServiceHTTPRun, string, bool, time.Time) (controlstate.VisitorPermission, error)
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
	return controlstate.ServiceHTTPRun{Subject: visitorscope.Scope{Kind: visitorscope.Service, ID: service}, RunID: run, Number: number, Token: credentials.ServiceRunToken(token)}
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
	result, err := store.RedeemServiceBrowserHandoff(r.Context(), serviceHTTPRun(service, run, token, body.RunNumber), h.config.ControlURL, body.Secret, time.Now())
	if err != nil {
		if errors.Is(err, controlstate.ErrVisitorPermission) || errors.Is(err, controlstate.ErrVisitorSigningKey) || errors.Is(err, controlstate.ErrVisitorPolicy) {
			writeVisitorTokenProblem(w, err)
		} else {
			writeServiceHTTPBrowserProblem(w, err)
		}
		return
	}
	result.BrowserHandoffResponse.Permission = visitorTokenResponse(result.Issued)
	writeJSON(w, 200, result.BrowserHandoffResponse)
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

func (h *handler) RevokeServiceHTTPGrant(w http.ResponseWriter, r *http.Request, service controlv1.ServiceID, grant string) {
	store, _, ok := h.serviceHTTP(w, r)
	if !ok {
		return
	}
	actor, ok := h.authorizeReads(w, r)
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
	actor, ok := h.authorizeReads(w, r)
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
		serviceVisitorError(w, "list service HTTP grants", err)
		return
	}
	writeJSON(w, 200, result)
}
