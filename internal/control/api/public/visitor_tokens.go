package public

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/httpjson"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type visitorTokenStore interface {
	IssueVisitorToken(context.Context, string, visitorscope.Scope, controlstate.VisitorTokenSource, time.Time) (controlstate.IssuedVisitorToken, error)
	CreateVisitorGrantCredentials(context.Context, string, visitorscope.Scope, string, time.Time, time.Time) (controlstate.VisitorGrantCredentials, error)
	IssueVisitorClientCertificate(context.Context, string, visitorscope.Scope, controlstate.VisitorTokenSource, []byte, time.Time) (controlstate.ServiceClientCertificate, error)
}

func (h *handler) IssueVisitorClientCertificate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	store, ok := h.store.(visitorTokenStore)
	if !ok {
		writeProblem(w, 503, controlv1.Unavailable, "visitor certificate issuance is unavailable")
		return
	}
	var body controlv1.VisitorCertificateRequest
	if decodeJSONLimited(w, r, &body, 32<<10) != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid visitor certificate request")
		return
	}
	scope := visitorscope.Scope{Kind: visitorscope.Kind(body.Resource.Kind), ID: body.Resource.Id}
	source, human, err := parseVisitorTokenSource(body.Source)
	if err != nil || !scope.Valid() || scope.Kind != visitorscope.Service || len(body.Csr) > 8192 {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid visitor certificate source or resource")
		return
	}
	switch source.(type) {
	case controlstate.DeviceTokenSource, controlstate.WorkloadTokenSource:
	default:
		writeProblem(w, 400, controlv1.InvalidRequest, "visitor certificates require a device or workload")
		return
	}
	ctx := r.Context()
	if human {
		var valid bool
		ctx, valid = h.visitorTokenPrincipal(w, r)
		if !valid {
			return
		}
	} else if len(r.Header.Values("Authorization")) != 0 {
		writeProblem(w, 400, controlv1.InvalidRequest, "select one visitor token source")
		return
	}
	result, err := store.IssueVisitorClientCertificate(ctx, h.config.ControlURL, scope, source, body.Csr, time.Now())
	if err != nil {
		writeVisitorTokenProblem(w, err)
		return
	}
	writeJSON(w, 201, controlv1.ServiceClientCertificate{ServiceId: result.ServiceID, CertificatePem: result.CertificatePEM, IssuerPem: result.IssuerPEM, ExpiresAt: result.ExpiresAt})
}

func visitorTokenResponse(issued controlstate.IssuedVisitorToken) controlv1.VisitorTokenResponse {
	permission := issued.Permission
	return controlv1.VisitorTokenResponse{Resource: controlv1.VisitorResourceScope{Kind: controlv1.VisitorResourceScopeKind(permission.Scope.Kind), Id: permission.Scope.ID},
		Hostname: permission.Hostname, Port: int(permission.Port), VisitorPolicyRevision: permission.VisitorPolicyRevision, ExpiresAt: permission.ExpiresAt, VisitorToken: issued.Token.Reveal()}
}

func (h *handler) IssueVisitorToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	store, ok := h.store.(visitorTokenStore)
	if !ok {
		writeProblem(w, 503, controlv1.Unavailable, "visitor token issuance is unavailable")
		return
	}
	var body controlv1.VisitorTokenRequest
	if decodeJSONLimited(w, r, &body, 8<<10) != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid visitor token request")
		return
	}
	scope := visitorscope.Scope{Kind: visitorscope.Kind(body.Resource.Kind), ID: body.Resource.Id}
	source, human, err := parseVisitorTokenSource(body.Source)
	if err != nil || !scope.Valid() {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid visitor token source or resource")
		return
	}
	ctx := r.Context()
	if human {
		var valid bool
		ctx, valid = h.visitorTokenPrincipal(w, r)
		if !valid {
			return
		}
	} else if len(r.Header.Values("Authorization")) != 0 {
		writeProblem(w, 400, controlv1.InvalidRequest, "select one visitor token source")
		return
	}
	result, err := store.IssueVisitorToken(ctx, h.config.ControlURL, scope, source, time.Now())
	if err != nil {
		writeVisitorTokenProblem(w, err)
		return
	}
	observability.AuthorizationDecision(ctx, "visitor_token.issue", true)
	writeJSON(w, 200, visitorTokenResponse(result))
}

func (h *handler) CreateVisitorCredential(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	store, ok := h.store.(visitorTokenStore)
	if !ok {
		writeProblem(w, 503, controlv1.Unavailable, "visitor credential issuance is unavailable")
		return
	}
	ctx, valid := h.visitorTokenPrincipal(w, r)
	if !valid {
		return
	}
	var body controlv1.CreateVisitorCredentialRequest
	if decodeJSONLimited(w, r, &body, 4096) != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid visitor credential request")
		return
	}
	scope := visitorscope.Scope{Kind: visitorscope.Kind(body.Resource.Kind), ID: body.Resource.Id}
	if !scope.Valid() || (body.Kind != "token" && body.Kind != "share") {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid visitor credential resource or kind")
		return
	}
	result, err := store.CreateVisitorGrantCredentials(ctx, h.config.ControlURL, scope, string(body.Kind), body.ExpiresAt, time.Now())
	if err != nil {
		writeVisitorTokenProblem(w, err)
		return
	}
	writeJSON(w, 201, controlv1.VisitorCredential{GrantId: result.GrantID, RefreshCredential: result.RefreshCredential, Permission: visitorTokenResponse(result.IssuedVisitorToken)})
}

func (h *handler) visitorTokenPrincipal(w http.ResponseWriter, r *http.Request) (context.Context, bool) {
	principal, ok := h.authorizeReads(w, r)
	if !ok {
		return r.Context(), false
	}
	if principal.controlPrincipal.IdentityID == "" || principal.controlPrincipal.SessionID == "" {
		writeBearerProblem(w)
		return r.Context(), false
	}
	return controlstate.WithControlPrincipal(r.Context(), principal.controlPrincipal), true
}

func parseVisitorTokenSource(raw json.RawMessage) (controlstate.VisitorTokenSource, bool, error) {
	invalid := errors.New("visitor token source is invalid")
	var discriminator struct {
		Kind string `json:"kind"`
	}
	if len(raw) == 0 || len(raw) > 4096 || json.Unmarshal(raw, &discriminator) != nil {
		return nil, false, invalid
	}
	decode := func(destination any) error {
		return httpjson.Decode(json.NewDecoder(bytes.NewReader(raw)), destination)
	}
	switch discriminator.Kind {
	case "control_session":
		var source controlv1.VisitorTokenControlSessionSource
		if decode(&source) != nil {
			return nil, false, invalid
		}
		preview := ""
		if source.PreviewId != nil {
			preview = *source.PreviewId
			if !opaqueid.Valid(preview, opaqueid.PreviewPrefix) {
				return nil, false, invalid
			}
		}
		return controlstate.BrowserTokenSource{PreviewID: preview}, true, nil
	case "browser_session":
		var source controlv1.VisitorTokenBrowserSessionSource
		if decode(&source) != nil || len(source.Secret) != 43 {
			return nil, false, invalid
		}
		return controlstate.BrowserSessionTokenSource{Secret: source.Secret}, false, nil
	case "device":
		var source controlv1.VisitorTokenDeviceSource
		if decode(&source) != nil || !opaqueid.Valid(source.DeviceId, opaqueid.VisitorDevicePrefix) {
			return nil, false, invalid
		}
		return controlstate.DeviceTokenSource{DeviceID: source.DeviceId}, true, nil
	case "workload":
		var source controlv1.VisitorTokenWorkloadSource
		if decode(&source) != nil || len(source.Credential) < 5 || len(source.Credential) > 256 {
			return nil, false, invalid
		}
		return controlstate.WorkloadTokenSource{Credential: source.Credential}, false, nil
	case "share":
		var source controlv1.VisitorTokenShareSource
		if decode(&source) != nil || !opaqueid.Valid(source.ShareId, opaqueid.SharePrefix) || len(source.Secret) != 43 {
			return nil, false, invalid
		}
		return controlstate.ShareTokenSource{ShareID: source.ShareId, Secret: source.Secret}, false, nil
	case "grant":
		var source controlv1.VisitorTokenGrantSource
		if decode(&source) != nil || len(source.Credential) < 5 || len(source.Credential) > 128 {
			return nil, false, invalid
		}
		return controlstate.GrantTokenSource{Credential: source.Credential}, false, nil
	default:
		return nil, false, invalid
	}
}

func writeVisitorTokenProblem(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, controlstate.ErrVisitorPermission), errors.Is(err, controlstate.ErrWorkloadDenied), errors.Is(err, controlstate.ErrPreviewAccess), errors.Is(err, controlstate.ErrServiceAccess):
		writeProblem(w, 403, controlv1.Forbidden, "visitor access denied")
	case errors.Is(err, controlstate.ErrVisitorSigningKey), errors.Is(err, controlstate.ErrVisitorPolicy):
		writeProblem(w, 503, controlv1.Unavailable, "visitor token signing is unavailable; retry preparation")
	default:
		writeControlStateProblem(w, "issue visitor permission", err)
	}
}
