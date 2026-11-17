package public

import (
	"encoding/base64"
	"net/http"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (h *handler) RedeemServiceShare(response http.ResponseWriter, request *http.Request, service controlv1.ServiceID, run controlv1.ServiceRunID) {
	response.Header().Set("Cache-Control", "no-store")
	var body controlv1.RedeemServiceShareRequest
	if decodeJSONLimited(response, request, &body, 4096) != nil || body.RunNumber < 1 ||
		(body.Secret == nil) == (body.HandoffToken == nil) || body.Secret != nil && body.ShareId == nil {
		writeProblem(response, 400, controlv1.InvalidRequest, "invalid share redemption request")
		return
	}
	token, ok := requestBearerToken(request)
	if !ok {
		writeBearerProblem(response)
		return
	}
	if h.shareAccess == nil {
		writeProblem(response, 503, controlv1.Unavailable, "share access is unavailable")
		return
	}
	var secret, handoff []byte
	var err error
	shareID := ""
	if body.Secret != nil {
		shareID = *body.ShareId
		secret, err = base64.RawURLEncoding.Strict().DecodeString(*body.Secret)
	} else {
		handoff, err = base64.RawURLEncoding.Strict().DecodeString(*body.HandoffToken)
	}
	if err != nil || len(secret) != 32 && len(handoff) != 32 {
		writeProblem(response, 404, controlv1.NotFound, "share not found")
		return
	}
	auth := serviceHTTPRun(service, run, token, body.RunNumber)
	auth.Hostname = body.Hostname
	result, err := h.shareAccess.RedeemShare(request.Context(), auth, shareID, secret, handoff, time.Now())
	if err != nil {
		writeControlStateProblem(request.Context(), response, "redeem share", err)
		return
	}
	permission, err := h.redeemedVisitorPermission(request.Context(), auth.Subject, controlstate.ShareSessionTokenSource{ShareID: result.ShareID, Secret: result.CookieSecret, RunID: run}, body.Hostname)
	if err != nil {
		writeVisitorTokenProblem(request.Context(), response, err)
		return
	}
	writeJSON(response, 200, controlv1.ShareRedemption{SchemaVersion: controlstate.ReviewSchemaVersion,
		ShareId: result.ShareID, CookieSecret: result.CookieSecret, ExpiresAt: result.ExpiresAt,
		NextUrl: result.NextURL, Bridge: result.Bridge, Permission: permission})
}
