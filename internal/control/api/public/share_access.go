package public

import (
	"encoding/base64"
	"net/http"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (h *handler) EnableShareAccess(response http.ResponseWriter, request *http.Request, runID controlv1.PublishRunID) {
	var body controlv1.EnableShareAccessRequest
	if err := decodeJSON(response, request, &body); err != nil || body.PublishRunNumber < 1 {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid share access request")
		return
	}
	auth, ok := h.authenticatePublishRunRequest(response, request, runID, uint64(body.PublishRunNumber))
	if !ok {
		return
	}
	if h.shareAccess == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "share access is unavailable")
		return
	}
	previewID := ""
	if body.PreviewId != nil {
		previewID = *body.PreviewId
	}
	if err := h.shareAccess.EnableShareAccess(request.Context(), auth, previewID); err != nil {
		writeControlStateProblem(response, "enable share access", err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func (h *handler) RedeemPublishRunShare(response http.ResponseWriter, request *http.Request, runID controlv1.PublishRunID) {
	var body controlv1.RedeemShareRequest
	if err := decodeJSON(response, request, &body); err != nil || body.PublishRunNumber < 1 ||
		(body.Secret == nil) == (body.HandoffToken == nil) || body.Secret != nil && body.ShareId == nil {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid share redemption request")
		return
	}
	auth, ok := h.authenticatePublishRunRequest(response, request, runID, uint64(body.PublishRunNumber))
	if !ok {
		return
	}
	if h.shareAccess == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "share access is unavailable")
		return
	}
	var secret, handoff []byte
	var err error
	shareID := ""
	if body.Secret != nil {
		shareID = *body.ShareId
		secret, err = base64.RawURLEncoding.DecodeString(*body.Secret)
	} else {
		handoff, err = base64.RawURLEncoding.DecodeString(*body.HandoffToken)
	}
	if err != nil || len(secret) != 32 && len(handoff) != 32 {
		writeProblem(response, http.StatusNotFound, controlv1.NotFound, "share not found")
		return
	}
	result, err := h.shareAccess.RedeemShare(request.Context(), auth, shareID, secret, handoff, time.Now())
	if err != nil {
		writeControlStateProblem(response, "redeem share", err)
		return
	}
	permission, err := h.redeemedVisitorPermission(request.Context(), visitorscope.Scope{Kind: visitorscope.PublicURL, ID: auth.PublicURLID}, controlstate.ShareSessionTokenSource{ShareID: result.ShareID, Secret: result.CookieSecret})
	if err != nil {
		writeVisitorTokenProblem(response, err)
		return
	}
	writeJSON(response, http.StatusOK, controlv1.ShareRedemption{
		SchemaVersion: controlstate.ReviewSchemaVersion,
		ShareId:       result.ShareID, CookieSecret: result.CookieSecret,
		ExpiresAt: result.ExpiresAt, NextUrl: result.NextURL, Bridge: result.Bridge,
		Permission: permission,
	})
}
