package controlapi

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (h *handler) EnableShareAccess(response http.ResponseWriter, request *http.Request, runID controlv1.PublishRunID) {
	var body controlv1.EnableShareAccessRequest
	if err := decodeJSON(response, request, &body); err != nil || body.PublishRunNumber < 1 || body.PreviewId == "" {
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
	if err := h.shareAccess.EnableShareAccess(request.Context(), auth, body.PreviewId); err != nil {
		writeControlStateProblem(response, "enable share access", err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func (h *handler) GetPublishRunShareState(response http.ResponseWriter, request *http.Request, runID controlv1.PublishRunID) {
	var body controlv1.PublishRunVersionRequest
	if err := decodeJSON(response, request, &body); err != nil || body.PublishRunNumber < 1 {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid share state request")
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
	shares, err := h.shareAccess.PublishRunShareState(request.Context(), auth, time.Now())
	if err != nil {
		writeControlStateProblem(response, "read publisher shares", err)
		return
	}
	result := controlv1.PublishRunShareState{SchemaVersion: controlstate.ReviewSchemaVersion, Shares: make([]controlv1.PublisherShare, len(shares))}
	if store, ok := h.store.(interface {
		PreviewTeamAccessForPublicURL(context.Context, string) (controlstate.Preview, error)
	}); ok {
		if preview, err := store.PreviewTeamAccessForPublicURL(request.Context(), auth.PublicURLID); err == nil {
			result.TeamAccessEnabled = &preview.TeamAccessEnabled
		} else if !errors.Is(err, controlstate.ErrPreviewAccess) {
			writeControlStateProblem(response, "read preview team access", err)
			return
		}
	}
	for index, share := range shares {
		cookies := make([]string, len(share.CookieHashes))
		for cookieIndex, hash := range share.CookieHashes {
			cookies[cookieIndex] = hex.EncodeToString(hash[:])
		}
		result.Shares[index] = controlv1.PublisherShare{
			SchemaVersion: controlstate.ReviewSchemaVersion,
			ShareId:       share.ID, ExpiresAt: share.ExpiresAt,
			SecretFingerprint: hex.EncodeToString(share.SecretFingerprint[:]), CookieHashes: cookies,
		}
	}
	writeJSON(response, http.StatusOK, result)
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
	writeJSON(response, http.StatusOK, controlv1.ShareRedemption{
		SchemaVersion: controlstate.ReviewSchemaVersion,
		ShareId:       result.ShareID, CookieSecret: result.CookieSecret,
		ExpiresAt: result.ExpiresAt, NextUrl: result.NextURL, Bridge: result.Bridge,
	})
}
