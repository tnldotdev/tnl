package public

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/control/api/serviceaccess"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (h *handler) CreateShare(response http.ResponseWriter, request *http.Request, previewID controlv1.PreviewID, _ controlv1.CreateShareParams) {
	h.createShare(response, request, string(previewID))
}

func (h *handler) CreateServiceShare(response http.ResponseWriter, request *http.Request, _ controlv1.CreateServiceShareParams) {
	h.createShare(response, request, "")
}

func (h *handler) createShare(response http.ResponseWriter, request *http.Request, previewID string) {
	response.Header().Set("Cache-Control", "no-store")
	var principal controlReadPrincipal
	signed := len(request.Header.Values("X-Tnl-Actor-Token")) != 0
	if signed {
		if previewID != "" {
			writeBearerProblem(response)
			return
		}
		var ok bool
		principal, ok = h.authorizeShareRequest(response, request, true)
		if !ok {
			return
		}
	}
	var body controlv1.CreateShareRequest
	if err := decodeJSONLimited(response, request, &body, 1<<20); err != nil || body.ExpiresAt.IsZero() || body.EntryServiceId == "" ||
		len(body.ServiceIds) == 0 || len(body.ServiceIds) > 32 || previewID == "" && len(body.ServiceIds) != 1 ||
		!slices.Contains(body.ServiceIds, body.EntryServiceId) || body.Label != nil && len(*body.Label) > 128 {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid share request")
		return
	}
	key := request.Header.Get("Idempotency-Key")
	if key == "" || len(key) > 128 || strings.TrimSpace(key) != key {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid share request")
		return
	}
	if h.shares == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "shares are unavailable")
		return
	}
	var credential controlstate.GuestCredential
	var guest bool
	if !signed {
		var proceed bool
		credential, guest, proceed = h.guestServiceCredential(response, request)
		if !proceed {
			return
		}
	}
	if guest && previewID != "" {
		writeProblem(response, http.StatusForbidden, controlv1.GuestDemoOnly, "guest access can only share its exact demo service")
		return
	}
	var ok bool
	if !guest && !signed {
		principal, ok = h.authorizeReads(response, request)
		if !ok {
			return
		}
	}
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		writeControlStateProblem(request.Context(), response, "generate share credential", err)
		return
	}
	secretFingerprint := sha256.Sum256(secret[:])
	encodedSecret := base64.RawURLEncoding.EncodeToString(secret[:])
	label := ""
	if body.Label != nil {
		label = *body.Label
	}
	if guest {
		h.createGuestShare(response, request, credential, body.ServiceIds[0], key, label, secretFingerprint, encodedSecret, body.ExpiresAt)
		return
	}
	var preview controlstate.Preview
	if previewID != "" {
		preview, ok = h.readPreview(response, request, previewID, principal)
		if !ok {
			return
		}
	}
	ids := slices.Clone(body.ServiceIds)
	slices.Sort(ids)
	for index, id := range ids {
		if id == "" || index > 0 && id == ids[index-1] || previewID != "" && !slices.Contains(preview.ServiceIDs, id) {
			writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "share services must be distinct and belong to the selected preview")
			return
		}
	}
	share, err := h.shares.CreateShare(request.Context(), controlstate.CreateShareRequest{
		PreviewID: previewID, TeamID: preview.TeamID, Label: label,
		ActingIdentityID: principal.identityID, IdempotencyKey: key,
		SecretFingerprint: secretFingerprint, ExpiresAt: body.ExpiresAt,
		ServiceIDs: ids, EntryServiceID: body.EntryServiceId,
	}, time.Now())
	if err != nil {
		shareProblem(request.Context(), response, "create share", err)
		return
	}
	writeJSON(response, http.StatusCreated, serviceaccess.ShareCreation(share, encodedSecret))
}

func (h *handler) createGuestShare(response http.ResponseWriter, request *http.Request, credential controlstate.GuestCredential, serviceID, key, label string, fingerprint [32]byte, secret string, expiresAt time.Time) {
	share, err := h.shares.CreateGuestShare(request.Context(), credential, serviceID, key, label, fingerprint, expiresAt, time.Now())
	if err != nil {
		guestProblem(request.Context(), response, "create guest share", err)
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	writeJSON(response, http.StatusCreated, serviceaccess.ShareCreation(share, secret))
}

func (h *handler) ListShares(response http.ResponseWriter, request *http.Request, previewID controlv1.PreviewID, _ controlv1.ListSharesParams) {
	principal, ok := h.authorizeReads(response, request)
	if !ok {
		return
	}
	preview, ok := h.readPreview(response, request, string(previewID), principal)
	if !ok {
		return
	}
	if h.shares == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "shares are unavailable")
		return
	}
	page, err := h.shares.ListShares(request.Context(), preview.ID, request.URL.Query().Get("cursor"))
	if err != nil {
		writeControlStateProblem(request.Context(), response, "list shares", err)
		return
	}
	writeJSON(response, http.StatusOK, serviceaccess.SharePage(page))
}

func (h *handler) ListTeamShares(response http.ResponseWriter, request *http.Request, _ controlv1.ListTeamSharesParams) {
	principal, ok := h.authorizeShareRequest(response, request, false)
	if !ok {
		return
	}
	teamID := request.URL.Query().Get("team_id")
	if _, member := principal.teamIDs[teamID]; !member && len(request.Header.Values("X-Tnl-Actor-Token")) == 0 {
		writeProblem(response, http.StatusNotFound, controlv1.NotFound, "resource not found")
		return
	}
	if h.shares == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "shares are unavailable")
		return
	}
	page, err := h.shares.ListTeamShares(request.Context(), teamID, principal.identityID, request.URL.Query().Get("cursor"))
	if err != nil {
		shareProblem(request.Context(), response, "list team shares", err)
		return
	}
	writeJSON(response, http.StatusOK, serviceaccess.SharePage(page))
}

func (h *handler) GetShare(response http.ResponseWriter, request *http.Request, shareID controlv1.ShareID) {
	share, ok := h.readShare(response, request, string(shareID))
	if ok {
		writeJSON(response, http.StatusOK, serviceaccess.Share(share))
	}
}

func (h *handler) RevokeShare(response http.ResponseWriter, request *http.Request, shareID controlv1.ShareID) {
	principal, ok := h.authorizeShareRequest(response, request, false)
	if !ok {
		return
	}
	if h.shares == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "shares are unavailable")
		return
	}
	revoked, err := h.shares.RevokeShare(request.Context(), shareID, principal.identityID, time.Now())
	if err != nil {
		shareProblem(request.Context(), response, "revoke share", err)
		return
	}
	writeJSON(response, http.StatusOK, serviceaccess.Share(revoked))
}

func (h *handler) readShare(response http.ResponseWriter, request *http.Request, id string) (controlstate.Share, bool) {
	principal, ok := h.authorizeShareRequest(response, request, false)
	if !ok {
		return controlstate.Share{}, false
	}
	if h.shares == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "shares are unavailable")
		return controlstate.Share{}, false
	}
	share, err := h.shares.GetShareForManagement(request.Context(), id, principal.identityID, time.Now())
	if err != nil {
		shareProblem(request.Context(), response, "read share", err)
		return controlstate.Share{}, false
	}
	return share, true
}

func shareProblem(ctx context.Context, response http.ResponseWriter, operation string, err error) {
	switch {
	case errors.Is(err, controlstate.ErrControlAuthentication), errors.Is(err, controlstate.ErrOIDCAssertionReplay):
		writeBearerProblem(response)
	case errors.Is(err, controlstate.ErrServiceManagerRequired), errors.Is(err, controlstate.ErrServiceAccess):
		writeProblem(response, http.StatusForbidden, controlv1.Forbidden, "current service manager permission is required")
	case errors.Is(err, controlstate.ErrServiceSourceSignInRequired):
		writeProblem(response, http.StatusForbidden, controlv1.Forbidden, "sign in through the current company source")
	case errors.Is(err, controlstate.ErrServiceVerifiedEmailRequired):
		writeProblem(response, http.StatusForbidden, controlv1.Forbidden, "sign in with a verified email")
	default:
		writeControlStateProblem(ctx, response, operation, err)
	}
}
