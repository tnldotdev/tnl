package controlapi

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (h *handler) CreateShare(response http.ResponseWriter, request *http.Request, previewID controlv1.PreviewID, _ controlv1.CreateShareParams) {
	h.createShare(response, request, string(previewID))
}

func (h *handler) CreateURLShare(response http.ResponseWriter, request *http.Request, _ controlv1.CreateURLShareParams) {
	h.createShare(response, request, "")
}

func (h *handler) createShare(response http.ResponseWriter, request *http.Request, previewID string) {
	var body controlv1.CreateShareRequest
	if err := decodeJSONLimited(response, request, &body, 1<<20); err != nil || body.ExpiresAt.IsZero() ||
		len(body.PublicUrlIds) == 0 || len(body.PublicUrlIds) > 32 || previewID == "" && len(body.PublicUrlIds) != 1 ||
		body.Label != nil && len(*body.Label) > 128 {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid share request")
		return
	}
	key := request.Header.Get("Idempotency-Key")
	fingerprint, err := hex.DecodeString(body.SecretFingerprint)
	if key == "" || len(key) > 128 || strings.TrimSpace(key) != key || err != nil || len(fingerprint) != 32 || hex.EncodeToString(fingerprint) != body.SecretFingerprint {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid share request")
		return
	}
	if h.shares == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "shares are unavailable")
		return
	}
	principal, ok := h.authorizeRouteReads(response, request)
	if !ok {
		return
	}
	var preview controlstate.Preview
	if previewID != "" {
		preview, ok = h.readPreview(response, request, previewID, principal)
		if !ok {
			return
		}
	}
	ids := slices.Clone(body.PublicUrlIds)
	slices.Sort(ids)
	for index, id := range ids {
		if id == "" || index > 0 && id == ids[index-1] || previewID != "" && !slices.Contains(preview.PublicURLIDs, id) {
			writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "share public URLs must be distinct and belong to the selected preview")
			return
		}
	}
	authorized := make([]controlstate.AuthorizedSharePublicURL, 0, len(ids))
	var revision uint64
	for _, id := range ids {
		route, err := h.store.GetPublicURLForAuthorization(request.Context(), id)
		if errors.Is(err, controlstate.ErrPublicURLNotFound) {
			writeProblem(response, http.StatusNotFound, controlv1.NotFound, "resource not found")
			return
		}
		if err != nil {
			writeControlStateProblem(response, "read share public URL", err)
			return
		}
		if previewID == "" && preview.TeamID == "" {
			preview.TeamID = route.TeamID
		}
		if route.TeamID != preview.TeamID || route.LifecycleState != controlstate.PublicURLLifecycleEnabled ||
			route.ServiceProtocol != controlstate.PublicURLServiceHTTP ||
			(route.Purpose != controlstate.PublicURLPurposeApp && (previewID != "" || route.Purpose != controlstate.PublicURLPurposeAlias && route.Purpose != controlstate.PublicURLPurposeDemo)) {
			writeProblem(response, http.StatusConflict, controlv1.Conflict, "public URL is not enabled for sharing")
			return
		}
		prefixes := make([]string, len(route.AllowedIPPrefixes))
		for index, prefix := range route.AllowedIPPrefixes {
			prefixes[index] = prefix.String()
		}
		decision, ok := h.authorizeExistingRouteMutation(response, request, principal, authorization.Request{
			Operation: authorization.OperationShareCreate, TeamID: route.TeamID,
			PublicURLMembershipID: route.MembershipID, DomainID: route.DomainID,
			CanonicalHostname: route.CanonicalHostname, PublicURLScope: authorization.PublicURLScope(route.PublicURLScope),
			Target: route.Target, AllowedIPPrefixes: prefixes, Ephemeral: route.Ephemeral,
			PublicURLID: route.ID, PublicURLMutationRevision: route.MutationRevision,
		})
		if !ok {
			return
		}
		if decision.IdentityID != principal.identityID || decision.TeamID != preview.TeamID ||
			revision != 0 && revision != decision.PolicyRevision {
			writeProblem(response, http.StatusConflict, controlv1.Conflict, "share authorization changed; retry")
			return
		}
		revision = decision.PolicyRevision
		authorized = append(authorized, controlstate.AuthorizedSharePublicURL{
			PublicURLID: id, ExpectedMutationRevision: route.MutationRevision,
		})
	}
	var secretFingerprint [32]byte
	copy(secretFingerprint[:], fingerprint)
	label := ""
	if body.Label != nil {
		label = *body.Label
	}
	share, err := h.shares.CreateShare(request.Context(), controlstate.CreateShareRequest{
		PreviewID: previewID, TeamID: preview.TeamID, Label: label,
		ActingIdentityID: principal.identityID, IdempotencyKey: key,
		SecretFingerprint: secretFingerprint, ExpiresAt: body.ExpiresAt,
		PolicyRevision: revision, PublicURLs: authorized,
	}, time.Now())
	if err != nil {
		writeControlStateProblem(response, "create share", err)
		return
	}
	writeJSON(response, http.StatusCreated, shareResponse(share))
}

func (h *handler) CreateGuestShare(response http.ResponseWriter, request *http.Request, publicURLID controlv1.PublicURLID, _ controlv1.CreateGuestShareParams) {
	if !h.config.GuestDemoEnabled || h.shares == nil || h.guests == nil {
		writeProblem(response, http.StatusNotFound, controlv1.NotFound, "resource not found")
		return
	}
	access, ok := requestBearerToken(request)
	if !ok {
		writeBearerProblem(response)
		return
	}
	guest, err := h.guests.GuestTrialByAccessToken(request.Context(), credentials.AccessToken(access))
	if err != nil {
		writeBearerProblem(response)
		return
	}
	address, err := guestRequestAddress(request)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid client address")
		return
	}
	matched, err := h.guests.GuestSourceMatches(guest, netip.PrefixFrom(address, address.BitLen()).String())
	if err != nil {
		writeControlStateProblem(response, "check guest IP", err)
		return
	}
	if !matched {
		writeProblem(response, http.StatusForbidden, controlv1.GuestIpChanged, "guest trial IP changed")
		return
	}
	var body controlv1.CreateGuestShareRequest
	if decodeJSONLimited(response, request, &body, 4096) != nil {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid guest share request")
		return
	}
	fingerprint, err := hex.DecodeString(body.SecretFingerprint)
	key := request.Header.Get("Idempotency-Key")
	if err != nil || len(fingerprint) != sha256.Size || hex.EncodeToString(fingerprint) != body.SecretFingerprint ||
		key == "" || len(key) > 128 || strings.TrimSpace(key) != key {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid guest share request")
		return
	}
	var digest [32]byte
	copy(digest[:], fingerprint)
	share, err := h.shares.CreateGuestShare(request.Context(), guest.ID, string(publicURLID), key, digest, time.Now())
	if err != nil {
		writeControlStateProblem(response, "create guest share", err)
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	writeJSON(response, http.StatusCreated, shareResponse(share))
}

func (h *handler) ListShares(response http.ResponseWriter, request *http.Request, previewID controlv1.PreviewID, _ controlv1.ListSharesParams) {
	principal, ok := h.authorizeRouteReads(response, request)
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
		writeControlStateProblem(response, "list shares", err)
		return
	}
	writeSharePage(response, page)
}

func (h *handler) ListTeamShares(response http.ResponseWriter, request *http.Request, _ controlv1.ListTeamSharesParams) {
	principal, ok := h.authorizeRouteReads(response, request)
	if !ok {
		return
	}
	teamID := request.URL.Query().Get("team_id")
	if _, member := principal.teamIDs[teamID]; !member {
		writeProblem(response, http.StatusNotFound, controlv1.NotFound, "resource not found")
		return
	}
	if h.shares == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "shares are unavailable")
		return
	}
	page, err := h.shares.ListTeamShares(request.Context(), teamID, principal.identityID, request.URL.Query().Get("cursor"))
	if err != nil {
		writeControlStateProblem(response, "list team shares", err)
		return
	}
	writeSharePage(response, page)
}

func writeSharePage(response http.ResponseWriter, page controlstate.SharePage) {
	body := controlv1.SharePage{SchemaVersion: controlstate.ReviewSchemaVersion, Shares: make([]controlv1.Share, len(page.Shares))}
	for index, share := range page.Shares {
		body.Shares[index] = shareResponse(share)
	}
	if page.NextCursor != "" {
		body.NextCursor = &page.NextCursor
	}
	writeJSON(response, http.StatusOK, body)
}

func (h *handler) GetShare(response http.ResponseWriter, request *http.Request, shareID controlv1.ShareID) {
	share, ok := h.readShare(response, request, string(shareID))
	if ok {
		writeJSON(response, http.StatusOK, shareResponse(share))
	}
}

func (h *handler) RevokeShare(response http.ResponseWriter, request *http.Request, shareID controlv1.ShareID) {
	share, ok := h.readShare(response, request, string(shareID))
	if !ok {
		return
	}
	revoked, err := h.shares.RevokeShare(request.Context(), share.ID, share.CreatedByIdentityID, time.Now())
	if err != nil {
		writeControlStateProblem(response, "revoke share", err)
		return
	}
	writeJSON(response, http.StatusOK, shareResponse(revoked))
}

func (h *handler) readShare(response http.ResponseWriter, request *http.Request, id string) (controlstate.Share, bool) {
	principal, ok := h.authorizeRouteReads(response, request)
	if !ok {
		return controlstate.Share{}, false
	}
	if h.shares == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "shares are unavailable")
		return controlstate.Share{}, false
	}
	share, err := h.shares.GetShare(request.Context(), id)
	if err != nil {
		writeControlStateProblem(response, "read share", err)
		return controlstate.Share{}, false
	}
	if share.PreviewID != "" {
		if _, ok := h.readPreview(response, request, share.PreviewID, principal); !ok {
			return controlstate.Share{}, false
		}
	} else if _, member := principal.teamIDs[share.TeamID]; !member {
		writeProblem(response, http.StatusNotFound, controlv1.NotFound, "resource not found")
		return controlstate.Share{}, false
	}
	if share.CreatedByIdentityID != principal.identityID {
		writeProblem(response, http.StatusNotFound, controlv1.NotFound, "resource not found")
		return controlstate.Share{}, false
	}
	return share, true
}

func shareResponse(share controlstate.Share) controlv1.Share {
	result := controlv1.Share{
		SchemaVersion: controlv1.ReviewSchemaVersion(share.SchemaVersion),
		Id:            share.ID, TeamId: share.TeamID, Scope: controlv1.ShareScope(share.Scope), Label: share.Label,
		PublicUrlIds: share.PublicURLIDs, CreatedByIdentityId: share.CreatedByIdentityID,
		CreatedAt: share.CreatedAt, ExpiresAt: share.ExpiresAt, RevokedAt: share.RevokedAt,
	}
	if share.PreviewID != "" {
		result.PreviewId = &share.PreviewID
	}
	return result
}
