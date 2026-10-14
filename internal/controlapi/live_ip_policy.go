package controlapi

import (
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (h *handler) authorizedLiveIPRoute(w http.ResponseWriter, r *http.Request, id string) (controlstate.PublicURL, publicURLReadPrincipal, bool) {
	principal, ok := h.authorizeRouteReads(w, r)
	if !ok {
		return controlstate.PublicURL{}, publicURLReadPrincipal{}, false
	}
	route, err := h.store.GetPublicURLForAuthorization(r.Context(), id)
	if err != nil {
		writeControlStateProblem(w, "read public URL IP policy", err)
		return controlstate.PublicURL{}, publicURLReadPrincipal{}, false
	}
	if _, allowed := principal.teamIDs[route.TeamID]; !allowed {
		writeProblem(w, http.StatusNotFound, controlv1.NotFound, "public URL not found")
		return controlstate.PublicURL{}, publicURLReadPrincipal{}, false
	}
	return route, principal, true
}

func (h *handler) authorizedLiveIPChange(w http.ResponseWriter, r *http.Request, route controlstate.PublicURL, principal publicURLReadPrincipal, prefixes []string) (controlstate.LiveIPPolicyChange, bool) {
	decision, ok := h.authorizeExistingRouteMutation(w, r, principal, authorization.Request{
		Operation: authorization.OperationPublicURLUpdate, TeamID: route.TeamID,
		PublicURLMembershipID: route.MembershipID, DomainID: route.DomainID,
		CanonicalHostname: route.CanonicalHostname, PublicURLScope: authorization.PublicURLScope(route.PublicURLScope),
		Target: route.Target, AllowedIPPrefixes: prefixes, Ephemeral: route.Ephemeral, PublicURLID: route.ID,
		PublicURLMutationRevision: route.MutationRevision,
	})
	if !ok {
		return controlstate.LiveIPPolicyChange{}, false
	}
	return controlstate.LiveIPPolicyChange{
		PublicURLID: route.ID, TeamID: decision.TeamID, ActingIdentityID: decision.IdentityID,
		PolicyRevision: decision.PolicyRevision, ExpectedMutationRevision: route.MutationRevision,
	}, true
}

func (h *handler) ReplacePublicURLIPPolicy(w http.ResponseWriter, r *http.Request, publicURLID controlv1.PublicURLID) {
	var body controlv1.ReplacePublicURLIPPolicyRequest
	if err := decodeJSONLimited(w, r, &body, 1<<20); err != nil || body.AllowedIpPrefixes == nil {
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "provide allowed_ip_prefixes")
		return
	}
	prefixes, err := authorization.CanonicalizeIPPrefixes(body.AllowedIpPrefixes)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "invalid visitor IP policy")
		return
	}
	route, principal, ok := h.authorizedLiveIPRoute(w, r, string(publicURLID))
	if !ok {
		return
	}
	change, ok := h.authorizedLiveIPChange(w, r, route, principal, prefixes)
	if !ok {
		return
	}
	change.Source = &prefixes
	updated, _, err := h.store.ChangeLiveIPPolicy(r.Context(), change, time.Now().UTC())
	if err != nil {
		writeControlStateProblem(w, "replace visitor IP policy", err)
		return
	}
	writeJSON(w, http.StatusOK, publicURLResponse(updated))
}

func (h *handler) CreatePublicURLOperatorIPEntry(w http.ResponseWriter, r *http.Request, publicURLID controlv1.PublicURLID) {
	var body controlv1.CreateOperatorIPEntryRequest
	if err := decodeJSONLimited(w, r, &body, 1024); err != nil || body.ExpiresInSeconds < 60 || body.ExpiresInSeconds > 86400 {
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "operator IP entry needs a lifetime from one minute to one day")
		return
	}
	canonical, err := authorization.CanonicalizeIPPrefixes([]string{body.Prefix})
	if err != nil {
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "invalid visitor IP prefix")
		return
	}
	route, principal, ok := h.authorizedLiveIPRoute(w, r, string(publicURLID))
	if !ok {
		return
	}
	prefixes := make([]string, 0, len(route.AllowedIPPrefixes)+1)
	for _, prefix := range route.AllowedIPPrefixes {
		prefixes = append(prefixes, prefix.String())
	}
	prefixes = append(prefixes, canonical[0])
	prefixes, err = authorization.CanonicalizeIPPrefixes(prefixes)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "visitor IP prefix is already allowed")
		return
	}
	change, ok := h.authorizedLiveIPChange(w, r, route, principal, prefixes)
	if !ok {
		return
	}
	change.AddOperator, change.OperatorLifetime = canonical[0], time.Duration(body.ExpiresInSeconds)*time.Second
	_, issued, err := h.store.ChangeLiveIPPolicy(r.Context(), change, time.Now().UTC())
	if errors.Is(err, controlstate.ErrPublicURLConflict) {
		writeProblem(w, http.StatusConflict, controlv1.Conflict, "operator IP entry already exists")
		return
	}
	if err != nil {
		writeControlStateProblem(w, "add operator visitor IP", err)
		return
	}
	writeJSON(w, http.StatusCreated, operatorIPEntryResponse(*issued))
}

func (h *handler) ListPublicURLOperatorIPEntries(w http.ResponseWriter, r *http.Request, publicURLID controlv1.PublicURLID) {
	route, _, ok := h.authorizedLiveIPRoute(w, r, string(publicURLID))
	if !ok {
		return
	}
	entries, err := h.store.ListOperatorIPEntries(r.Context(), route.ID, time.Now().UTC())
	if err != nil {
		writeControlStateProblem(w, "list operator IP entries", err)
		return
	}
	result := make([]controlv1.OperatorIPEntry, len(entries))
	for i, entry := range entries {
		result[i] = operatorIPEntryResponse(entry)
	}
	writeJSON(w, http.StatusOK, struct {
		Entries []controlv1.OperatorIPEntry `json:"entries"`
	}{result})
}

func (h *handler) DeletePublicURLOperatorIPEntry(w http.ResponseWriter, r *http.Request, publicURLID controlv1.PublicURLID, entryID string) {
	route, principal, ok := h.authorizedLiveIPRoute(w, r, string(publicURLID))
	if !ok {
		return
	}
	prefixes := make([]string, len(route.AllowedIPPrefixes))
	for i, prefix := range route.AllowedIPPrefixes {
		prefixes[i] = prefix.String()
	}
	slices.Sort(prefixes)
	change, ok := h.authorizedLiveIPChange(w, r, route, principal, prefixes)
	if !ok {
		return
	}
	change.RevokeOperatorID = entryID
	_, _, err := h.store.ChangeLiveIPPolicy(r.Context(), change, time.Now().UTC())
	if err != nil {
		writeControlStateProblem(w, "revoke operator visitor IP", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func operatorIPEntryResponse(entry controlstate.OperatorIPGrant) controlv1.OperatorIPEntry {
	return controlv1.OperatorIPEntry{Id: entry.ID, Prefix: entry.Prefix,
		OwnerId: entry.OwnerID, ExpiresAt: entry.ExpiresAt}
}
