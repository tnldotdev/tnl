package controlapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (h *handler) ownerFeedbackDecision(ctx context.Context, token string, principal publicURLReadPrincipal, thread controlstate.FeedbackThread) (authorization.Decision, uint64, error) {
	if _, member := principal.teamIDs[thread.TeamID]; !member {
		return authorization.Decision{}, 0, authorization.ErrForbidden
	}
	route, err := h.store.GetPublicURLForAuthorization(ctx, thread.PublicURLID)
	if err != nil || route.TeamID != thread.TeamID || route.LifecycleState != controlstate.PublicURLLifecycleEnabled {
		return authorization.Decision{}, 0, authorization.ErrForbidden
	}
	prefixes := make([]string, len(route.AllowedIPPrefixes))
	for index, prefix := range route.AllowedIPPrefixes {
		prefixes[index] = prefix.String()
	}
	decision, err := h.authorizer.Authorize(ctx, authorization.Request{
		AccessToken: token, Operation: authorization.OperationPublicURLUpdate,
		TeamID: route.TeamID, PublicURLMembershipID: route.MembershipID, DomainID: route.DomainID,
		CanonicalHostname: route.CanonicalHostname, PublicURLScope: authorization.PublicURLScope(route.PublicURLScope),
		Target: route.Target, AllowedIPPrefixes: prefixes, Ephemeral: route.Ephemeral,
		PublicURLID: route.ID, PublicURLMutationRevision: route.MutationRevision,
	})
	if err != nil || decision.IdentityID != principal.identityID || decision.TeamID != thread.TeamID {
		if err != nil {
			return authorization.Decision{}, 0, err
		}
		return authorization.Decision{}, 0, authorization.ErrUnavailable
	}
	return decision, route.MutationRevision, nil
}

func feedbackOwnerFailure(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, authorization.ErrUnauthenticated):
		writeBearerProblem(response)
	case errors.Is(err, authorization.ErrForbidden):
		writeProblem(response, http.StatusNotFound, controlv1.NotFound, "resource not found")
	default:
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "feedback authorization is unavailable")
	}
}

func (h *handler) getOwnerFeedback(response http.ResponseWriter, request *http.Request, id string) (controlstate.FeedbackThread, authorization.Decision, uint64, bool) {
	principal, ok := h.authorizeRouteReads(response, request)
	if !ok {
		return controlstate.FeedbackThread{}, authorization.Decision{}, 0, false
	}
	if h.feedback == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "feedback is unavailable")
		return controlstate.FeedbackThread{}, authorization.Decision{}, 0, false
	}
	thread, err := h.feedback.GetFeedback(request.Context(), id)
	if err != nil {
		writeControlStateProblem(response, "read feedback thread", err)
		return controlstate.FeedbackThread{}, authorization.Decision{}, 0, false
	}
	token, _ := requestBearerToken(request)
	decision, revision, err := h.ownerFeedbackDecision(request.Context(), token, principal, thread)
	if err != nil {
		feedbackOwnerFailure(response, err)
		return controlstate.FeedbackThread{}, authorization.Decision{}, 0, false
	}
	return thread, decision, revision, true
}

func (h *handler) GetFeedbackThread(response http.ResponseWriter, request *http.Request, feedbackID controlv1.FeedbackID) {
	thread, _, _, ok := h.getOwnerFeedback(response, request, feedbackID)
	if !ok {
		return
	}
	result, err := feedbackThreadResponse(thread)
	if err != nil {
		writeControlStateProblem(response, "encode feedback thread", err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (h *handler) ListFeedbackThreads(response http.ResponseWriter, request *http.Request, _ controlv1.ListFeedbackThreadsParams) {
	principal, ok := h.authorizeRouteReads(response, request)
	if !ok {
		return
	}
	teamID := request.URL.Query().Get("team_id")
	if _, member := principal.teamIDs[teamID]; !member {
		writeProblem(response, http.StatusNotFound, controlv1.NotFound, "resource not found")
		return
	}
	if h.feedback == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "feedback is unavailable")
		return
	}
	page, err := h.feedback.ListFeedbackForTeam(request.Context(), teamID, request.URL.Query().Get("cursor"))
	if err != nil {
		writeControlStateProblem(response, "list feedback threads", err)
		return
	}
	token, _ := requestBearerToken(request)
	manageable := make([]controlstate.FeedbackThread, 0, len(page.Threads))
	for _, thread := range page.Threads {
		if _, _, err := h.ownerFeedbackDecision(request.Context(), token, principal, thread); err == nil {
			manageable = append(manageable, thread)
		} else if !errors.Is(err, authorization.ErrForbidden) {
			feedbackOwnerFailure(response, err)
			return
		}
	}
	page.Threads = manageable
	result, err := feedbackThreadPageResponse(page)
	if err != nil {
		writeControlStateProblem(response, "encode feedback list", err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (h *handler) AppendFeedbackEvent(response http.ResponseWriter, request *http.Request, feedbackID controlv1.FeedbackID, _ controlv1.AppendFeedbackEventParams) {
	var body controlv1.AppendFeedbackEventRequest
	if err := decodeJSONLimited(response, request, &body, 64<<10); err != nil {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid feedback event")
		return
	}
	thread, decision, revision, ok := h.getOwnerFeedback(response, request, feedbackID)
	if !ok {
		return
	}
	write, err := feedbackEventWrite(body.Type, body.Text, body.Evidence, body.CheckoutMarker)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid feedback event")
		return
	}
	write.FeedbackID = thread.ID
	write.IdempotencyKey = request.Header.Get("Idempotency-Key")
	write.Actor = controlstate.FeedbackActor{
		Kind: "developer", IdentityID: decision.IdentityID,
		PolicyRevision: decision.PolicyRevision, AuthorityIssuer: h.authorityIssuerFor(decision),
		ExpectedMutationRevision: revision,
	}
	event, err := h.feedback.AppendFeedback(request.Context(), write, time.Now())
	if err != nil {
		writeControlStateProblem(response, "append feedback event", err)
		return
	}
	result, err := feedbackEventResponse(event)
	if err != nil {
		writeControlStateProblem(response, "encode feedback event", err)
		return
	}
	writeJSON(response, http.StatusCreated, result)
}

func (h *handler) ListFeedbackThreadEvents(response http.ResponseWriter, request *http.Request, feedbackID controlv1.FeedbackID, _ controlv1.ListFeedbackThreadEventsParams) {
	thread, _, _, ok := h.getOwnerFeedback(response, request, feedbackID)
	if !ok {
		return
	}
	after, err := feedbackAfterCursor(request)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid feedback cursor")
		return
	}
	page, err := h.feedback.ListFeedbackEventsForThread(request.Context(), thread.ID, after)
	if err != nil {
		writeControlStateProblem(response, "list feedback thread events", err)
		return
	}
	result, err := feedbackEventPageResponse(page)
	if err != nil {
		writeControlStateProblem(response, "encode feedback events", err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (h *handler) ListFeedbackEvents(response http.ResponseWriter, request *http.Request, _ controlv1.ListFeedbackEventsParams) {
	principal, ok := h.authorizeRouteReads(response, request)
	if !ok {
		return
	}
	teamID := request.URL.Query().Get("team_id")
	if _, member := principal.teamIDs[teamID]; !member {
		writeProblem(response, http.StatusNotFound, controlv1.NotFound, "resource not found")
		return
	}
	after, err := feedbackAfterCursor(request)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid feedback cursor")
		return
	}
	if h.feedback == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "feedback is unavailable")
		return
	}
	page, err := h.feedback.ListFeedbackEventsForTeam(request.Context(), teamID, after)
	if err != nil {
		writeControlStateProblem(response, "watch feedback events", err)
		return
	}
	token, _ := requestBearerToken(request)
	visible := make([]controlstate.FeedbackEvent, 0, len(page.Events))
	for _, event := range page.Events {
		thread, err := h.feedback.GetFeedback(request.Context(), event.FeedbackID)
		if err != nil {
			writeControlStateProblem(response, "read watched feedback", err)
			return
		}
		if _, _, err := h.ownerFeedbackDecision(request.Context(), token, principal, thread); err == nil {
			visible = append(visible, event)
		} else if !errors.Is(err, authorization.ErrForbidden) {
			feedbackOwnerFailure(response, err)
			return
		}
	}
	page.Events = visible
	result, err := feedbackEventPageResponse(page)
	if err != nil {
		writeControlStateProblem(response, "encode watched feedback", err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func feedbackAfterCursor(request *http.Request) (uint64, error) {
	value := request.URL.Query().Get("after_cursor")
	if value == "" {
		return 0, nil
	}
	parsed, err := strconv.ParseUint(value, 10, 63)
	return parsed, err
}

func feedbackEventWrite(kind controlv1.FeedbackEventType, text *string, evidence *controlv1.FeedbackEvidence, marker *controlv1.CheckoutMarker) (controlstate.AppendFeedbackRequest, error) {
	write := controlstate.AppendFeedbackRequest{Type: controlstate.FeedbackEventType(kind)}
	if text != nil {
		write.Text = *text
	}
	if evidence != nil {
		encoded, err := json.Marshal(evidence)
		if err != nil {
			return controlstate.AppendFeedbackRequest{}, err
		}
		write.Evidence = encoded
	}
	if marker != nil {
		encoded, err := json.Marshal(marker)
		if err != nil {
			return controlstate.AppendFeedbackRequest{}, err
		}
		write.CheckoutMarker = encoded
	}
	return write, nil
}
