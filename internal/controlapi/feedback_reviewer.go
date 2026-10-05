package controlapi

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func feedbackReviewerActor(access controlv1.FeedbackReviewerAccess) (controlstate.FeedbackActor, error) {
	actor := controlstate.FeedbackActor{Kind: "reviewer", AllowedIP: access.AllowedIp}
	if access.AllowedIp {
		return actor, nil
	}
	if access.ShareId == nil || access.CookieSecret == nil {
		return actor, controlstate.ErrFeedbackAccess
	}
	secret, err := base64.RawURLEncoding.DecodeString(*access.CookieSecret)
	if err != nil || len(secret) != 32 {
		return actor, controlstate.ErrFeedbackAccess
	}
	actor.ShareID, actor.CookieSecret = *access.ShareId, secret
	return actor, nil
}

func (h *handler) CreateFeedbackReport(response http.ResponseWriter, request *http.Request, runID controlv1.PublishRunID, _ controlv1.CreateFeedbackReportParams) {
	var body controlv1.CreateFeedbackReportRequest
	if err := decodeJSONLimited(response, request, &body, 64<<10); err != nil || body.PublishRunNumber < 1 {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid feedback report")
		return
	}
	auth, ok := h.authenticatePublishRunRequest(response, request, runID, uint64(body.PublishRunNumber))
	if !ok {
		return
	}
	if h.feedback == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "feedback is unavailable")
		return
	}
	actor, err := feedbackReviewerActor(body.Access)
	if err != nil {
		writeControlStateProblem(response, "verify feedback reviewer", err)
		return
	}
	anchor, err := json.Marshal(body.Anchor)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid feedback element")
		return
	}
	evidence, err := json.Marshal(body.Evidence)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid feedback evidence")
		return
	}
	marker, err := json.Marshal(body.CheckoutAtReport)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid checkout marker")
		return
	}
	displayName := ""
	if body.Report.DisplayName != nil {
		displayName = *body.Report.DisplayName
	}
	thread, err := h.feedback.CreateFeedback(request.Context(), auth, controlstate.CreateFeedbackRequest{
		PageTitle: optionalFeedbackString(body.PageTitle),
		PreviewID: body.PreviewId, Service: body.Service, PagePath: body.PagePath,
		ReportText: body.Report.Text, AuthorDisplayName: displayName,
		Anchor: anchor, Evidence: evidence, CheckoutAtReport: marker,
		IdempotencyKey: request.Header.Get("Idempotency-Key"), Actor: actor,
	}, time.Now())
	if err != nil {
		writeControlStateProblem(response, "create feedback report", err)
		return
	}
	result, err := feedbackThreadResponse(thread)
	if err != nil {
		writeControlStateProblem(response, "encode feedback report", err)
		return
	}
	writeJSON(response, http.StatusCreated, result)
}

func (h *handler) ListPreviewPageFeedback(response http.ResponseWriter, request *http.Request, runID controlv1.PublishRunID) {
	var body controlv1.PreviewPageFeedbackRequest
	if err := decodeJSON(response, request, &body); err != nil || body.PublishRunNumber < 1 {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid page feedback request")
		return
	}
	auth, ok := h.authenticatePublishRunRequest(response, request, runID, uint64(body.PublishRunNumber))
	if !ok {
		return
	}
	if h.feedback == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "feedback is unavailable")
		return
	}
	actor, err := feedbackReviewerActor(body.Access)
	if err != nil {
		writeControlStateProblem(response, "verify feedback reviewer", err)
		return
	}
	_, publicURLID, err := h.feedback.ReviewerFeedbackScope(request.Context(), auth, body.PreviewId, actor, time.Now())
	if err != nil {
		writeControlStateProblem(response, "read reviewer page", err)
		return
	}
	cursor := ""
	if body.Cursor != nil {
		cursor = *body.Cursor
	}
	page, err := h.feedback.ListFeedbackForPublicURL(request.Context(), body.PreviewId, publicURLID, optionalFeedbackString(body.PagePath), optionalFeedbackString(body.State), cursor)
	if err != nil {
		writeControlStateProblem(response, "list page feedback", err)
		return
	}
	result, err := feedbackThreadPageResponse(page)
	if err != nil {
		writeControlStateProblem(response, "encode page feedback", err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func optionalFeedbackString[T ~string](value *T) string {
	if value == nil {
		return ""
	}
	return string(*value)
}

func (h *handler) AppendReviewerFeedbackEvent(response http.ResponseWriter, request *http.Request, runID controlv1.PublishRunID, feedbackID controlv1.FeedbackID, _ controlv1.AppendReviewerFeedbackEventParams) {
	var body controlv1.AppendReviewerFeedbackEventRequest
	if err := decodeJSONLimited(response, request, &body, 64<<10); err != nil || body.PublishRunNumber < 1 {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid reviewer feedback")
		return
	}
	auth, ok := h.authenticatePublishRunRequest(response, request, runID, uint64(body.PublishRunNumber))
	if !ok {
		return
	}
	if h.feedback == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "feedback is unavailable")
		return
	}
	actor, err := feedbackReviewerActor(body.Access)
	if err != nil {
		writeControlStateProblem(response, "verify feedback reviewer", err)
		return
	}
	thread, authorized := h.readReviewerFeedback(response, request, auth, feedbackID, actor)
	if !authorized {
		return
	}
	write, err := feedbackEventWrite(body.Type, body.Text, body.Evidence, body.CheckoutMarker)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid reviewer feedback")
		return
	}
	write.FeedbackID, write.IdempotencyKey, write.Actor = thread.ID, request.Header.Get("Idempotency-Key"), actor
	event, err := h.feedback.AppendFeedback(request.Context(), write, time.Now())
	if err != nil {
		writeControlStateProblem(response, "append reviewer feedback", err)
		return
	}
	result, err := feedbackEventResponse(event)
	if err != nil {
		writeControlStateProblem(response, "encode reviewer feedback", err)
		return
	}
	writeJSON(response, http.StatusCreated, result)
}

func (h *handler) GetReviewerFeedbackThread(response http.ResponseWriter, request *http.Request, runID controlv1.PublishRunID, feedbackID controlv1.FeedbackID) {
	thread, _, ok := h.reviewerFeedbackRead(response, request, runID, feedbackID)
	if !ok {
		return
	}
	result, err := feedbackThreadResponse(thread)
	if err != nil {
		writeControlStateProblem(response, "encode reviewer feedback thread", err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (h *handler) ListReviewerFeedbackEvents(response http.ResponseWriter, request *http.Request, runID controlv1.PublishRunID, feedbackID controlv1.FeedbackID) {
	thread, body, ok := h.reviewerFeedbackRead(response, request, runID, feedbackID)
	if !ok {
		return
	}
	after := uint64(0)
	if body.AfterCursor != nil {
		if *body.AfterCursor < 0 {
			writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid feedback cursor")
			return
		}
		after = uint64(*body.AfterCursor)
	}
	page, err := h.feedback.ListFeedbackEventsForThread(request.Context(), thread.ID, after)
	if err != nil {
		writeControlStateProblem(response, "list reviewer feedback events", err)
		return
	}
	result, err := feedbackEventPageResponse(page)
	if err != nil {
		writeControlStateProblem(response, "encode reviewer feedback events", err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (h *handler) reviewerFeedbackRead(response http.ResponseWriter, request *http.Request, runID controlv1.PublishRunID, feedbackID controlv1.FeedbackID) (controlstate.FeedbackThread, controlv1.ReviewerFeedbackReadRequest, bool) {
	var body controlv1.ReviewerFeedbackReadRequest
	if err := decodeJSON(response, request, &body); err != nil || body.PublishRunNumber < 1 || body.PreviewId == "" {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid reviewer feedback request")
		return controlstate.FeedbackThread{}, body, false
	}
	auth, ok := h.authenticatePublishRunRequest(response, request, runID, uint64(body.PublishRunNumber))
	if !ok {
		return controlstate.FeedbackThread{}, body, false
	}
	if h.feedback == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "feedback is unavailable")
		return controlstate.FeedbackThread{}, body, false
	}
	actor, err := feedbackReviewerActor(body.Access)
	if err != nil {
		writeControlStateProblem(response, "verify feedback reviewer", err)
		return controlstate.FeedbackThread{}, body, false
	}
	thread, ok := h.readReviewerFeedback(response, request, auth, feedbackID, actor)
	if !ok || thread.PreviewID != body.PreviewId {
		if ok {
			writeProblem(response, http.StatusNotFound, controlv1.NotFound, "resource not found")
		}
		return controlstate.FeedbackThread{}, body, false
	}
	return thread, body, true
}

func (h *handler) readReviewerFeedback(response http.ResponseWriter, request *http.Request, auth controlstate.PublishRunAuthentication, id string, actor controlstate.FeedbackActor) (controlstate.FeedbackThread, bool) {
	thread, err := h.feedback.GetFeedback(request.Context(), id)
	if err != nil {
		writeControlStateProblem(response, "read reviewer feedback", err)
		return controlstate.FeedbackThread{}, false
	}
	_, publicURLID, err := h.feedback.ReviewerFeedbackScope(request.Context(), auth, thread.PreviewID, actor, time.Now())
	if err != nil {
		writeControlStateProblem(response, "verify reviewer feedback access", err)
		return controlstate.FeedbackThread{}, false
	}
	if thread.PublicURLID != publicURLID || thread.PublicURLID != auth.PublicURLID {
		writeProblem(response, http.StatusNotFound, controlv1.NotFound, "resource not found")
		return controlstate.FeedbackThread{}, false
	}
	return thread, true
}
