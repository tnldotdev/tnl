package public

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/httpjson"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/authorization"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func feedbackReviewerActor(access controlv1.FeedbackReviewerAccess) (controlstate.FeedbackActor, error) {
	actor := controlstate.FeedbackActor{Kind: "reviewer", VisitAllowed: access.VisitAllowed}
	var err error
	actor.VisitProof, err = feedbackVisitProof(access.VisitProof)
	if err != nil {
		return actor, err
	}
	if actor.VisitProof != nil && (access.ShareId != nil || access.ShareSecret != nil || access.CookieSecret != nil) {
		return actor, controlstate.ErrFeedbackAccess
	}
	if access.SourceIp != nil {
		actor.SourceIP = *access.SourceIp
	}
	if access.BrowserCookieSecret != nil {
		secret, err := feedbackAccessSecret(*access.BrowserCookieSecret)
		if err != nil {
			return actor, controlstate.ErrFeedbackAccess
		}
		actor.BrowserCookieSecret = secret
	}
	if access.ShareId != nil || access.ShareSecret != nil || access.CookieSecret != nil {
		if access.ShareId == nil || !opaqueid.Valid(*access.ShareId, opaqueid.SharePrefix) ||
			(access.ShareSecret == nil) == (access.CookieSecret == nil) {
			return actor, controlstate.ErrFeedbackAccess
		}
		supplied := access.ShareSecret
		if access.CookieSecret != nil {
			supplied = access.CookieSecret
		}
		secret, err := feedbackAccessSecret(*supplied)
		if err != nil {
			return actor, err
		}
		actor.ShareID = *access.ShareId
		if access.CookieSecret != nil {
			actor.CookieSecret = secret
		} else {
			actor.ShareSecret = secret
		}
	}
	if !actor.VisitAllowed && actor.VisitProof == nil && actor.ShareID == "" && len(actor.BrowserCookieSecret) == 0 {
		return actor, controlstate.ErrFeedbackAccess
	}
	return actor, nil
}

func feedbackVisitProof(raw json.RawMessage) (controlstate.FeedbackVisitProof, error) {
	if raw == nil {
		return nil, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return nil, controlstate.ErrFeedbackAccess
	}
	var kind string
	if json.Unmarshal(fields["kind"], &kind) != nil {
		return nil, controlstate.ErrFeedbackAccess
	}
	switch kind {
	case "bearer":
		var proof controlv1.FeedbackBearerVisitProof
		if httpjson.Decode(json.NewDecoder(bytes.NewReader(raw)), &proof) != nil ||
			proof.Kind != controlv1.FeedbackVisitBearer || len(proof.Token) == 0 || len(proof.Token) > 2048 {
			return nil, controlstate.ErrFeedbackAccess
		}
		return controlstate.FeedbackBearerVisitProof{Token: visitortoken.Token(proof.Token)}, nil
	case "connector":
		var proof controlv1.FeedbackConnectorVisitProof
		var generation string
		if httpjson.Decode(json.NewDecoder(bytes.NewReader(raw)), &proof) != nil ||
			proof.Kind != controlv1.FeedbackVisitConnector || !opaqueid.Valid(proof.PairId, "cpp_") ||
			proof.DeliveryGeneration < 1 || len(proof.PermissionToken) == 0 || len(proof.PermissionToken) > 2048 ||
			json.Unmarshal(fields["delivery_generation"], &generation) != nil || generation != strconv.FormatInt(proof.DeliveryGeneration, 10) {
			return nil, controlstate.ErrFeedbackAccess
		}
		return controlstate.FeedbackConnectorVisitProof{
			PairID: proof.PairId, DeliveryGeneration: proof.DeliveryGeneration, PermissionToken: visitortoken.Token(proof.PermissionToken),
		}, nil
	default:
		return nil, controlstate.ErrFeedbackAccess
	}
}

func feedbackAccessSecret(value string) ([]byte, error) {
	secret, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(value) != 43 || len(secret) != 32 {
		return nil, controlstate.ErrFeedbackAccess
	}
	return secret, nil
}

func (h *handler) feedbackBrowserActor(request *http.Request, auth controlstate.ServiceHTTPRun, actor controlstate.FeedbackActor) (controlstate.FeedbackActor, error) {
	actor.ServiceRun = &auth
	if len(actor.BrowserCookieSecret) == 0 {
		return actor, nil
	}
	token := base64.RawURLEncoding.EncodeToString(actor.BrowserCookieSecret)
	session, principal, teamMember, err := h.browserSessionAccess(request, auth, token)
	if err != nil {
		if errors.Is(err, controlstate.ErrPreviewAccess) || errors.Is(err, authorization.ErrUnauthenticated) || errors.Is(err, clientauthority.ErrUnauthenticated) {
			return actor, controlstate.ErrVisitorSignIn
		}
		return actor, err
	}
	actor.IdentityID, actor.DisplayName, actor.TeamMember = session.IdentityID, principal.displayName, teamMember
	return actor, nil
}

func (h *handler) CreateFeedbackReport(response http.ResponseWriter, request *http.Request, serviceID controlv1.ServiceID, runID controlv1.ServiceRunID, _ controlv1.CreateFeedbackReportParams) {
	var body controlv1.CreateFeedbackReportRequest
	if err := decodeJSONLimited(response, request, &body, 64<<10); err != nil || body.RunNumber < 1 {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid feedback report")
		return
	}
	_, token, ok := h.serviceHTTP(response, request)
	if !ok {
		return
	}
	auth := serviceHTTPRun(serviceID, runID, token, body.RunNumber)
	if h.feedback == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "feedback is unavailable")
		return
	}
	actor, err := feedbackReviewerActor(body.Access)
	if err != nil {
		writeControlStateProblem(request.Context(), response, "verify feedback reviewer", err)
		return
	}
	actor, err = h.feedbackBrowserActor(request, auth, actor)
	if err != nil {
		writeFeedbackProblem(request.Context(), response, "verify signed-in reviewer", err)
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
	source, err := json.Marshal(body.SourceAtReport)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid source state")
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
		Anchor: anchor, Evidence: evidence, SourceAtReport: source,
		IdempotencyKey: request.Header.Get("Idempotency-Key"), Actor: actor,
	}, time.Now())
	if err != nil {
		writeFeedbackProblem(request.Context(), response, "create feedback report", err)
		return
	}
	result, err := feedbackThreadResponse(thread)
	if err != nil {
		writeControlStateProblem(request.Context(), response, "encode feedback report", err)
		return
	}
	writeJSON(response, http.StatusCreated, result)
}

func (h *handler) ListPreviewPageFeedback(response http.ResponseWriter, request *http.Request, serviceID controlv1.ServiceID, runID controlv1.ServiceRunID) {
	var body controlv1.PreviewPageFeedbackRequest
	if err := decodeJSON(response, request, &body); err != nil || body.RunNumber < 1 {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid page feedback request")
		return
	}
	_, token, ok := h.serviceHTTP(response, request)
	if !ok {
		return
	}
	auth := serviceHTTPRun(serviceID, runID, token, body.RunNumber)
	if h.feedback == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "feedback is unavailable")
		return
	}
	actor, err := feedbackReviewerActor(body.Access)
	if err != nil {
		writeControlStateProblem(request.Context(), response, "verify feedback reviewer", err)
		return
	}
	actor, err = h.feedbackBrowserActor(request, auth, actor)
	if err != nil {
		writeFeedbackProblem(request.Context(), response, "verify signed-in reviewer", err)
		return
	}
	_, service, err := h.feedback.ReviewerFeedbackScope(request.Context(), auth, body.PreviewId, actor, time.Now())
	if err != nil {
		writeFeedbackProblem(request.Context(), response, "read reviewer page", err)
		return
	}
	cursor := ""
	if body.Cursor != nil {
		cursor = *body.Cursor
	}
	page, err := h.feedback.ListFeedbackForService(request.Context(), body.PreviewId, service, optionalFeedbackString(body.PagePath), optionalFeedbackString(body.State), cursor)
	if err != nil {
		writeControlStateProblem(request.Context(), response, "list page feedback", err)
		return
	}
	result, err := feedbackThreadPageResponse(page)
	if err != nil {
		writeControlStateProblem(request.Context(), response, "encode page feedback", err)
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

func (h *handler) AppendReviewerFeedbackEvent(response http.ResponseWriter, request *http.Request, serviceID controlv1.ServiceID, runID controlv1.ServiceRunID, feedbackID controlv1.FeedbackID, _ controlv1.AppendReviewerFeedbackEventParams) {
	var body controlv1.AppendReviewerFeedbackEventRequest
	if err := decodeJSONLimited(response, request, &body, 64<<10); err != nil || body.RunNumber < 1 || !body.Type.Valid() {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid reviewer feedback")
		return
	}
	_, token, ok := h.serviceHTTP(response, request)
	if !ok {
		return
	}
	auth := serviceHTTPRun(serviceID, runID, token, body.RunNumber)
	if h.feedback == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "feedback is unavailable")
		return
	}
	actor, err := feedbackReviewerActor(body.Access)
	if err != nil {
		writeControlStateProblem(request.Context(), response, "verify feedback reviewer", err)
		return
	}
	actor, err = h.feedbackBrowserActor(request, auth, actor)
	if err != nil {
		writeFeedbackProblem(request.Context(), response, "verify signed-in reviewer", err)
		return
	}
	thread, authorized := h.readReviewerFeedback(response, request, auth, feedbackID, actor)
	if !authorized {
		return
	}
	write, err := feedbackEventWrite(controlv1.FeedbackEventType(body.Type), body.Text, body.Evidence, body.SourceState)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid reviewer feedback")
		return
	}
	write.FeedbackID, write.IdempotencyKey, write.Actor = thread.ID, request.Header.Get("Idempotency-Key"), actor
	event, err := h.feedback.AppendFeedback(request.Context(), write, time.Now())
	if err != nil {
		writeFeedbackProblem(request.Context(), response, "append reviewer feedback", err)
		return
	}
	result, err := feedbackEventResponse(event)
	if err != nil {
		writeControlStateProblem(request.Context(), response, "encode reviewer feedback", err)
		return
	}
	writeJSON(response, http.StatusCreated, result)
}

func (h *handler) GetReviewerFeedbackThread(response http.ResponseWriter, request *http.Request, serviceID controlv1.ServiceID, runID controlv1.ServiceRunID, feedbackID controlv1.FeedbackID) {
	thread, _, ok := h.reviewerFeedbackRead(response, request, serviceID, runID, feedbackID)
	if !ok {
		return
	}
	result, err := feedbackThreadResponse(thread)
	if err != nil {
		writeControlStateProblem(request.Context(), response, "encode reviewer feedback thread", err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (h *handler) ListReviewerFeedbackEvents(response http.ResponseWriter, request *http.Request, serviceID controlv1.ServiceID, runID controlv1.ServiceRunID, feedbackID controlv1.FeedbackID) {
	thread, body, ok := h.reviewerFeedbackRead(response, request, serviceID, runID, feedbackID)
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
		writeControlStateProblem(request.Context(), response, "list reviewer feedback events", err)
		return
	}
	result, err := feedbackEventPageResponse(page)
	if err != nil {
		writeControlStateProblem(request.Context(), response, "encode reviewer feedback events", err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (h *handler) reviewerFeedbackRead(response http.ResponseWriter, request *http.Request, serviceID controlv1.ServiceID, runID controlv1.ServiceRunID, feedbackID controlv1.FeedbackID) (controlstate.FeedbackThread, controlv1.ReviewerFeedbackReadRequest, bool) {
	var body controlv1.ReviewerFeedbackReadRequest
	if err := decodeJSON(response, request, &body); err != nil || body.RunNumber < 1 || body.PreviewId == "" {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid reviewer feedback request")
		return controlstate.FeedbackThread{}, body, false
	}
	_, token, ok := h.serviceHTTP(response, request)
	if !ok {
		return controlstate.FeedbackThread{}, body, false
	}
	auth := serviceHTTPRun(serviceID, runID, token, body.RunNumber)
	if h.feedback == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "feedback is unavailable")
		return controlstate.FeedbackThread{}, body, false
	}
	actor, err := feedbackReviewerActor(body.Access)
	if err != nil {
		writeControlStateProblem(request.Context(), response, "verify feedback reviewer", err)
		return controlstate.FeedbackThread{}, body, false
	}
	actor, err = h.feedbackBrowserActor(request, auth, actor)
	if err != nil {
		writeFeedbackProblem(request.Context(), response, "verify signed-in reviewer", err)
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

func (h *handler) readReviewerFeedback(response http.ResponseWriter, request *http.Request, auth controlstate.ServiceHTTPRun, id string, actor controlstate.FeedbackActor) (controlstate.FeedbackThread, bool) {
	thread, err := h.feedback.GetFeedback(request.Context(), id)
	if err != nil {
		writeControlStateProblem(request.Context(), response, "read reviewer feedback", err)
		return controlstate.FeedbackThread{}, false
	}
	_, service, err := h.feedback.ReviewerFeedbackScope(request.Context(), auth, thread.PreviewID, actor, time.Now())
	if err != nil {
		writeFeedbackProblem(request.Context(), response, "verify reviewer feedback access", err)
		return controlstate.FeedbackThread{}, false
	}
	if thread.ServiceID != service || thread.ServiceID != auth.Subject.ID {
		writeProblem(response, http.StatusNotFound, controlv1.NotFound, "resource not found")
		return controlstate.FeedbackThread{}, false
	}
	return thread, true
}
