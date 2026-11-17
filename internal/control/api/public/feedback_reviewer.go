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
		if access.ShareId == nil || !opaqueid.Valid(*access.ShareId, opaqueid.SharePrefix) || (access.ShareSecret == nil) == (access.CookieSecret == nil) {
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
		if httpjson.Decode(json.NewDecoder(bytes.NewReader(raw)), &proof) != nil || proof.Kind != controlv1.FeedbackVisitBearer || len(proof.Token) == 0 || len(proof.Token) > 2048 {
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
		return controlstate.FeedbackConnectorVisitProof{PairID: proof.PairId, DeliveryGeneration: proof.DeliveryGeneration, PermissionToken: visitortoken.Token(proof.PermissionToken)}, nil
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

func (h *handler) AuthorizeReviewerFeedback(w http.ResponseWriter, r *http.Request, service controlv1.ServiceID, run controlv1.ServiceRunID) {
	var body controlv1.AuthorizeReviewerFeedbackRequest
	if decodeJSON(w, r, &body) != nil || body.RunNumber < 1 || !body.Operation.Valid() || body.Operation == "update" || body.Operation == "delete" {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid feedback authorization")
		return
	}
	_, token, ok := h.serviceHTTP(w, r)
	if !ok {
		return
	}
	auth := serviceHTTPRun(service, run, token, body.RunNumber)
	if h.feedback == nil {
		writeProblem(w, 503, controlv1.Unavailable, "feedback authorization is unavailable")
		return
	}
	actor, err := feedbackReviewerActor(body.Access)
	if err != nil {
		writeFeedbackProblem(r.Context(), w, "verify feedback reviewer", err)
		return
	}
	actor, err = h.feedbackBrowserActor(r, auth, actor)
	if err != nil {
		writeFeedbackProblem(r.Context(), w, "verify signed-in reviewer", err)
		return
	}
	decision, err := h.feedback.AuthorizeReviewerFeedback(r.Context(), auth, body.PreviewId, string(body.Operation), actor, time.Now())
	if err != nil {
		writeFeedbackProblem(r.Context(), w, "authorize reviewer feedback", err)
		return
	}
	writeJSON(w, 200, decision)
}
