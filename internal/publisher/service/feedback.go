//go:build !js || !wasm

package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	servicestream "github.com/tnldotdev/tnl/internal/publisher/service/stream"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/transport/httpstream"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// nativeHTTP holds the optional feedback runtime on the shared service frontend.
type nativeHTTP struct{ feedback feedbackFrontend }

type FeedbackClient interface {
	AuthorizeReviewerFeedback(context.Context, string, string, controlv1.AuthorizeReviewerFeedbackRequest, credentials.ServiceRunToken) (controlv1.FeedbackAuthorization, error)
}

// feedbackFrontend adds the toolbar and feedback routes to a native service run.
// the service checks visitor access before handing a request to it.
type feedbackFrontend interface {
	handle(http.ResponseWriter, *http.Request, feedbackAuthorization) bool
	prepareBrowser(http.ResponseWriter, *http.Request) *http.Request
	responseHooks(httpstream.ResponseHooks) httpstream.ResponseHooks
	close(context.Context) error
}

func (f *HTTP) prepareNativeHTTP(ctx context.Context) error {
	if !f.Demo {
		return nil
	}
	// use the preview control assigned to this run, not a caller-supplied id.
	// validate it before setting up the browser and feedback handlers.
	preview, err := f.Control.CreateServiceRunPreview(ctx, f.Subject.ID, f.RunID, f.Number, f.Token)
	if err != nil {
		return fmt.Errorf("service: create demo feedback preview: %w", err)
	}
	if !opaqueid.Valid(preview.Id, opaqueid.PreviewPrefix) || preview.SchemaVersion != 1 ||
		len(preview.ServiceIds) != 1 || preview.ServiceIds[0] != f.Subject.ID {
		return failure.Wrap("create demo feedback preview", failure.ServerResponseInvalid,
			errors.New("preview has an invalid ID, schema, or service membership"))
	}
	f.PreviewID = preview.Id
	return nil
}

func (f *HTTP) startNativeHTTP() error {
	f.browser.PreviewID = f.PreviewID
	runtime, err := newFeedbackRuntime(*f)
	if err != nil || runtime == nil {
		return err
	}
	f.feedback = runtime
	f.ResponseHooks = runtime.responseHooks(f.ResponseHooks)
	return nil
}

func (f HTTP) closeNativeHTTP(ctx context.Context) error {
	if f.feedback != nil {
		return f.feedback.close(ctx)
	}
	return nil
}

func (f HTTP) prepareNativeApplication(w http.ResponseWriter, r *http.Request) *http.Request {
	if f.feedback != nil {
		return f.feedback.prepareBrowser(w, r)
	}
	return r
}

func (f HTTP) handleNativeReserved(w http.ResponseWriter, r *http.Request, connector *servicestream.ConnectorHTTPAuthorization) bool {
	status := r.URL.Path == "/__tnl/access" && r.Method == http.MethodGet && f.PreviewID != ""
	if !status && (f.feedback == nil || !strings.HasPrefix(r.URL.Path, "/__tnl/feedback")) {
		return false
	}
	authorization, guard, guarded, err := f.authorizeFeedback(w, r, connector)
	if guard != nil {
		defer guard.Finish()
	}
	if status {
		if err != nil && servicestream.HTTPDecisionStatus(err) != http.StatusForbidden {
			servicestream.DenyHTTP(w, r, servicestream.HTTPDecisionStatus(err))
			return true
		}
		writePreviewAccessStatus(w, previewAccessStatus(f, authorization.permission, err == nil))
		return true
	}
	if err != nil {
		servicestream.DenyHTTP(w, r, servicestream.HTTPDecisionStatus(err))
		return true
	}
	if guard != nil {
		w = guard
	}
	f.feedback.handle(w, guarded, authorization)
	return true
}

func (f HTTP) authorizeFeedback(w http.ResponseWriter, r *http.Request, connector *servicestream.ConnectorHTTPAuthorization) (feedbackAuthorization, *httpaccess.Guard, *http.Request, error) {
	if connector != nil {
		// use the admitted connector identity, not credentials in the HTTP request.
		access, err := connectorFeedbackAuthorization(*connector)
		return access, nil, r, err
	}
	var tokens *httpaccess.Tokens
	if f.browser != nil {
		tokens = f.browser.Tokens
	}
	authorization, guard, guarded, err := httpaccess.AuthorizeRequest(w, r, f.Policy, tokens)
	if err != nil {
		return feedbackAuthorization{permission: authorization.Permission()}, guard, guarded, err
	}
	access, err := bearerFeedbackAuthorization(authorization)
	return access, guard, guarded, err
}

// feedbackAuthorization is supplied by request admission, never browser input.
// only the control wire owner reveals its selected proof.
type feedbackAuthorization struct {
	permission visitortoken.VerifiedPermission
	allowed    bool
	proof      json.RawMessage
}

func (feedbackAuthorization) String() string   { return "feedback authorization" }
func (feedbackAuthorization) GoString() string { return "feedback authorization" }

func bearerFeedbackAuthorization(authorization httpaccess.Authorization) (feedbackAuthorization, error) {
	result := feedbackAuthorization{permission: authorization.Permission(), allowed: true}
	token, bearer := authorization.BearerToken()
	if !bearer {
		if result.permission.Valid() {
			return feedbackAuthorization{}, visitortoken.ErrBinding
		}
		return result, nil
	}
	proof, err := json.Marshal(controlv1.FeedbackBearerVisitProof{Kind: controlv1.FeedbackVisitBearer, Token: token.Reveal()})
	if err != nil {
		return feedbackAuthorization{}, err
	}
	result.proof = proof
	return result, nil
}

func connectorFeedbackAuthorization(authorization servicestream.ConnectorHTTPAuthorization) (feedbackAuthorization, error) {
	proof, err := json.Marshal(controlv1.FeedbackConnectorVisitProof{
		Kind: controlv1.FeedbackVisitConnector, PairId: authorization.PairID,
		DeliveryGeneration: authorization.DeliveryGeneration, PermissionToken: authorization.PermissionToken.Reveal(),
	})
	if err != nil {
		return feedbackAuthorization{}, err
	}
	return feedbackAuthorization{permission: authorization.Permission, allowed: true, proof: proof}, nil
}
