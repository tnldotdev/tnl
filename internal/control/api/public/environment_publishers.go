package public

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type EnvironmentPublisherStore interface {
	AuthenticateEnvironmentPublisherManager(context.Context, credentials.AccessToken) (controlstate.EnvironmentPublisherManager, error)
	IssueEnvironmentPublisherEnrollment(context.Context, controlstate.IssueEnvironmentPublisherEnrollmentRequest) (controlstate.EnvironmentPublisherEnrollment, error)
	ListEnvironmentPublishers(context.Context, controlstate.EnvironmentPublisherSelection) ([]controlstate.EnvironmentPublisherStatus, error)
	RevokeEnvironmentPublisher(context.Context, controlstate.EnvironmentPublisherSelection, string, time.Time) error
	RedeemEnvironmentPublisherEnrollment(context.Context, string, ed25519.PublicKey, time.Time) (controlstate.EnvironmentPublisher, error)
	AcquireEnvironmentPublisherLease(context.Context, string, string, string, string, time.Time) (controlstate.EnvironmentPublisherLease, error)
	VerifyEnvironmentPublisher(context.Context, string, string, string, string, time.Time) (controlstate.EnvironmentPublisher, error)
	GetEnvironmentPublisherAssignments(context.Context, string, time.Time) (controlstate.EnvironmentPublisherAssignments, error)
	AcknowledgeEnvironmentPublisher(context.Context, string, controlstate.EnvironmentPublication, bool, time.Time) error
}

func (h *handler) environmentPublisherStore(w http.ResponseWriter) (EnvironmentPublisherStore, bool) {
	w.Header().Set("Cache-Control", "no-store")
	store := h.dependencies.EnvironmentPublishers
	if store == nil {
		writeProblem(w, http.StatusServiceUnavailable, controlv1.Unavailable, "environment publishers are unavailable")
		return nil, false
	}
	return store, true
}

func environmentPublisherSession(w http.ResponseWriter, r *http.Request, store EnvironmentPublisherStore) (controlstate.EnvironmentPublisherManager, bool) {
	token, ok := requestBearerToken(r)
	if !ok {
		writeBearerProblem(w)
		return controlstate.EnvironmentPublisherManager{}, false
	}
	manager, err := store.AuthenticateEnvironmentPublisherManager(r.Context(), credentials.AccessToken(token))
	if err != nil {
		environmentPublisherProblem(r.Context(), w, "authenticate environment publisher manager", err)
		return controlstate.EnvironmentPublisherManager{}, false
	}
	return manager, true
}

func environmentPublisherProblem(ctx context.Context, w http.ResponseWriter, operation string, err error) {
	if errors.Is(err, controlstate.ErrEnvironmentPublisher) || errors.Is(err, controlstate.ErrControlAuthentication) {
		writeBearerProblem(w)
		return
	}
	environmentProblem(ctx, w, operation, err)
}

func (h *handler) CreateEnvironmentPublisherEnrollment(w http.ResponseWriter, r *http.Request, project, environment string, params controlv1.CreateEnvironmentPublisherEnrollmentParams) {
	store, ok := h.environmentPublisherStore(w)
	if !ok {
		return
	}
	if h.config.ControlURL == "" {
		writeProblem(w, http.StatusServiceUnavailable, controlv1.Unavailable, "publisher installation server is unavailable")
		return
	}
	var body controlv1.CreateEnvironmentPublisherEnrollmentRequest
	if decodeJSON(w, r, &body) != nil || body.ExpiresIn < 60 || body.ExpiresIn > 86400 || params.IdempotencyKey != nil && *params.IdempotencyKey == "" {
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "invalid environment publisher enrollment")
		return
	}
	manager, ok := environmentPublisherSession(w, r, store)
	if !ok {
		return
	}
	result, err := store.IssueEnvironmentPublisherEnrollment(r.Context(), controlstate.IssueEnvironmentPublisherEnrollmentRequest{
		EnvironmentPublisherSelection: controlstate.EnvironmentPublisherSelection{TeamID: body.TeamId, ProjectKey: project, EnvironmentID: environment, Manager: manager},
		ExpectedRevision:              body.ExpectedRevision, ExpectedConfigurationHash: body.ConfigurationHash, Services: body.Services, MaxMembers: body.MaxMembers, Lifetime: time.Duration(body.ExpiresIn) * time.Second, Now: time.Now(),
		IdempotencyKey: optionalFeedbackString(params.IdempotencyKey),
	})
	if err != nil {
		environmentPublisherProblem(r.Context(), w, "issue environment publisher enrollment", err)
		return
	}
	writeJSON(w, http.StatusCreated, controlv1.EnvironmentPublisherEnrollment{Ref: controlv1.EnvironmentReference{Server: h.config.ControlURL, ProjectKey: result.ProjectKey, EnvironmentId: result.EnvironmentID}, EnrollmentKey: result.Key, ExpiresAt: result.ExpiresAt, MaxMembers: result.MaxMembers})
}

func (h *handler) ListEnvironmentPublishers(w http.ResponseWriter, r *http.Request, project, environment string, params controlv1.ListEnvironmentPublishersParams) {
	store, ok := h.environmentPublisherStore(w)
	if !ok {
		return
	}
	manager, ok := environmentPublisherSession(w, r, store)
	if !ok {
		return
	}
	result, err := store.ListEnvironmentPublishers(r.Context(), controlstate.EnvironmentPublisherSelection{TeamID: params.TeamId, ProjectKey: project, EnvironmentID: environment, Manager: manager})
	if err != nil {
		environmentPublisherProblem(r.Context(), w, "list environment publishers", err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *handler) RevokeEnvironmentPublisher(w http.ResponseWriter, r *http.Request, project, environment, publisher string, params controlv1.RevokeEnvironmentPublisherParams) {
	store, ok := h.environmentPublisherStore(w)
	if !ok {
		return
	}
	manager, ok := environmentPublisherSession(w, r, store)
	if !ok {
		return
	}
	if err := store.RevokeEnvironmentPublisher(r.Context(), controlstate.EnvironmentPublisherSelection{TeamID: params.TeamId, ProjectKey: project, EnvironmentID: environment, Manager: manager}, publisher, time.Now()); err != nil {
		environmentPublisherProblem(r.Context(), w, "revoke environment publisher", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) RedeemEnvironmentPublisherEnrollment(w http.ResponseWriter, r *http.Request) {
	store, ok := h.environmentPublisherStore(w)
	if !ok {
		return
	}
	var body controlv1.RedeemEnvironmentPublisherEnrollmentRequest
	if decodeJSON(w, r, &body) != nil {
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "invalid environment publisher enrollment")
		return
	}
	public, err := base64.RawURLEncoding.Strict().DecodeString(body.PublicKey)
	if err != nil || len(public) != ed25519.PublicKeySize {
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "invalid Ed25519 public key")
		return
	}
	result, err := store.RedeemEnvironmentPublisherEnrollment(r.Context(), body.EnrollmentKey, public, time.Now())
	if err != nil {
		environmentPublisherProblem(r.Context(), w, "redeem environment publisher enrollment", err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *handler) AcquireEnvironmentPublisherLease(w http.ResponseWriter, r *http.Request) {
	store, ok := h.environmentPublisherStore(w)
	if !ok {
		return
	}
	if h.config.ControlURL == "" {
		writeProblem(w, http.StatusServiceUnavailable, controlv1.Unavailable, "environment publisher assertion audience is unavailable")
		return
	}
	var body controlv1.EnvironmentPublisherProof
	if decodeJSON(w, r, &body) != nil {
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "invalid environment publisher assertion")
		return
	}
	result, err := store.AcquireEnvironmentPublisherLease(r.Context(), body.PublisherIdentityId, body.EnvironmentId, body.Assertion, h.config.ControlURL+"/v1/environment-publishers/lease", time.Now())
	if err != nil {
		environmentPublisherProblem(r.Context(), w, "acquire environment publisher lease", err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *handler) VerifyEnvironmentPublisher(w http.ResponseWriter, r *http.Request) {
	store, ok := h.environmentPublisherStore(w)
	if !ok {
		return
	}
	if h.config.ControlURL == "" {
		writeProblem(w, http.StatusServiceUnavailable, controlv1.Unavailable, "environment publisher assertion audience is unavailable")
		return
	}
	var body controlv1.EnvironmentPublisherProof
	if decodeJSON(w, r, &body) != nil {
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "invalid environment publisher assertion")
		return
	}
	result, err := store.VerifyEnvironmentPublisher(r.Context(), body.PublisherIdentityId, body.EnvironmentId, body.Assertion, h.config.ControlURL+"/v1/environment-publishers/verify", time.Now())
	if err != nil {
		environmentPublisherProblem(r.Context(), w, "verify environment publisher identity", err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *handler) GetEnvironmentPublisherAssignments(w http.ResponseWriter, r *http.Request) {
	store, ok := h.environmentPublisherStore(w)
	if !ok {
		return
	}
	token, ok := requestBearerToken(r)
	if !ok {
		writeBearerProblem(w)
		return
	}
	result, err := store.GetEnvironmentPublisherAssignments(r.Context(), token, time.Now())
	if err != nil {
		environmentPublisherProblem(r.Context(), w, "get environment publisher assignments", err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *handler) AcknowledgeEnvironmentPublisher(w http.ResponseWriter, r *http.Request) {
	store, ok := h.environmentPublisherStore(w)
	if !ok {
		return
	}
	token, ok := requestBearerToken(r)
	if !ok {
		writeBearerProblem(w)
		return
	}
	var body controlv1.EnvironmentPublisherAcknowledgement
	if decodeJSON(w, r, &body) != nil {
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "invalid environment publisher acknowledgement")
		return
	}
	publication := controlstate.EnvironmentPublication{EnvironmentID: body.Environment.EnvironmentId, MutationRevision: body.Environment.MutationRevision, ConfigurationHash: body.Environment.ConfigurationHash}
	if err := store.AcknowledgeEnvironmentPublisher(r.Context(), token, publication, body.Healthy, time.Now()); err != nil {
		environmentPublisherProblem(r.Context(), w, "acknowledge environment publisher", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
