package controlapi

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type PublisherGroupStore interface {
	RevokePublisherGroupMember(context.Context, string, string, string, string, string, time.Time) error
	IssuePublisherGroupEnrollment(context.Context, string, string, string, string, int, time.Duration, time.Time) (controlstate.PublisherGroupEnrollment, error)
	RedeemPublisherGroupEnrollment(context.Context, string, ed25519.PublicKey, time.Time) (controlstate.PublisherGroupMember, error)
	AcquirePublisherGroupLease(context.Context, string, string, string, string, time.Time) (controlstate.PublisherGroupLease, error)
	VerifyPublisherGroupIdentity(context.Context, string, string, string, string, time.Time) (controlstate.PublisherGroupVerification, error)
	GetPublisherGroupAssignments(context.Context, string, time.Time) (controlstate.PublisherGroupAssignments, error)
	AcknowledgePublisherGroupConfiguration(context.Context, string, int64, string, bool, time.Time) error
}

func (h *handler) RevokePublisherGroupMember(w http.ResponseWriter, r *http.Request, project, group, publisher string, params controlv1.RevokePublisherGroupMemberParams) {
	store, ok := h.publisherGroupStore(w)
	if !ok {
		return
	}
	actor, ok := h.projectManager(w, r, params.TeamId)
	if !ok {
		return
	}
	if err := store.RevokePublisherGroupMember(r.Context(), params.TeamId, project, group, publisher, actor, time.Now()); err != nil {
		projectConfigurationProblem(w, "revoke publisher group member", err)
		return
	}
	w.WriteHeader(204)
}

func (h *handler) publisherGroupStore(w http.ResponseWriter) (PublisherGroupStore, bool) {
	store, ok := h.store.(PublisherGroupStore)
	if !ok {
		writeProblem(w, 503, controlv1.Unavailable, "publisher groups are unavailable")
	}
	w.Header().Set("Cache-Control", "no-store")
	return store, ok
}

func (h *handler) CreatePublisherGroupEnrollment(w http.ResponseWriter, r *http.Request, project, group string) {
	store, ok := h.publisherGroupStore(w)
	if !ok {
		return
	}
	var body controlv1.CreatePublisherGroupEnrollmentRequest
	if decodeJSON(w, r, &body) != nil || body.MaxMembers < 1 || body.MaxMembers > 256 || body.ExpiresIn < 60 || body.ExpiresIn > 86400 {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid publisher group enrollment")
		return
	}
	actor, ok := h.projectManager(w, r, body.TeamId)
	if !ok {
		return
	}
	result, err := store.IssuePublisherGroupEnrollment(r.Context(), body.TeamId, project, group, actor, body.MaxMembers, time.Duration(body.ExpiresIn)*time.Second, time.Now())
	if err != nil {
		if errors.Is(err, controlstate.ErrPublisherGroup) {
			writeProblem(w, 404, controlv1.NotFound, "publisher group not found")
			return
		}
		projectConfigurationProblem(w, "issue publisher group enrollment", err)
		return
	}
	writeJSON(w, 201, result)
}

func (h *handler) RedeemPublisherGroupEnrollment(w http.ResponseWriter, r *http.Request) {
	store, ok := h.publisherGroupStore(w)
	if !ok {
		return
	}
	var body controlv1.RedeemPublisherGroupEnrollmentRequest
	if decodeJSON(w, r, &body) != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid publisher group enrollment")
		return
	}
	public, err := base64.RawURLEncoding.Strict().DecodeString(body.PublicKey)
	if err != nil || len(public) != ed25519.PublicKeySize {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid Ed25519 public key")
		return
	}
	result, err := store.RedeemPublisherGroupEnrollment(r.Context(), body.EnrollmentKey, public, time.Now())
	if err != nil {
		projectConfigurationProblem(w, "redeem publisher group enrollment", err)
		return
	}
	writeJSON(w, 200, result)
}

func (h *handler) AcquirePublisherGroupLease(w http.ResponseWriter, r *http.Request) {
	store, ok := h.publisherGroupStore(w)
	if !ok {
		return
	}
	if h.config.ControlURL == "" {
		writeProblem(w, 503, controlv1.Unavailable, "publisher group assertion audience is unavailable")
		return
	}
	var body controlv1.PublisherGroupLeaseRequest
	if decodeJSON(w, r, &body) != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid publisher group assertion")
		return
	}
	result, err := store.AcquirePublisherGroupLease(r.Context(), body.PublisherIdentityId, body.GroupId, body.Assertion, h.config.ControlURL+"/v1/publisher-groups/lease", time.Now())
	if err != nil {
		projectConfigurationProblem(w, "acquire publisher group lease", err)
		return
	}
	writeJSON(w, 200, result)
}

func (h *handler) VerifyPublisherGroupIdentity(w http.ResponseWriter, r *http.Request) {
	store, ok := h.publisherGroupStore(w)
	if !ok {
		return
	}
	if h.config.ControlURL == "" {
		writeProblem(w, 503, controlv1.Unavailable, "publisher group assertion audience is unavailable")
		return
	}
	var body controlv1.PublisherGroupLeaseRequest
	if decodeJSON(w, r, &body) != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid publisher group assertion")
		return
	}
	result, err := store.VerifyPublisherGroupIdentity(r.Context(), body.PublisherIdentityId, body.GroupId, body.Assertion, h.config.ControlURL+"/v1/publisher-groups/verify", time.Now())
	if err != nil {
		projectConfigurationProblem(w, "verify publisher group identity", err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *handler) GetPublisherGroupAssignments(w http.ResponseWriter, r *http.Request) {
	store, ok := h.publisherGroupStore(w)
	if !ok {
		return
	}
	token, ok := requestBearerToken(r)
	if !ok {
		writeBearerProblem(w)
		return
	}
	result, err := store.GetPublisherGroupAssignments(r.Context(), token, time.Now())
	if err != nil {
		projectConfigurationProblem(w, "get publisher group assignments", err)
		return
	}
	writeJSON(w, 200, result)
}

func (h *handler) AcknowledgePublisherGroupConfiguration(w http.ResponseWriter, r *http.Request) {
	store, ok := h.publisherGroupStore(w)
	if !ok {
		return
	}
	token, ok := requestBearerToken(r)
	if !ok {
		writeBearerProblem(w)
		return
	}
	var body controlv1.PublisherGroupAcknowledgement
	if decodeJSON(w, r, &body) != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid publisher group acknowledgement")
		return
	}
	if err := store.AcknowledgePublisherGroupConfiguration(r.Context(), token, body.Revision, body.ConfigurationHash, body.Healthy, time.Now()); err != nil {
		projectConfigurationProblem(w, "acknowledge publisher group configuration", err)
		return
	}
	w.WriteHeader(204)
}
