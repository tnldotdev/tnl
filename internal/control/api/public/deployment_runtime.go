package public

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type DeploymentRuntimeStore interface {
	RedeemDeploymentPublisherEnrollment(context.Context, string, ed25519.PublicKey, time.Time) (controlstate.DeploymentPublisherIdentity, error)
	AcquireDeploymentPublisherLease(context.Context, string, string, string, string, time.Time) (controlstate.DeploymentPublisherLease, error)
	VerifyDeploymentIdentity(context.Context, string, string, string, string, time.Time) (controlstate.DeploymentPublisherVerification, error)
	GetDeploymentPublisherAssignments(context.Context, string, time.Time) (controlstate.DeploymentPublisherAssignments, error)
	AcknowledgeDeploymentPublisherConfiguration(context.Context, string, int64, string, bool, time.Time) error
}

func (h *handler) RenameDeploymentNamespace(w http.ResponseWriter, r *http.Request, project, deployment string) {
	w.Header().Set("Cache-Control", "no-store")
	var body controlv1.RenameDeploymentNamespaceRequest
	if decodeJSON(w, r, &body) != nil {
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "invalid deployment DNS namespace rename")
		return
	}
	actor, ok := h.projectManager(w, r, body.TeamId)
	if !ok {
		return
	}
	store, ok := h.dependencies.Deployments, h.dependencies.Deployments != nil
	if !ok {
		writeProblem(w, http.StatusServiceUnavailable, controlv1.Unavailable, "deployment DNS namespace rename is unavailable")
		return
	}
	result, err := store.RenameDeploymentNamespace(r.Context(), controlstate.RenameDeploymentNamespaceRequest{TeamID: body.TeamId, ProjectKey: project, Deployment: deployment, NamespaceLabel: body.NamespaceLabel, ExpectedRevision: body.ExpectedRevision, IdempotencyKey: body.IdempotencyKey, ActorID: actor, DNSAutomation: h.config.DNSAutomation, Now: time.Now()})
	if err != nil {
		projectConfigurationProblem(r.Context(), w, "rename deployment DNS namespace", err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *handler) RenameDeployment(w http.ResponseWriter, r *http.Request, project, deployment string) {
	w.Header().Set("Cache-Control", "no-store")
	var body controlv1.RenameDeploymentRequest
	if decodeJSON(w, r, &body) != nil {
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "invalid deployment rename")
		return
	}
	actor, ok := h.projectManager(w, r, body.TeamId)
	if !ok {
		return
	}
	store, ok := h.dependencies.Deployments, h.dependencies.Deployments != nil
	if !ok {
		writeProblem(w, http.StatusServiceUnavailable, controlv1.Unavailable, "deployment rename is unavailable")
		return
	}
	result, err := store.RenameDeployment(r.Context(), body.TeamId, project, deployment, body.Name, actor, body.ExpectedRevision, time.Now())
	if err != nil {
		projectConfigurationProblem(r.Context(), w, "rename deployment", err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *handler) deploymentPublisherStore(w http.ResponseWriter) (DeploymentRuntimeStore, bool) {
	store, ok := h.dependencies.DeploymentRuntime, h.dependencies.DeploymentRuntime != nil
	if !ok {
		writeProblem(w, 503, controlv1.Unavailable, "deployments are unavailable")
	}
	w.Header().Set("Cache-Control", "no-store")
	return store, ok
}

func (h *handler) RedeemDeploymentPublisherEnrollment(w http.ResponseWriter, r *http.Request) {
	store, ok := h.deploymentPublisherStore(w)
	if !ok {
		return
	}
	var body controlv1.RedeemDeploymentPublisherEnrollmentRequest
	if decodeJSON(w, r, &body) != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid deployment enrollment")
		return
	}
	public, err := base64.RawURLEncoding.Strict().DecodeString(body.PublicKey)
	if err != nil || len(public) != ed25519.PublicKeySize {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid Ed25519 public key")
		return
	}
	result, err := store.RedeemDeploymentPublisherEnrollment(r.Context(), body.EnrollmentKey, public, time.Now())
	if err != nil {
		projectConfigurationProblem(r.Context(), w, "redeem deployment enrollment", err)
		return
	}
	writeJSON(w, 200, result)
}

func (h *handler) AcquireDeploymentPublisherLease(w http.ResponseWriter, r *http.Request) {
	store, ok := h.deploymentPublisherStore(w)
	if !ok {
		return
	}
	if h.config.ControlURL == "" {
		writeProblem(w, 503, controlv1.Unavailable, "deployment assertion audience is unavailable")
		return
	}
	var body controlv1.DeploymentPublisherLeaseRequest
	if decodeJSON(w, r, &body) != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid deployment assertion")
		return
	}
	result, err := store.AcquireDeploymentPublisherLease(r.Context(), body.PublisherIdentityId, body.DeploymentId, body.Assertion, h.config.ControlURL+"/v1/publisher/deployments/lease", time.Now())
	if err != nil {
		projectConfigurationProblem(r.Context(), w, "acquire deployment lease", err)
		return
	}
	writeJSON(w, 200, result)
}

func (h *handler) VerifyDeploymentIdentity(w http.ResponseWriter, r *http.Request) {
	store, ok := h.deploymentPublisherStore(w)
	if !ok {
		return
	}
	if h.config.ControlURL == "" {
		writeProblem(w, 503, controlv1.Unavailable, "deployment assertion audience is unavailable")
		return
	}
	var body controlv1.DeploymentPublisherLeaseRequest
	if decodeJSON(w, r, &body) != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid deployment assertion")
		return
	}
	result, err := store.VerifyDeploymentIdentity(r.Context(), body.PublisherIdentityId, body.DeploymentId, body.Assertion, h.config.ControlURL+"/v1/publisher/deployments/verify", time.Now())
	if err != nil {
		projectConfigurationProblem(r.Context(), w, "verify deployment identity", err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *handler) GetDeploymentPublisherAssignments(w http.ResponseWriter, r *http.Request) {
	store, ok := h.deploymentPublisherStore(w)
	if !ok {
		return
	}
	token, ok := requestBearerToken(r)
	if !ok {
		writeBearerProblem(w)
		return
	}
	result, err := store.GetDeploymentPublisherAssignments(r.Context(), token, time.Now())
	if err != nil {
		projectConfigurationProblem(r.Context(), w, "get deployment assignments", err)
		return
	}
	writeJSON(w, 200, result)
}

func (h *handler) AcknowledgeDeploymentPublisherConfiguration(w http.ResponseWriter, r *http.Request) {
	store, ok := h.deploymentPublisherStore(w)
	if !ok {
		return
	}
	token, ok := requestBearerToken(r)
	if !ok {
		writeBearerProblem(w)
		return
	}
	var body controlv1.DeploymentPublisherAcknowledgement
	if decodeJSON(w, r, &body) != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid deployment acknowledgement")
		return
	}
	if err := store.AcknowledgeDeploymentPublisherConfiguration(r.Context(), token, body.Revision, body.ConfigurationHash, body.Healthy, time.Now()); err != nil {
		projectConfigurationProblem(r.Context(), w, "acknowledge deployment configuration", err)
		return
	}
	w.WriteHeader(204)
}
