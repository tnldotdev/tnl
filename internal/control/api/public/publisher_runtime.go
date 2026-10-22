package public

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/policy/publisherprovenance"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (h *handler) ObservePublisherRuntime(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	store, ok := h.store.(interface {
		PublisherRuntime(context.Context, controlstate.PublisherRuntimeRequest) (controlstate.PublisherRuntimeResponse, error)
	})
	if !ok || h.config.ControlURL == "" {
		writeProblem(w, http.StatusServiceUnavailable, controlv1.Unavailable, "publisher runtime observation is unavailable")
		return
	}
	var b controlv1.PublisherRuntimeRequest
	if decodeJSONLimited(w, r, &b, 8192) != nil || !b.Action.Valid() || publisherprovenance.Validate(b.Deployment) != nil {
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "invalid publisher runtime request")
		return
	}
	if b.Action == controlv1.RuntimeStart && !h.acceptingNewWork(w) {
		return
	}
	// controlproxy replaces RemoteAddr only after trusted-peer validation. raw
	// forwarding headers are never source evidence at this handler boundary.
	source, _, _ := net.SplitHostPort(r.RemoteAddr)
	result, err := store.PublisherRuntime(r.Context(), controlstate.PublisherRuntimeRequest{PublisherIdentityID: b.PublisherIdentityId, ScopeID: b.ScopeId, ProcessRunID: b.ProcessRunId, Action: string(b.Action), Assertion: b.Assertion, ExpectedEpoch: b.ExpectedEpoch, Audience: h.config.ControlURL + "/v1/publisher-runtime", SourceIP: source, Now: time.Now(), Deployment: b.Deployment})
	if errors.Is(err, controlstate.ErrPublisherDeploymentConflict) {
		writeProblem(w, http.StatusConflict, controlv1.Conflict, "publisher deployment binding conflicts with the recorded replica")
		return
	}
	if errors.Is(err, controlstate.ErrPublisherRuntimeStale) {
		writeProblem(w, http.StatusConflict, controlv1.Conflict, "publisher runtime has been replaced or stopped")
		return
	}
	if err != nil {
		publisherProblem(w, "observe publisher runtime", err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func runtimeResponse(s *controlstate.PublisherRuntimeStatus) *controlv1.PublisherRuntimeStatus {
	if s == nil {
		return nil
	}
	r := &controlv1.PublisherRuntimeStatus{PublisherIdentityId: s.PublisherIdentityID, TeamId: s.TeamID, ProcessRunId: s.ProcessRunID, Epoch: s.Epoch, Evidence: controlv1.PublisherRuntimeStatusEvidence(s.Evidence), AddressFamily: controlv1.PublisherRuntimeStatusAddressFamily(s.AddressFamily), StartedAt: s.StartedAt, ObservedAt: s.ObservedAt, LastSeenAt: s.LastSeenAt, LeaseExpiresAt: s.LeaseExpiresAt, StoppedAt: s.StoppedAt, Active: s.Active, Deployment: s.Deployment}
	if s.Address != "" {
		r.Address = &s.Address
	}
	return r
}
