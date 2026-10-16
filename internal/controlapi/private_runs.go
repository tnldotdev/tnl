package controlapi

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type privateRunStore interface {
	PreparePrivateServiceRun(context.Context, string, controlstate.PublisherIdentity, string, time.Time) (controlstate.PrivateRunPreparation, error)
	BindPrivateServiceRunKey(context.Context, string, string, int64, controlstate.PublisherIdentity, ed25519.PublicKey, []byte, time.Time) (controlstate.PrivateRunState, error)
	HeartbeatPrivateServiceRun(context.Context, string, string, string, time.Time) (controlstate.PrivateRunState, error)
	ClosePrivateServiceRun(context.Context, string, string, string, time.Time) error
}

func (h *handler) privateRuns(w http.ResponseWriter) (privateRunStore, bool) {
	store, ok := h.store.(privateRunStore)
	if !ok {
		writeProblem(w, 503, controlv1.Unavailable, "private service runs are unavailable")
	}
	return store, ok
}

func privateRunProblem(w http.ResponseWriter, operation string, err error) {
	if errors.Is(err, controlstate.ErrInsufficientRelayServices) {
		writeProblem(w, 503, controlv1.Unavailable, "two live relay services are required")
		return
	}
	privateVisitorError(w, operation, err)
}

func privateRunConnections(rows []controlstate.PrivateRunAssignment) []controlv1.ConnectionAssignment {
	result := make([]controlv1.ConnectionAssignment, 0, len(rows))
	for _, row := range rows {
		result = append(result, controlv1.ConnectionAssignment{
			PublisherConnectionId: row.PublisherConnectionID,
			ConnectionSlot:        int(row.ConnectionSlot), ConnectionAssignmentRevision: row.Revision,
			PublisherConnectionCredential:          row.Credential,
			PublisherConnectionCredentialExpiresAt: row.CredentialExpiresAt,
			RelayServiceId:                         row.RelayServiceID, RelayAddress: row.RelayAddress,
			TlsServerName: row.TLSServerName, State: controlv1.PublisherConnectionState(row.State),
		})
	}
	return result
}

func (h *handler) PreparePrivateServiceRun(w http.ResponseWriter, r *http.Request, serviceID controlv1.PrivateServiceID, _ controlv1.PreparePrivateServiceRunParams) {
	if r.Header.Get("Idempotency-Key") == "" {
		writeProblem(w, 400, controlv1.InvalidRequest, "idempotency key is required")
		return
	}
	_, publisher, ok := h.authenticatePublisher(w, r)
	if !ok {
		return
	}
	store, ok := h.privateRuns(w)
	if !ok {
		return
	}
	prepared, err := store.PreparePrivateServiceRun(r.Context(), serviceID, publisher, r.Header.Get("Idempotency-Key"), time.Now())
	if err != nil {
		privateRunProblem(w, "prepare private service run", err)
		return
	}
	writeJSON(w, 201, controlv1.PrivateServiceRunPreparation{
		TeamId: prepared.TeamID, PrivateServiceId: prepared.ServiceID,
		PrivateRunId: prepared.RunID, RunNumber: prepared.RunNumber,
		PublisherIdentityId: prepared.PublisherIdentityID, PublisherGrantId: prepared.PublisherGrantID,
		PublisherKeyId: prepared.PublisherKeyID, IdempotencyKey: prepared.IdempotencyKey,
		BindingNonce: hex.EncodeToString(prepared.Nonce), ExpiresAt: prepared.ExpiresAt,
	})
}

func (h *handler) BindPrivateServiceRunKey(w http.ResponseWriter, r *http.Request, serviceID controlv1.PrivateServiceID, runID controlv1.PrivateRunID) {
	var body controlv1.BindPrivateServiceRunKeyRequest
	if decodeJSON(w, r, &body) != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid private run binding")
		return
	}
	public, keyErr := hex.DecodeString(body.StreamPublicKey)
	signature, sigErr := base64.RawURLEncoding.Strict().DecodeString(body.BindingSignature)
	if keyErr != nil || sigErr != nil || len(public) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize ||
		hex.EncodeToString(public) != body.StreamPublicKey || body.RunNumber < 1 {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid publisher key or signature")
		return
	}
	_, publisher, ok := h.authenticatePublisher(w, r)
	if !ok {
		return
	}
	store, ok := h.privateRuns(w)
	if !ok {
		return
	}
	bound, err := store.BindPrivateServiceRunKey(r.Context(), serviceID, runID, body.RunNumber, publisher, public, signature, time.Now())
	if err != nil {
		privateRunProblem(w, "bind private service run", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, controlv1.PrivateServiceRunSetup{
		PrivateServiceId: bound.ServiceID, PrivateRunId: bound.RunID, RunNumber: bound.RunNumber,
		StreamPublicKey: hex.EncodeToString(bound.PublicKey), RunToken: bound.Token,
		PublisherConnections: privateRunConnections(bound.Connections),
	})
}

func (h *handler) HeartbeatPrivateServiceRun(w http.ResponseWriter, r *http.Request, serviceID controlv1.PrivateServiceID, runID controlv1.PrivateRunID) {
	token, ok := requestBearerToken(r)
	if !ok {
		writeBearerProblem(w)
		return
	}
	store, ok := h.privateRuns(w)
	if !ok {
		return
	}
	state, err := store.HeartbeatPrivateServiceRun(r.Context(), serviceID, runID, token, time.Now())
	if err != nil {
		privateRunProblem(w, "heartbeat private service run", err)
		return
	}
	writeJSON(w, 200, controlv1.PrivateServiceRunState{
		PrivateServiceId: state.ServiceID, PrivateRunId: state.RunID, RunNumber: state.RunNumber,
		State: controlv1.PrivateServiceRunStateState(state.State), PublisherExpiresAt: state.ExpiresAt,
		StreamPublicKey: hex.EncodeToString(state.PublicKey), PublisherConnections: privateRunConnections(state.Connections),
	})
}

func (h *handler) ClosePrivateServiceRun(w http.ResponseWriter, r *http.Request, serviceID controlv1.PrivateServiceID, runID controlv1.PrivateRunID) {
	token, ok := requestBearerToken(r)
	if !ok {
		writeBearerProblem(w)
		return
	}
	store, ok := h.privateRuns(w)
	if !ok {
		return
	}
	if err := store.ClosePrivateServiceRun(r.Context(), serviceID, runID, token, time.Now()); err != nil {
		privateRunProblem(w, "close private service run", err)
		return
	}
	w.WriteHeader(204)
}
