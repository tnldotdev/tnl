package public

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type serviceHeartbeatStore struct {
	PublicURLStore
	serviceRunStore
	service, run, token string
	health              controlstate.ServiceRunHealth
	calls               int
}

func (s *serviceHeartbeatStore) HeartbeatServiceRun(_ context.Context, service, run, token string, now time.Time, health controlstate.ServiceRunHealth) (controlstate.ServiceRunState, error) {
	s.service, s.run, s.token, s.health = service, run, token, health
	s.calls++
	return controlstate.ServiceRunState{ServiceID: service, RunID: run, RunNumber: 1, State: "starting", ExpiresAt: now.Add(45 * time.Second),
		Healthy: health.Healthy, StreamCapacity: health.StreamCapacity, ReportedStreams: health.ActiveStreams}, nil
}

func TestServiceHeartbeatPreservesExplicitHealthAndStreamCounts(t *testing.T) {
	for _, health := range []controlv1.ServiceRunHeartbeat{
		{Healthy: false, StreamCapacity: 7, ActiveStreams: 3},
		{Healthy: true, StreamCapacity: 7, ActiveStreams: 7},
	} {
		store := &serviceHeartbeatStore{}
		h := &handler{store: store}
		body, err := json.Marshal(health)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodPost, "/v1/services/service/runs/run", bytes.NewReader(body))
		r.Header.Set("Authorization", "Bearer run-token")
		w := httptest.NewRecorder()
		h.HeartbeatServiceRun(w, r, "service", "run")
		want := controlstate.ServiceRunHealth{Healthy: health.Healthy, StreamCapacity: health.StreamCapacity, ActiveStreams: health.ActiveStreams}
		if w.Code != 200 || store.calls != 1 || store.service != "service" || store.run != "run" || store.token != "run-token" || store.health != want {
			t.Fatalf("heartbeat changed its authenticated scope or report: status=%d calls=%d health=%+v", w.Code, store.calls, store.health)
		}
		var state controlv1.ServiceRunState
		if err := json.Unmarshal(w.Body.Bytes(), &state); err != nil {
			t.Fatal(err)
		}
		if state.Healthy == nil || *state.Healthy != health.Healthy || state.StreamCapacity == nil || *state.StreamCapacity != health.StreamCapacity || state.ActiveStreams == nil || *state.ActiveStreams != health.ActiveStreams {
			t.Fatalf("heartbeat response lost explicit health or stream counts: %+v", state)
		}
	}
}

type privateSelectionResponseStore struct {
	PublicURLStore
	serviceVisitorStore
	issued controlstate.ServiceSelection
}

func (s privateSelectionResponseStore) SelectServiceRun(_ context.Context, serviceID, identityID, deviceID string, _ time.Time) (controlstate.ServiceSelection, error) {
	if serviceID != s.issued.ServiceID || deviceID != s.issued.DeviceID || identityID != s.issued.IdentityID {
		panic("run selected for the wrong authenticated scope")
	}
	return s.issued, nil
}

func TestPrivateSelectionReturnsServiceEndpointWithoutStreamCrypto(t *testing.T) {
	service, _ := opaqueid.New(opaqueid.ServicePrefix)
	device, _ := opaqueid.New("vdev_")
	store := privateSelectionResponseStore{issued: controlstate.ServiceSelection{
		Subject:         tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, DeviceID: device, IdentityID: testPublicURLReadPrincipal().identityID},
		ServiceMetadata: controlstate.ServiceMetadata{Protocol: "tcp", TrustRevision: 1, Endpoint: &controlstate.ServiceEndpoint{Hostname: "service.worktree.member.example.test", Port: 25443}},
		ServiceID:       service, DeviceID: device, IdentityID: testPublicURLReadPrincipal().identityID,
		ServiceRunID: "srun_0123456789ABCDEFGHIJKL",
		ExpiresAt:    time.Now().Add(time.Minute), RunNumber: 1,
	}}
	h := &handler{store: store, authorizer: &recordingAuthorizer{principal: testPublicURLReadPrincipal()}}
	r := httptest.NewRequest(http.MethodPost, "/v1/services/"+service+"/select-run", strings.NewReader(`{"device_id":"`+device+`"}`))
	r.Header.Set("Authorization", "Bearer access-token")
	w := httptest.NewRecorder()
	h.SelectServiceRun(w, r, service)
	if w.Code != 201 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("selection response: %d %s", w.Code, w.Body.String())
	}
	var raw map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["stream_public_key"]; ok {
		t.Fatal("selection exposed per-run crypto")
	}
	var parsed controlv1.ServiceSelection
	if err := json.Unmarshal(w.Body.Bytes(), &parsed); err != nil || parsed.Endpoint == nil || parsed.Endpoint.Hostname != store.issued.Endpoint.Hostname || parsed.Endpoint.Port != 25443 {
		t.Fatalf("generated response contract = %+v: %v", parsed, err)
	}
}
