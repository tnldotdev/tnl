package public

import (
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

func TestServiceRunCapacityIsRetryableWithoutRevokingVisitor(t *testing.T) {
	w := httptest.NewRecorder()
	serviceVisitorError(w, "select service run", controlstate.ErrServiceRunUnavailable)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("full run response = %d; want a retryable 503", w.Code)
	}
}
