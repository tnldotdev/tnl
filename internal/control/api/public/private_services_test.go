package controlapi

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
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type privateSelectionResponseStore struct {
	PublicURLStore
	privateVisitorStore
	issued controlstate.PrivateServiceSelection
}

func (s privateSelectionResponseStore) SelectPrivateServiceRun(_ context.Context, serviceID, identityID, deviceID string, _ time.Time) (controlstate.PrivateServiceSelection, error) {
	if serviceID != s.issued.PrivateServiceID || deviceID != s.issued.DeviceID || identityID != s.issued.IdentityID {
		panic("run selected for the wrong authenticated scope")
	}
	return s.issued, nil
}

func TestPrivateSelectionReturnsManagedEndpointWithoutStreamCrypto(t *testing.T) {
	service, _ := opaqueid.New(opaqueid.PrivateServicePrefix)
	device, _ := opaqueid.New("vdev_")
	store := privateSelectionResponseStore{issued: controlstate.PrivateServiceSelection{
		Subject:                tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, DeviceID: device, IdentityID: testPublicURLReadPrincipal().identityID},
		PrivateServiceMetadata: controlstate.PrivateServiceMetadata{Protocol: "tcp", TrustRevision: 1, ManagedTLS: &controlstate.ManagedServiceTLS{Hostname: "service.worktree.member.example.test", Port: 25443}},
		PrivateServiceID:       service, DeviceID: device, IdentityID: testPublicURLReadPrincipal().identityID,
		PrivateRunID: "psrun_0123456789ABCDEFGHIJKL",
		ExpiresAt:    time.Now().Add(time.Minute), RunNumber: 1,
	}}
	h := &handler{store: store, authorizer: &recordingAuthorizer{principal: testPublicURLReadPrincipal()}}
	r := httptest.NewRequest(http.MethodPost, "/v1/private-services/"+service+"/select-run", strings.NewReader(`{"device_id":"`+device+`"}`))
	r.Header.Set("Authorization", "Bearer access-token")
	w := httptest.NewRecorder()
	h.SelectPrivateServiceRun(w, r, service)
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
	var parsed controlv1.PrivateServiceSelection
	if err := json.Unmarshal(w.Body.Bytes(), &parsed); err != nil || parsed.ManagedTls == nil || parsed.ManagedTls.Hostname != store.issued.ManagedTLS.Hostname || parsed.ManagedTls.Port != 25443 {
		t.Fatalf("generated response contract = %+v: %v", parsed, err)
	}
}
