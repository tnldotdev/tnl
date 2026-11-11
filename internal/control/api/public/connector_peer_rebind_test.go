package public

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type connectorRebindTestStore struct {
	ConnectorPeerPairStore
	call func(context.Context, string, string, controlstate.ConnectorPeerPairRebindRequest, time.Time) (controlstate.ConnectorPeerPairRebindState, error)
}

func (s connectorRebindTestStore) RebindConnectorPeerPair(ctx context.Context, service, pair string, request controlstate.ConnectorPeerPairRebindRequest, at time.Time) (controlstate.ConnectorPeerPairRebindState, error) {
	return s.call(ctx, service, pair, request, at)
}

func TestConnectorPeerRebindHTTPPreservesSignedOwnerAndClassifiesAuthority(t *testing.T) {
	const service, pair = "svc_1234567890123456789012", "cpp_1234567890123456789012"
	workload := "wls_1234567890123456789012"
	body := controlv1.ConnectorPeerPairRebindRequest{Phase: controlv1.ConnectorPeerPairInspect, ExpectedGeneration: 7, IdempotencyKey: "retained-owner", RequestedAt: time.Now().UTC().Truncate(time.Microsecond), ServiceRunId: "srun_1234567890123456789012", RunNumber: 3,
		PublisherIdentityId: "pub_1234567890123456789012", TrustRevision: 9, Subject: controlv1.VisitorSubject{Kind: controlv1.WorkloadSession, WorkloadSessionId: &workload},
		Source: json.RawMessage(`{"kind":"workload","credential":"wlc_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`)}
	proof, err := controlv1.ConnectorPeerPairRebindProof(service, pair, body)
	if err != nil {
		t.Fatal(err)
	}
	message, err := proof.Message()
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	body.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, message))
	for _, test := range []struct {
		name   string
		err    error
		status int
	}{
		{"inspect", nil, http.StatusOK},
		{"stale network", controlstate.ErrConnectorPeerBindingStale, http.StatusConflict},
		{"revoked", controlstate.ErrServiceAccess, http.StatusForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			called := false
			store := connectorRebindTestStore{call: func(_ context.Context, gotService, gotPair string, request controlstate.ConnectorPeerPairRebindRequest, at time.Time) (controlstate.ConnectorPeerPairRebindState, error) {
				called = true
				got, err := request.Proof.Message()
				if err != nil || !bytes.Equal(got, message) || !ed25519.Verify(key.Public().(ed25519.PublicKey), got, request.Signature) || gotService != service || gotPair != pair || at.IsZero() {
					t.Fatal("HTTP adapter changed the signed owner or proof", err)
				}
				if _, ok := request.Source.(controlstate.WorkloadTokenSource); !ok {
					t.Fatal("HTTP adapter changed the subject's credential kind")
				}
				return controlstate.ConnectorPeerPairRebindState{HighWaterGeneration: 7}, test.err
			}}
			handler := testHandler(t, Config{}, nil, nil, nil, Stores{ConnectorPeerPairs: store})
			wire, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/services/"+service+"/connector-peer-pairs/"+pair+"/rebind", bytes.NewReader(wire)))
			if !called || response.Code != test.status || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("unexpected signed rebind response", called, response.Code)
			}
			if test.err == nil {
				var state controlv1.ConnectorPeerPairRebindState
				if err := json.Unmarshal(response.Body.Bytes(), &state); err != nil || state.HighWaterGeneration != 7 || state.ReadyRelays == nil {
					t.Fatal("inspection response lost its high-water or empty relay selection", err)
				}
			}
		})
	}
}

func TestConnectorPeerRebindStrictHTTPAndSourceBoundary(t *testing.T) {
	identity, device := "ident_1234567890123456789012", "vdev_1234567890123456789012"
	body := controlv1.ConnectorPeerPairRebindRequest{Phase: controlv1.ConnectorPeerPairInspect, ExpectedGeneration: 1, IdempotencyKey: "owner", RequestedAt: time.Now(), ServiceRunId: "srun_1234567890123456789012", RunNumber: 1,
		PublisherIdentityId: "pub_1234567890123456789012", TrustRevision: 1, Subject: controlv1.VisitorSubject{Kind: controlv1.HumanDevice, IdentityId: &identity, DeviceId: &device},
		Source: json.RawMessage(`{"kind":"device","device_id":"vdev_abcdefghijklmnopqrstuv"}`), Signature: base64.RawURLEncoding.EncodeToString(make([]byte, 64))}
	for _, test := range []struct {
		name   string
		input  any
		status int
	}{
		{"missing body", nil, 400}, {"source does not match signed subject", body, 403},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler := testHandler(t, Config{}, nil, nil, nil)
			response := httptest.NewRecorder()
			var wire []byte
			if test.input != nil {
				wire, _ = json.Marshal(test.input)
			}
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/services/svc_1234567890123456789012/connector-peer-pairs/cpp_1234567890123456789012/rebind", bytes.NewReader(wire)))
			if response.Code != test.status || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal(response.Code, response.Body.String())
			}
		})
	}
}

func TestConnectorPeerRebindDenialPrecedesStale(t *testing.T) {
	for _, err := range []error{controlstate.ErrServiceAccess, controlstate.ErrVisitorPermission, controlstate.ErrWorkloadDenied} {
		response := httptest.NewRecorder()
		connectorPairProblem(t.Context(), response, errors.Join(controlstate.ErrConnectorPeerBindingStale, err))
		if response.Code != http.StatusForbidden {
			t.Fatal("denial became retryable", response.Code)
		}
	}
}
