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

type connectorRetirementTestStore struct {
	ConnectorPeerPairStore
	call func(context.Context, string, string, controlstate.ConnectorPeerPairRetireRequest, time.Time) (controlstate.ConnectorPeerPairRetirement, error)
}

func (s connectorRetirementTestStore) RetireConnectorPeerPair(ctx context.Context, service, pair string, request controlstate.ConnectorPeerPairRetireRequest, at time.Time) (controlstate.ConnectorPeerPairRetirement, error) {
	return s.call(ctx, service, pair, request, at)
}

func TestConnectorPeerRetireHTTPBodyOnlyExactProof(t *testing.T) {
	const service, pair = "svc_1234567890123456789012", "cpp_1234567890123456789012"
	at := time.Now().UTC().Truncate(time.Microsecond)
	body := controlv1.ConnectorPeerPairRetireRequest{ServiceRunId: "srun_1234567890123456789012", RunNumber: 2,
		PublisherIdentityId: "pub_1234567890123456789012", DeliveryId: "AQEBAQEBAQEBAQEBAQEBAQ", IdempotencyKey: "original-owner", RequestedAt: at}
	proof, err := controlv1.ConnectorPeerPairRetireProof(service, pair, body)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	session := bytes.Repeat([]byte{9}, 32)
	mac, err := proof.SessionProof(session)
	if err != nil {
		t.Fatal(err)
	}
	message, err := proof.Message(mac)
	if err != nil {
		t.Fatal(err)
	}
	body.SessionProof, body.Signature = base64.RawURLEncoding.EncodeToString(mac), base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, message))
	wire, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		err    error
		status int
	}{
		{"committed", nil, 200}, {"scope missing or revoked", controlstate.ErrServiceAccess, 403},
		{"changed retry", controlstate.ErrServiceConflict, 409}, {"database failure", errors.New("independent database failure"), 500},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			store := connectorRetirementTestStore{call: func(_ context.Context, gotService, gotPair string, got controlstate.ConnectorPeerPairRetireRequest, now time.Time) (controlstate.ConnectorPeerPairRetirement, error) {
				calls++
				if gotService != service || gotPair != pair || got.Proof != proof || now.IsZero() ||
					got.Proof.VerifySignature(key.Public().(ed25519.PublicKey), got.SessionProof, got.Signature) != nil ||
					got.Proof.VerifySessionProof(session, got.SessionProof) != nil {
					t.Fatal("handler changed exact retirement authentication")
				}
				return controlstate.ConnectorPeerPairRetirement{
					ServiceID: service, PairID: pair, ServiceRunID: body.ServiceRunId, RunNumber: body.RunNumber,
					PublisherIdentityID: body.PublisherIdentityId, DeliveryID: body.DeliveryId, IdempotencyKey: body.IdempotencyKey, OwnerRevision: 2,
					Retirement: controlstate.ConnectorPeerPairRetirementObservation{ObservedAt: at, RetiredAt: at, RetainedUntil: at.Add(time.Minute)},
				}, test.err
			}}
			handler := testHandler(t, Config{}, nil, nil, nil, Stores{ConnectorPeerPairs: store})
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/services/"+service+"/connector-peer-pairs/"+pair+"/retire", bytes.NewReader(wire)))
			if calls != 1 || response.Code != test.status || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("unexpected retirement response", calls, response.Code)
			}
			if test.err == nil {
				var result controlv1.ConnectorPeerPairRetirement
				if json.Unmarshal(response.Body.Bytes(), &result) != nil || result.ValidateFor(service, pair, body) != nil {
					t.Fatal("handler fabricated or changed the committed receipt")
				}
			}
		})
	}
	for _, authorization := range []string{"", "Bearer control", "Bearer workload", "Bearer run"} {
		t.Run("forbidden header "+authorization, func(t *testing.T) {
			response := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "/v1/services/"+service+"/connector-peer-pairs/"+pair+"/retire", bytes.NewReader(wire))
			request.Header["authorization"] = []string{authorization}
			testHandler(t, Config{}, nil, nil, nil).ServeHTTP(response, request)
			if response.Code != http.StatusForbidden {
				t.Fatal("retirement accepted an Authorization header", response.Code)
			}
		})
	}
	for _, bad := range [][]byte{nil, []byte("null"), []byte("{}"), append(bytes.Clone(wire[:len(wire)-1]), []byte(`,"source":{"kind":"device"}}`)...)} {
		response := httptest.NewRecorder()
		testHandler(t, Config{}, nil, nil, nil).ServeHTTP(response,
			httptest.NewRequest(http.MethodPost, "/v1/services/"+service+"/connector-peer-pairs/"+pair+"/retire", bytes.NewReader(bad)))
		if response.Code != http.StatusBadRequest {
			t.Fatal("invalid or parent-authenticated shape reached retirement", response.Code)
		}
	}
}
