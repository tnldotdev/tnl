package controlv1

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func rebindRequestFixture() ConnectorPeerPairRebindRequest {
	identity, device := "ident_1234567890123456789012", "vdev_1234567890123456789012"
	return ConnectorPeerPairRebindRequest{Phase: ConnectorPeerPairInspect, IdempotencyKey: "pair-one", ExpectedGeneration: 7,
		RequestedAt: time.Date(2026, 1, 2, 3, 4, 5, 123456000, time.UTC), ServiceRunId: "srun_1234567890123456789012", RunNumber: 2,
		PublisherIdentityId: "pub_1234567890123456789012", TrustRevision: 9,
		Subject: VisitorSubject{Kind: HumanDevice, IdentityId: &identity, DeviceId: &device}}
}

func TestConnectorPeerPairRebindProofAdapter(t *testing.T) {
	const service, pair = "svc_1234567890123456789012", "cpp_1234567890123456789012"
	body := rebindRequestFixture()
	message, err := ConnectorPeerPairRebindProofMessage(service, pair, body)
	if err != nil {
		t.Fatal(err)
	}
	want, err := (tunnelv1.ConnectorPeerPairRebindProof{Phase: "inspect", ServiceID: service, PairID: pair,
		IdempotencyKey: body.IdempotencyKey, ExpectedGeneration: body.ExpectedGeneration, RequestedAt: body.RequestedAt,
		ServiceRunID: body.ServiceRunId, RunNumber: body.RunNumber, PublisherIdentityID: body.PublisherIdentityId, TrustRevision: body.TrustRevision,
		Subject: tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, IdentityID: *body.Subject.IdentityId, DeviceID: *body.Subject.DeviceId}}).Message()
	if err != nil || !bytes.Equal(message, want) {
		t.Fatal("HTTP adapter changed native signing bytes", err)
	}
	body.Source, body.Signature = json.RawMessage(`{"kind":"workload","credential":"not-signing-input"}`), "not-signing-input"
	next, err := ConnectorPeerPairRebindProofMessage(service, pair, body)
	if err != nil || !bytes.Equal(next, message) {
		t.Fatal("source or signature entered proof bytes", err)
	}
	for _, edit := range []func(*ConnectorPeerPairRebindRequest){
		func(r *ConnectorPeerPairRebindRequest) { empty := ""; r.Subject.WorkloadSessionId = &empty },
		func(r *ConnectorPeerPairRebindRequest) { r.ExpectedRelays = make([]ConnectorPeerPairRelay, 3) },
		func(r *ConnectorPeerPairRebindRequest) { r.PathProofs = make([]ConnectorPeerPairPathProof, 3) },
		func(r *ConnectorPeerPairRebindRequest) { r.BindingChallenge = "unused" },
	} {
		changed := body
		edit(&changed)
		if _, err := ConnectorPeerPairRebindProofMessage(service, pair, changed); err == nil {
			t.Fatal("invalid HTTP phase or subject signed")
		}
	}
}

func TestConnectorPeerRebindGeneratedClientAndState(t *testing.T) {
	const service, pair = "svc_1234567890123456789012", "cpp_1234567890123456789012"
	request, err := NewRebindConnectorPeerPairRequest("https://control.example.test", service, pair, rebindRequestFixture())
	if err != nil {
		t.Fatal(err)
	}
	if request.Method != http.MethodPost || request.URL.Path != "/v1/services/"+service+"/connector-peer-pairs/"+pair+"/rebind" ||
		request.Header.Get("Content-Type") != "application/json" {
		t.Fatal("generated lifecycle request changed")
	}
	var body ConnectorPeerPairRebindRequest
	if err := json.NewDecoder(request.Body).Decode(&body); err != nil || body.Phase != ConnectorPeerPairInspect || body.ExpectedGeneration != 7 {
		t.Fatal("generated lifecycle body changed", err)
	}
	response, err := ParseRebindConnectorPeerPairResponse(&http.Response{StatusCode: http.StatusOK,
		Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(
			`{"high_water_generation":8,"ready_relays":[],"operation":{"operation_id":"ik_1234567890123456789012","delivery_generation":8,"status":"aborted"}}`))})
	if err != nil || response.JSON200 == nil || response.JSON200.HighWaterGeneration != 8 || response.JSON200.Pending != nil ||
		response.JSON200.Active != nil || response.JSON200.Operation == nil || response.JSON200.Operation.Status != ConnectorPeerPairOperationAborted {
		t.Fatal("generated lifecycle state changed", err)
	}
}

func TestConnectorPeerAdditiveFieldsPreserveLegacyJSON(t *testing.T) {
	for _, value := range []any{ConnectorPeerPair{}, ConnectorPeerPairDelivery{}, ConnectorPeerPairPrepared{}} {
		wire, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"session_key", "binding_state", "binding_challenge", "operation_id", "path_proofs", "phase"} {
			if bytes.Contains(wire, []byte(`"`+name+`"`)) {
				t.Fatalf("empty additive field %s changed legacy output", name)
			}
		}
	}
}
