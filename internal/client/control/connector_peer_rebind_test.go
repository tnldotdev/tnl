package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestConnectorPeerRebindSourceAndBearerStayAdapterOwned(t *testing.T) {
	for _, workload := range []bool{false, true} {
		for _, phase := range []controlv1.ConnectorPeerPairRebindPhase{"inspect", "prepare", "activate", "abort"} {
			t.Run(map[bool]string{false: "device", true: "workload"}[workload]+"/"+string(phase), func(t *testing.T) {
				const service, pair, device = "svc_aaaaaaaaaaaaaaaaaaaaaa", "cpp_bbbbbbbbbbbbbbbbbbbbbb", "vdev_cccccccccccccccccccccc"
				body := controlv1.ConnectorPeerPairRebindRequest{Phase: phase, IdempotencyKey: "stable-owner", OperationId: "ik_dddddddddddddddddddddd", ExpectedGeneration: 7,
					RequestedAt: time.Now().UTC().Truncate(time.Microsecond), ServiceRunId: "sr_eeeeeeeeeeeeeeeeeeeeee", RunNumber: 4, TrustRevision: 3, PublisherIdentityId: "pub_ffffffffffffffffffffff",
					Source: json.RawMessage(`{"kind":"device","device_id":"do-not-use-caller-source"}`), Signature: "already-signed", ExpectedRelays: []controlv1.ConnectorPeerPairRelay{}, PathProofs: []controlv1.ConnectorPeerPairPathProof{}}
				want := controlv1.ConnectorPeerPairRebindState{HighWaterGeneration: 8, ReadyRelays: []controlv1.ConnectorPeerPairRelay{}, Operation: &controlv1.ConnectorPeerPairRebindOperation{OperationId: body.OperationId, DeliveryGeneration: 8, Status: "pending"}}
				calls := 0
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls++
					if r.Method != http.MethodPost || r.URL.Path != "/v1/services/"+service+"/connector-peer-pairs/"+pair+"/rebind" {
						t.Error("rebind changed the selected service or retained pair", r.URL.Path)
					}
					authorization := "Bearer signed-in-control"
					if workload {
						authorization = ""
					}
					if r.Header.Get("Authorization") != authorization {
						t.Error("rebind crossed the device/workload bearer boundary")
					}
					var got controlv1.ConnectorPeerPairRebindRequest
					if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
						t.Error(err)
					}
					var source map[string]string
					if err := json.Unmarshal(got.Source, &source); err != nil {
						t.Error(err)
					}
					wantSource := map[string]string{"kind": "device", "device_id": device}
					if workload {
						wantSource = map[string]string{"kind": "workload", "credential": "private-workload-credential"}
					}
					if !reflect.DeepEqual(source, wantSource) {
						t.Error("rebind trusted a caller-supplied source")
					}
					got.Source = body.Source
					if !reflect.DeepEqual(got, body) {
						t.Error("adapter changed the signed phase request")
					}
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(want)
				}))
				defer server.Close()
				client, err := New(server.URL, server.Client(), "signed-in-control")
				if err != nil {
					t.Fatal(err)
				}
				var got controlv1.ConnectorPeerPairRebindState
				if workload {
					got, err = client.RebindWorkloadConnectorPeerPair(t.Context(), service, pair, "private-workload-credential", body)
				} else {
					got, err = client.RebindDeviceConnectorPeerPair(t.Context(), service, pair, device, body)
				}
				if err != nil || calls != 1 || !reflect.DeepEqual(got, want) {
					t.Fatal("rebind adapter lost the operation snapshot", err)
				}
			})
		}
	}
}
