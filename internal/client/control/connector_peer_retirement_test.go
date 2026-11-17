package control

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func retirementWireFixture() (controlv1.ConnectorPeerPairRetireRequest, controlv1.ConnectorPeerPairRetirement) {
	at := time.Now().UTC().Truncate(time.Microsecond)
	body := controlv1.ConnectorPeerPairRetireRequest{ServiceRunId: "srun_1234567890123456789012", RunNumber: 2,
		PublisherIdentityId: "pub_1234567890123456789012", DeliveryId: "AQEBAQEBAQEBAQEBAQEBAQ", IdempotencyKey: "exact-owner", RequestedAt: at,
		SessionProof: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)),
		Signature:    base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 64))}
	result := controlv1.ConnectorPeerPairRetirement{ServiceId: "svc_1234567890123456789012", PairId: "cpp_1234567890123456789012",
		ServiceRunId: body.ServiceRunId, RunNumber: body.RunNumber, PublisherIdentityId: body.PublisherIdentityId,
		DeliveryId: body.DeliveryId, IdempotencyKey: body.IdempotencyKey, Disposition: controlv1.ConnectorPeerPairDispositionRetired, OwnerRevision: 2,
		Retirement: controlv1.ConnectorPeerPairRetirementObservation{ObservedAt: at, RetiredAt: at, RetainedUntil: at.Add(time.Minute)}}
	return body, result
}

func TestConnectorPeerRetireRPCNoBearerAndIdenticalRetry(t *testing.T) {
	body, want := retirementWireFixture()
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if len(r.Header.Values("Authorization")) != 0 {
			t.Error("retirement inherited a control bearer")
		}
		if r.Method != http.MethodPost || r.URL.Path != "/v1/services/"+want.ServiceId+"/connector-peer-pairs/"+want.PairId+"/retire" {
			t.Error("retirement reselected another scope")
		}
		var got controlv1.ConnectorPeerPairRetireRequest
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil || !reflect.DeepEqual(got, body) {
			t.Error("retirement changed the signed retry body", err)
		}
		_ = json.NewEncoder(w).Encode(want)
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client(), "revoked-control-token")
	if err != nil {
		t.Fatal(err)
	}
	client.api.RequestEditors = append(client.api.RequestEditors, func(_ context.Context, request *http.Request) error {
		request.Header["authorization"] = []string{""}
		request.Header.Set("Authorization", "Bearer must-not-send")
		if !VisitorSourceAuthenticates(request.Context()) {
			t.Error("retirement could trigger management token refresh")
		}
		return nil
	})
	for range 2 {
		got, err := client.RetireConnectorPeerPair(t.Context(), want.ServiceId, want.PairId, body)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatal("exact retirement retry lost its receipt", err)
		}
	}
	if calls != 2 {
		t.Fatal("RPC performed an internal replay or refresh", calls)
	}
}

func TestConnectorPeerRetireRPCRejectsFalseSuccess(t *testing.T) {
	body, result := retirementWireFixture()
	valid, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, wire := range []string{
		`null`, `{}`, string(bytes.Replace(valid, []byte(`"retired"`), []byte(`"candidate"`), 1)),
		string(bytes.Replace(valid, []byte(`"owner_revision":"2"`), []byte(`"owner_revision":"3"`), 1)),
		string(bytes.Replace(valid, []byte(result.PairId), []byte("cpp_abcdefghijklmnopqrstuv"), 1)),
		string(bytes.Replace(valid, []byte(result.IdempotencyKey), []byte("sibling"), 1)),
		string(bytes.Replace(valid, []byte(`"owner_revision":"2"`), []byte(`"owner_revision":2`), 1)),
		string(valid[:len(valid)-1]) + `,"remote_joined":true}`,
	} {
		t.Run(wire, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(wire)) }))
			defer server.Close()
			client, err := New(server.URL, server.Client(), "")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.RetireConnectorPeerPair(t.Context(), result.ServiceId, result.PairId, body); err == nil {
				t.Fatal("mismatched or unsupported response became confirmed retirement")
			}
		})
	}
	for _, status := range []int{http.StatusNoContent, http.StatusNotFound, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) }))
			defer server.Close()
			client, err := New(server.URL, server.Client(), "")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.RetireConnectorPeerPair(t.Context(), result.ServiceId, result.PairId, body); err == nil {
				t.Fatal("empty or unavailable retirement became success")
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	client, err := New("https://control.example.test", nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.RetireConnectorPeerPair(ctx, result.ServiceId, result.PairId, body); !errors.Is(err, context.Canceled) {
		t.Fatal("caller cancellation was not preserved", err)
	}
}
