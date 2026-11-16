package auth

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestConnectorPeerRetireBypassesManagementRefreshTransport(t *testing.T) {
	const service, pair = "svc_1234567890123456789012", "cpp_1234567890123456789012"
	body := controlv1.ConnectorPeerPairRetireRequest{ServiceRunId: "srun_1234567890123456789012", RunNumber: 2,
		PublisherIdentityId: "pub_1234567890123456789012", DeliveryId: "AQEBAQEBAQEBAQEBAQEBAQ", IdempotencyKey: "owner", RequestedAt: time.Now(),
		SessionProof: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)),
		Signature:    base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 64))}
	base := &recordingTransport{respond: func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/v1/services/"+service+"/connector-peer-pairs/"+pair+"/retire" || len(r.Header.Values("Authorization")) != 0 {
			t.Error("retirement fetched or sent parent authority")
		}
		response := jsonResponse(http.StatusUnauthorized, map[string]any{"code": "unauthenticated"})
		response.Header.Set("WWW-Authenticate", "Bearer")
		return response, nil
	}}
	// no store, authority client, or explicit token exists. a management-token
	// read would fail before reaching the base; a 401 must not initiate refresh.
	source := &tokenSource{control: control{serverEndpoint: testControlOrigin}}
	client, err := clientcontrol.NewExternallyAuthenticated(testControlOrigin, &http.Client{Transport: &bearerTransport{base: base, source: source}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.RetireConnectorPeerPair(t.Context(), service, pair, body); err == nil {
		t.Fatal("unauthorized response became retirement confirmation")
	}
	if len(base.snapshot()) != 1 {
		t.Fatal("retirement read a management session or retried after a challenge")
	}
}
