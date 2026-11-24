package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/failure"
	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
)

const slotToken = "private-test-slot-credential-abcdef0123456789"
const testInventory = `[{"service_id":"slot-a","relay_id":"relay-a","hostname":"a.relay.example","internal_address":"10.74.0.7:9445","credential":"` + slotToken + `"}]`

func TestSlotOwnsRegistrationRenewalAndCertificate(t *testing.T) {
	cluster := testRelaySecrets(t)
	slots, err := ParseSlots([]byte(testInventory), cluster)
	if err != nil {
		t.Fatal(err)
	}
	host := "a.relay.example"
	storeCalls := 0
	store := &relayStoreStub{
		registerRelay: func(context.Context, controlstate.RelayRegistration, time.Time, time.Duration) (controlstate.RelayLease, error) {
			storeCalls++
			return controlstate.RelayLease{}, nil
		},
		renewRelay: func(context.Context, controlstate.RelayRenewal, time.Time, time.Duration) (controlstate.RelayLease, error) {
			storeCalls++
			return controlstate.RelayLease{}, nil
		},
		getRelayTransportCertificate: func(context.Context, controlstate.RelayLeaseIdentity, time.Time) (controlstate.RelayTransportCertificate, error) {
			storeCalls++
			return controlstate.RelayTransportCertificate{RelayServiceID: "slot-a", TLSServerName: host, PrivateKeyPEM: "fixture-key"}, nil
		},
	}
	h, err := NewHandler(Config{Store: store, Slots: slots, ClusterSecrets: cluster, LeaseDuration: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	call := func(token, method, path string, body any, status int) {
		t.Helper()
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(method, path, bytes.NewReader(encoded))
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		h.ServeHTTP(response, request)
		if response.Code != status || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: status %d", path, response.Code)
		}
		if status != http.StatusOK {
			assertRelayProblemType(t, response, "https://tnl.dev/p/unauthenticated")
			if strings.Contains(response.Body.String(), "fixture-key") || strings.Contains(response.Body.String(), token) {
				t.Fatal("denial included private material")
			}
		}
	}
	const register = "/internal/v1/relays/register"
	body := relayv1.RelayRegistration{RelayServiceId: "slot-a", RelayId: "relay-a", RelayRunId: "run-1", Region: "aws:us-east-1", ProtocolVersion: 1, ConnectionCapacity: 2, StreamCapacity: 3, RelayAddress: host + ":443", TlsServerName: host, InternalRelayAddress: "10.74.0.7:9445"}
	call(testRelayClusterSecret, "POST", register, body, 401)
	call(slotToken, "POST", register, body, 200)
	for _, change := range []func(*relayv1.RelayRegistration){
		func(r *relayv1.RelayRegistration) { r.TlsServerName = "b.relay.example" },
		func(r *relayv1.RelayRegistration) { r.RelayAddress = "b.relay.example:443" },
		func(r *relayv1.RelayRegistration) { r.RelayId = "relay-b" },
		func(r *relayv1.RelayRegistration) { r.RelayServiceId = "slot-b" },
		func(r *relayv1.RelayRegistration) { r.InternalRelayAddress = "10.74.1.7:9445" },
	} {
		other := body
		change(&other)
		call(slotToken, "POST", register, other, 403)
	}
	renew := relayv1.RelayRenewal{RelayId: "relay-a", RelayServiceId: "slot-a", RelayRunId: "run-1", RelayLeaseRevision: 1}
	call(slotToken, "POST", "/internal/v1/relays/relay-a/renew", renew, 200)
	renew.RelayServiceId = "slot-b"
	call(slotToken, "POST", "/internal/v1/relays/relay-a/renew", renew, 403)
	const cert = "/internal/v1/relay-services/slot-a/certificate?relay_id=relay-a&relay_run_id=run-1&relay_lease_revision=1"
	call(slotToken, "GET", cert, nil, 200)
	call(slotToken, "GET", strings.Replace(cert, "slot-a", "slot-b", 1), nil, 403)
	host = "b.relay.example"
	call(slotToken, "GET", cert, nil, 403)
	if storeCalls != 4 {
		t.Fatalf("unexpected store call count %d", storeCalls)
	}
}

func TestInvalidSlotInventoryFailsClosed(t *testing.T) {
	for _, data := range []string{"[]", strings.Replace(testInventory, slotToken, testRelayClusterSecret, 1), testInventory[:len(testInventory)-1] + "," + testInventory[1:]} {
		slots, err := ParseSlots([]byte(data), testRelaySecrets(t))
		if reason, ok := failure.ReasonOf(err); !ok || reason != failure.ServerConfigInvalid || len(slots.entries) != 0 {
			t.Fatal("invalid inventory did not fail closed")
		}
	}
	_, err := ParseSlots([]byte(slotToken), testRelaySecrets(t))
	var cause *json.SyntaxError
	if !errors.As(err, &cause) || !errors.Is(err, cause) || strings.Contains(failure.SafeMessage(err, failure.Unexpected), slotToken) {
		t.Fatal("invalid inventory lost its cause or exposed private material")
	}
}
