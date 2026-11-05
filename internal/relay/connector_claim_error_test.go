package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestConnectorClaimErrorKeepsDenialOverStaleOverRetryAcrossJoinedCauses(t *testing.T) {
	stale := &serviceapi.ProblemError{Status: http.StatusConflict, Code: string(relayv1.StaleNetworkBinding)}
	denied := &serviceapi.ProblemError{Status: http.StatusForbidden, Code: string(relayv1.Unauthenticated)}
	retry := &ControlProblemError{Status: http.StatusServiceUnavailable}
	for _, test := range []struct {
		cause error
		want  tunnelv1.ErrorCode
	}{
		{stale, tunnelv1.StaleNetworkBinding},
		{fmt.Errorf("direct adapter: %w", stale), tunnelv1.StaleNetworkBinding},
		{&ControlProblemError{Status: http.StatusConflict, Problem: &relayv1.Problem{Code: relayv1.StaleNetworkBinding}}, tunnelv1.StaleNetworkBinding},
		{errors.Join(retry, stale), tunnelv1.StaleNetworkBinding},
		{errors.Join(stale, retry), tunnelv1.StaleNetworkBinding},
		{errors.Join(stale, errors.Join(retry, denied)), tunnelv1.Unauthenticated},
		{errors.Join(denied, errors.Join(retry, stale)), tunnelv1.Unauthenticated},
		{errors.Join(&tunnel.ProtocolError{Code: tunnelv1.StaleNetworkBinding}, denied), tunnelv1.Unauthenticated},
		{errors.Join(&tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}, stale), tunnelv1.Unauthenticated},
		{&serviceapi.ProblemError{Status: http.StatusServiceUnavailable}, tunnelv1.Unavailable},
		{errors.Join(retry, &ControlProblemError{Status: http.StatusForbidden}), tunnelv1.Unauthenticated},
		{errors.New("denied"), tunnelv1.Unauthenticated},
	} {
		result := connectorClaimError(test.cause)
		var classified *tunnel.ProtocolError
		if !errors.As(result, &classified) || classified.Code != test.want || !errors.Is(result, test.cause) {
			t.Fatal("claim error changed scope or lost its cause", test.want, result)
		}
	}
}

func TestConnectorHTTPClaimPreservesExactStaleNetworkProblem(t *testing.T) {
	f := newConnectorBindingFixture(t)
	problem := relayv1.Problem{Status: http.StatusConflict, Type: "https://tnl.dev/problems/stale-network-binding", Title: "stale network binding", Code: relayv1.StaleNetworkBinding}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(problem.Status)
		_ = json.NewEncoder(w).Encode(problem)
	}))
	t.Cleanup(server.Close)
	generated, err := relayv1.NewClientWithResponses(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewHTTPControlClient(generated)
	if err != nil {
		t.Fatal(err)
	}
	proof := f.proof
	proof.RequestedAt = proof.RequestedAt.UTC()
	lease := f.acceptor.CurrentLease()
	_, err = client.ClaimConnectorPeerPairLegFromAcceptedSocket(context.Background(), lease, netip.MustParseAddr("192.0.2.1"), proof, make([]byte, 64))
	var raw *serviceapi.ProblemError
	var classified *tunnel.ProtocolError
	if !errors.As(err, &raw) || raw.Code != string(relayv1.StaleNetworkBinding) || !errors.As(connectorClaimError(err), &classified) || classified.Code != tunnelv1.StaleNetworkBinding {
		t.Fatal("HTTP claim erased its exact typed stale result", err)
	}
	if got := ControlErrorCode(relayControlError("claim connector peer pair leg", err)); got != tunnelv1.StaleNetworkBinding {
		t.Fatal("relay control error adapter erased its exact code", got)
	}
}
