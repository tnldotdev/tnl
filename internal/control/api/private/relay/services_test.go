package relay

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	serverhttp "github.com/tnldotdev/tnl/internal/serverhttp"
	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
)

type publisherSourceStore struct {
	*relayStoreStub
	t      *testing.T
	body   relayv1.ServicePublisherConnectionClaim
	id     string
	calls  int
	source netip.Addr
}

func (s *publisherSourceStore) ClaimServicePublisherConnection(_ context.Context, connection, service, run string, number, revision int64, credential string, source netip.Addr, lease controlstate.RelayLeaseIdentity, _ time.Time) (controlstate.ServicePublisherConnection, error) {
	s.t.Helper()
	s.calls++
	s.source = source
	if connection != s.id || service != s.body.ServiceId || run != s.body.ServiceRunId ||
		number != s.body.RunNumber || revision != s.body.ConnectionAssignmentRevision || credential != s.body.Credential ||
		lease != privateRelayIdentity(s.body.RelayId, s.body.RelayRunId, s.body.RelayLeaseRevision) {
		s.t.Fatal("observed source replaced the exact assignment or relay identity")
	}
	return controlstate.ServicePublisherConnection{ConnectionID: connection, ServiceID: service, RunID: run,
		RunNumber: number, Revision: revision, RelayServiceID: "relay-a"}, nil
}

func TestServiceClaimRequiresCanonicalObservedPublisherSource(t *testing.T) {
	for _, transport := range []string{"HTTP", "direct"} {
		t.Run(transport, func(t *testing.T) {
			credential, _, err := credentials.NewPublisherConnectionCredential()
			if err != nil {
				t.Fatal(err)
			}
			body := relayv1.ServicePublisherConnectionClaim{ServiceId: "svc_" + strings.Repeat("a", 22),
				ServiceRunId: "srun_" + strings.Repeat("b", 22), RunNumber: 3,
				ConnectionAssignmentRevision: 7, Credential: credential.String(),
				RelayId: "relay-a-1", RelayRunId: "relay-run", RelayLeaseRevision: 2}
			store := &publisherSourceStore{relayStoreStub: &relayStoreStub{}, t: t, body: body, id: "pc_" + strings.Repeat("c", 22)}
			client, err := NewDirectClient(DirectConfig{Store: store, LeaseDuration: time.Minute})
			if err != nil {
				t.Fatal(err)
			}
			handler := testRelayHandler(t, store, time.Now(), nil)
			claim := func(source string) int {
				t.Helper()
				input := body
				input.ObservedSourceIp = source
				if transport == "HTTP" {
					return serveRelayJSON(t, handler, http.MethodPost, "/internal/v1/private-publisher-connections/"+store.id+"/claim", input).Code
				}
				_, err := client.ClaimServicePublisherConnection(t.Context(), store.id, input)
				if err == nil {
					return http.StatusOK
				}
				var problem *serverhttp.ProblemError
				if !errors.As(err, &problem) {
					t.Fatal("source validation did not return an HTTP problem", err)
				}
				return problem.Status
			}
			for _, invalid := range []string{"", "0.0.0.0", "::", "::ffff:192.0.2.1", "192.0.2.1/32", "192.0.2.1:443", "fe80::1%en0", " 192.0.2.1", "2001:0db8::1"} {
				if status := claim(invalid); status != http.StatusBadRequest || store.calls != 0 {
					t.Fatalf("invalid observed source %q reached state: status=%d calls=%d", invalid, status, store.calls)
				}
			}
			for _, source := range []string{"192.0.2.1", "2001:db8::1"} {
				if status := claim(source); status != http.StatusOK || store.source != netip.MustParseAddr(source) {
					t.Fatalf("accepted publisher source changed: status=%d source=%v", status, store.source)
				}
			}
			if store.calls != 2 {
				t.Fatal("valid source did not reach the exact claim once")
			}
		})
	}
}

type serviceConnectionErrorStore struct {
	*relayStoreStub
	err   error
	calls int
}

func (s *serviceConnectionErrorStore) ClaimServicePublisherConnection(context.Context, string, string, string, int64, int64, string, netip.Addr, controlstate.RelayLeaseIdentity, time.Time) (controlstate.ServicePublisherConnection, error) {
	s.calls++
	return controlstate.ServicePublisherConnection{}, s.err
}

func (s *serviceConnectionErrorStore) ReadyServicePublisherConnection(context.Context, string, string, int64, int64, controlstate.RelayLeaseIdentity, time.Time) (controlstate.ServicePublisherConnection, error) {
	s.calls++
	return controlstate.ServicePublisherConnection{}, s.err
}

func (s *serviceConnectionErrorStore) DisconnectServicePublisherConnection(context.Context, string, string, int64, int64, controlstate.RelayLeaseIdentity, time.Time, bool) (controlstate.ServicePublisherConnection, error) {
	s.calls++
	return controlstate.ServicePublisherConnection{}, s.err
}

func TestServiceConnectionErrorsMatchHTTPAndStandalone(t *testing.T) {
	for _, test := range []struct {
		err    error
		status int
		code   string
	}{
		{controlstate.ErrServiceAccess, 409, "stale_connection_assignment"},
		{controlstate.ErrPublisherIdentity, 401, "invalid_publisher_connection_credential"},
		{controlstate.ErrGuestTrialSpent, 401, "invalid_publisher_connection_credential"},
		{controlstate.ErrRelayConnectionCapacity, 503, "relay_connection_capacity_exhausted"},
		{controlstate.ErrRelayLeaseStale, 409, "relay_lease_stale"},
		{controlstate.ErrRelayDraining, 503, "relay_draining"},
		{errors.New("private database failure"), 500, "internal"},
	} {
		t.Run(test.code+"/"+test.err.Error(), func(t *testing.T) {
			for _, operation := range []string{"claim", "ready", "disconnect"} {
				t.Run(operation, func(t *testing.T) {
					credential, _, err := credentials.NewPublisherConnectionCredential()
					if err != nil {
						t.Fatal(err)
					}
					id := "pc_" + strings.Repeat("a", 22)
					transition := relayv1.ServicePublisherConnectionTransition{
						ServiceRunId: "srun_" + strings.Repeat("b", 22), RunNumber: 1,
						ConnectionAssignmentRevision: 2, RelayId: "relay-a", RelayRunId: "relay-run", RelayLeaseRevision: 3,
					}
					if operation == "disconnect" {
						transition.Unexpected = new(true)
					}
					claim := relayv1.ServicePublisherConnectionClaim{
						ServiceId: "svc_" + strings.Repeat("c", 22), ServiceRunId: transition.ServiceRunId,
						RunNumber: transition.RunNumber, ConnectionAssignmentRevision: transition.ConnectionAssignmentRevision,
						RelayId: transition.RelayId, RelayRunId: transition.RelayRunId, RelayLeaseRevision: transition.RelayLeaseRevision,
						Credential: credential.String(), ObservedSourceIp: "192.0.2.1",
					}
					store := &serviceConnectionErrorStore{relayStoreStub: &relayStoreStub{}, err: test.err}
					reported := 0
					report := func(err error) {
						if !errors.Is(err, test.err) {
							t.Fatal("operator report lost the original failure", err)
						}
						reported++
					}
					direct, err := NewDirectClient(DirectConfig{Store: store, LeaseDuration: time.Minute, Report: report})
					if err != nil {
						t.Fatal(err)
					}
					var body any = transition
					switch operation {
					case "claim":
						body = claim
						_, err = direct.ClaimServicePublisherConnection(t.Context(), id, claim)
					case "ready":
						_, err = direct.ReadyServicePublisherConnection(t.Context(), id, transition)
					case "disconnect":
						err = direct.DisconnectServicePublisherConnection(t.Context(), id, transition)
					}
					var problem *serverhttp.ProblemError
					if !errors.As(err, &problem) || problem.Status != test.status || problem.Code != test.code || strings.Contains(problem.Detail, "private database") {
						t.Fatal("standalone lost the authored state classification", err)
					}
					handler := testRelayHandler(t, store, time.Now(), report)
					response := serveRelayJSON(t, handler, http.MethodPost, "/internal/v1/private-publisher-connections/"+id+"/"+operation, body)
					var wire relayv1.Problem
					decodeRelayResponse(t, response, &wire)
					if response.Code != problem.Status || string(wire.Code) != problem.Code || wire.Detail != problem.Detail || store.calls != 2 {
						t.Fatal("HTTP and standalone classification differ", response.Code, wire, problem)
					}
					wantReports := 0
					if test.status == http.StatusInternalServerError {
						wantReports = 2
					}
					if reported != wantReports {
						t.Fatal("expected rejection was logged or unknown cause was lost", reported, wantReports)
					}
				})
			}
		})
	}
}

func TestServiceConnectionTransitionRequiresExplicitDisconnectClassification(t *testing.T) {
	for _, transport := range []string{"HTTP", "direct"} {
		for _, operation := range []string{"ready", "disconnect"} {
			for _, classification := range []struct {
				name  string
				value *bool
			}{{"absent", nil}, {"false", new(false)}, {"true", new(true)}} {
				t.Run(transport+"/"+operation+"/"+classification.name, func(t *testing.T) {
					store := &serviceConnectionErrorStore{relayStoreStub: &relayStoreStub{}, err: controlstate.ErrServiceAccess}
					body := relayv1.ServicePublisherConnectionTransition{
						ServiceRunId: "srun_" + strings.Repeat("b", 22), RunNumber: 1,
						ConnectionAssignmentRevision: 2, RelayId: "relay-a", RelayRunId: "relay-run", RelayLeaseRevision: 3,
						Unexpected: classification.value,
					}
					id := "pc_" + strings.Repeat("a", 22)
					var status int
					if transport == "HTTP" {
						response := serveRelayJSON(t, testRelayHandler(t, store, time.Now(), nil), http.MethodPost,
							"/internal/v1/private-publisher-connections/"+id+"/"+operation, body)
						status = response.Code
					} else {
						direct, err := NewDirectClient(DirectConfig{Store: store, LeaseDuration: time.Minute})
						if err != nil {
							t.Fatal(err)
						}
						if operation == "ready" {
							_, err = direct.ReadyServicePublisherConnection(t.Context(), id, body)
						} else {
							err = direct.DisconnectServicePublisherConnection(t.Context(), id, body)
						}
						var problem *serverhttp.ProblemError
						if !errors.As(err, &problem) {
							t.Fatal("transition lost its authored problem", err)
						}
						status = problem.Status
					}
					valid := (operation == "disconnect") == (classification.value != nil)
					wantStatus, wantCalls := http.StatusBadRequest, 0
					if valid {
						wantStatus, wantCalls = http.StatusConflict, 1
					}
					if status != wantStatus || store.calls != wantCalls {
						t.Fatal("transition inferred or ignored disconnect classification", status, store.calls)
					}
				})
			}
		}
	}
}
