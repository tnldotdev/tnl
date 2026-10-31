package relay

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability/operatorlog"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type nativePeerClaimStoreStub struct {
	*relayStoreStub
	err    error
	cancel context.CancelFunc
}

func (s nativePeerClaimStoreStub) ClaimNativePeerPairLeg(context.Context, controlstate.RelayLeaseIdentity, netip.Addr, tunnelv1.NativePairLegProof, []byte, time.Time) (controlstate.NativePeerPairLegClaim, error) {
	if s.cancel != nil {
		s.cancel()
	}
	return controlstate.NativePeerPairLegClaim{}, s.err
}

func TestNativePeerClaimProblemPreservesCauseAndSafeOutput(t *testing.T) {
	now := time.Now().UTC()
	proof := tunnelv1.NativePairLegProof{PairID: "npp_1234567890123456789012", DeliveryGeneration: 1,
		ServiceID: "svc_1234567890123456789012", ServiceRunID: "srun_1234567890123456789012", RunNumber: 1,
		PublisherIdentityID: "pub_1234567890123456789012", ConnectionSlot: 0, PublisherConnectionID: "pc_1234567890123456789012",
		AssignmentRevision: 1, RelayServiceID: "relay-a", RelayID: "node-a", RelayRunID: "process-a", RelayLeaseRevision: 1,
		RequestedAt: now, Nonce: bytes.Repeat([]byte{1}, 32), Signature: bytes.Repeat([]byte{2}, 64)}
	lease := relayv1.RelayLease{RelayServiceId: proof.RelayServiceID, RelayId: proof.RelayID, RelayRunId: proof.RelayRunID, RelayLeaseRevision: 1}
	body, err := relayv1.NewNativePeerPairLegClaimRequest(lease, netip.MustParseAddr("192.0.2.10"), proof, bytes.Repeat([]byte{3}, 64))
	if err != nil {
		t.Fatal("valid framed request fixture", err)
	}
	secretCause := errors.New("private-provider-proof-material")
	for _, test := range []struct {
		name     string
		cause    error
		status   int
		code     string
		reports  bool
		canceled bool
	}{
		{"unexpected", fmt.Errorf("provider failure: %w", secretCause), 500, "internal", true, false},
		{"service", controlstate.ErrServiceAccess, 409, "stale_connection_assignment", false, false},
		{"permission", controlstate.ErrVisitorPermission, 409, "stale_connection_assignment", false, false},
		{"workload", controlstate.ErrWorkloadDenied, 409, "stale_connection_assignment", false, false},
		{"canceled request", fmt.Errorf("database canceled: %w", context.Canceled), 0, "", false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := nativePeerClaimStoreStub{relayStoreStub: &relayStoreStub{}, err: test.cause}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if test.canceled {
				store.cancel = cancel
			}
			var reported error
			h := testRelayHandler(t, store, now, func(err error) { reported = err })
			if test.canceled {
				s, err := newService(DirectConfig{Store: store, LeaseDuration: time.Minute, Now: func() time.Time { return now }, Report: func(err error) { reported = err }})
				if err != nil {
					t.Fatal(err)
				}
				_, err = s.ClaimNativePeerPairLeg(ctx, proof.PairID, 0, body)
				if !errors.Is(err, context.Canceled) || reported != nil {
					t.Fatal("canceled claim became an internal failure", err, reported)
				}
				return
			}
			response := serveRelayJSON(t, h, http.MethodPost, "/internal/v1/native-peer-pairs/"+proof.PairID+"/legs/0/claim", body)
			var problem relayv1.Problem
			decodeRelayResponse(t, response, &problem)
			if response.Code != test.status || string(problem.Code) != test.code || response.Header().Get("Cache-Control") != "no-store" || strings.Contains(response.Body.String(), secretCause.Error()) {
				t.Fatal("unsafe or misclassified HTTP problem", response.Code, problem.Code)
			}
			if test.reports {
				if !errors.Is(reported, secretCause) {
					t.Fatal("operator report lost the provider cause")
				}
				reason, ok := failure.ReasonOf(reported)
				if !ok || reason != failure.ServerAPIInternal {
					t.Fatal("operator report lost owned classification")
				}
				if strings.Contains(operatorlog.Format("claim native peer pair leg", reason, "request"), secretCause.Error()) {
					t.Fatal("operator output printed provider material")
				}
			} else if reported != nil {
				t.Fatal("expected denial became an internal report")
			}
			direct, err := NewDirectClient(DirectConfig{Store: store, LeaseDuration: time.Minute, Now: func() time.Time { return now }, Report: func(error) {}})
			if err != nil {
				t.Fatal(err)
			}
			_, err = direct.ClaimNativePeerPairLegFromAcceptedSocket(t.Context(), lease, netip.MustParseAddr("192.0.2.10"), proof, bytes.Repeat([]byte{3}, 64))
			var local *serviceapi.ProblemError
			if !errors.As(err, &local) || local.Status != test.status || local.Code != test.code || strings.Contains(local.Detail, secretCause.Error()) {
				t.Fatal("direct adapter changed the safe problem", err)
			}
		})
	}
}
