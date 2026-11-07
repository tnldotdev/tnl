package stream

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestConnectorRecoveryWakeOnlyTracksTransitions(t *testing.T) {
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(nil)
	var canceled atomic.Int32
	p := &connectorConnection{ctx: ctx, cancel: cancel, until: time.Now().Add(time.Minute), changed: make(chan struct{}), recover: make(chan struct{}, 1), bindingCancel: func() { canceled.Add(1) }}
	p.requestRecovery(connectorInspecting)
	<-p.recover
	inspected := p.changed
	for range 100 {
		p.requestRecovery(connectorInspecting)
	}
	if p.changed != inspected || len(p.recover) != 0 {
		t.Fatal("unchanged inspection kept waking its coordinator")
	}
	p.requestRecovery(connectorRebinding)
	<-p.recover
	staged := p.changed
	for range 100 {
		p.requestRecovery(connectorRebinding)
		p.requestRecovery(connectorInspecting)
	}
	if p.changed != staged || len(p.recover) != 0 || canceled.Load() != 1 || p.recoveryState != connectorRebinding {
		t.Fatal("repeated recovery changed state, restarted cancellation, or woke its coordinator")
	}
}

type recoveryPhaseControl struct {
	Control
	call func(controlv1.ConnectorPeerPairRebindRequest) (controlv1.ConnectorPeerPairRebindState, error)
}

func (c recoveryPhaseControl) RebindConnectorPeerPair(_ context.Context, _, _ string, request controlv1.ConnectorPeerPairRebindRequest) (controlv1.ConnectorPeerPairRebindState, error) {
	return c.call(request)
}

func TestConnectorRecoveryRejectedPrepareInspectsBeforeChoosingNewOperation(t *testing.T) {
	for _, code := range []controlv1.ProblemCode{controlv1.Conflict, controlv1.StaleNetworkBinding} {
		t.Run(string(code), func(t *testing.T) {
			signer, run, original, request, state := rebindFixture(t)
			state.Pending, state.PendingUntil, state.Operation, state.HighWaterGeneration = nil, nil, nil, original.DeliveryGeneration
			ctx, cancel := context.WithCancelCause(t.Context())
			defer cancel(nil)
			calls := 0
			control := recoveryPhaseControl{call: func(request controlv1.ConnectorPeerPairRebindRequest) (controlv1.ConnectorPeerPairRebindState, error) {
				calls++
				if request.Phase != controlv1.ConnectorPeerPairInspect {
					t.Fatal("phase conflict skipped current-owner inspection")
				}
				return state, nil
			}}
			p := &connectorConnection{ctx: ctx, cancel: cancel, config: Config{Control: control}, signer: signer, owner: request.IdempotencyKey, run: run, pair: original,
				until: time.Now().Add(time.Minute), permission: controlv1.VisitorTokenResponse{ExpiresAt: time.Now().Add(time.Minute)}, highWater: original.DeliveryGeneration, changed: make(chan struct{}), recoveryState: connectorRebinding}
			op := &connectorRebindOperation{prepare: &connectorRebindPhase{request: request, started: time.Now()}}
			p.rebind = op
			rejected := &clientcontrol.ProblemError{Status: http.StatusConflict, Problem: controlv1.Problem{Code: code}}
			if !connectorBindingChanged(rejected) {
				t.Fatal("authenticated stale binding was terminal")
			}
			if err := p.reconcileRebind(op); !connectorTemporary(err) || calls != 1 || p.rebind != nil || p.recoveryState != connectorRebinding || !reflect.DeepEqual(p.pair, original) {
				t.Fatal("rejected prepare did not retain its owner for a fresh CAS", err)
			}
		})
	}
	denied := &clientcontrol.ProblemError{Status: http.StatusForbidden, Problem: controlv1.Problem{Code: controlv1.Forbidden}}
	stale := &clientcontrol.ProblemError{Status: http.StatusConflict, Problem: controlv1.Problem{Code: controlv1.StaleNetworkBinding}}
	for _, err := range []error{errors.Join(denied, context.DeadlineExceeded), errors.Join(stale, denied), errors.Join(denied, stale)} {
		if connectorBindingChanged(err) {
			t.Fatal("authority denial acquired network-recovery permission")
		}
	}
}
