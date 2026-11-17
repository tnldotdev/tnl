package service

import (
	"context"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestPrivateExpiredAssignmentStopsTransportAttempts(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, bound, _, _ := privateFixture(t, "127.0.0.1:1")
		expires := time.Now().Add(250 * time.Millisecond)
		for slot := range bound.connections {
			bound.connections[slot].PublisherConnectionCredentialExpiresAt = expires
		}
		var attempts atomic.Int32
		connector := muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) {
			attempts.Add(1)
			return nil, errors.New("relay unavailable")
		})
		slots, err := tunnel.NewSlots(t.Context(), tunnel.SlotsConfig{SingleUse: true, BackoffMin: 10 * time.Millisecond, BackoffMax: 10 * time.Millisecond,
			Connect: func(ctx context.Context, slot uint8, _ bool) (tunnel.SlotSession, error) {
				claimed, err := bound.ConnectSlot(ctx, slot, ConnectOptions{QUIC: connector, WebSocket: connector})
				if err != nil {
					return nil, err
				}
				return claimed, nil
			}})
		if err != nil {
			t.Fatal(err)
		}
		defer slots.Close()
		for slot := range uint8(2) {
			if err := slots.Set(slot, bound.connections[slot].PublisherConnectionId); err != nil {
				t.Fatal(err)
			}
		}
		time.Sleep(time.Until(expires) + 30*time.Millisecond)
		synctest.Wait()
		before := attempts.Load()
		wait, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
		defer cancel()
		var readyErr error
	waitReady:
		for {
			current, changed := slots.Snapshot()
			if current[0] != nil || current[1] != nil {
				t.Fatal("expired assignment became ready")
			}
			select {
			case <-wait.Done():
				readyErr = context.Cause(wait)
				break waitReady
			case <-changed:
			}
		}
		synctest.Wait()
		if !errors.Is(readyErr, context.DeadlineExceeded) || before == 0 || attempts.Load() != before {
			t.Fatal("expired credentials continued pre-claim transport attempts", readyErr, before, attempts.Load())
		}
	})
}

func TestPrivateConnectionUpdateRejectsExpiredSecondSlotAtomically(t *testing.T) {
	_, bound, _, _ := privateFixture(t, "127.0.0.1:1")
	var claims [2]*Claimed
	for slot := range claims {
		claims[slot], _ = newClaimedTestPair(t, bound, uint8(slot), nil)
	}
	before := bound.connections
	next := before
	for slot := range next {
		var err error
		next[slot].PublisherConnectionId, err = opaqueid.New(opaqueid.PublisherConnectionPrefix)
		if err != nil {
			t.Fatal(err)
		}
		next[slot].ConnectionAssignmentRevision++
	}
	next[1].PublisherConnectionCredentialExpiresAt = time.Now().Add(-time.Second)
	p := bound.prepared.Preparation
	err := bound.ApplyHeartbeat(controlv1.ServiceRunState{ServiceId: p.ServiceId, ServiceRunId: p.ServiceRunId,
		RunNumber: p.RunNumber, State: "ready", PublisherExpiresAt: time.Now().Add(time.Minute), PublisherConnections: next[:]})
	if !errors.Is(err, ErrPrivateStream) || !reflect.DeepEqual(bound.connections, before) {
		t.Fatal("expired slot 1 partially installed valid slot 0", err)
	}
	for slot, claimed := range claims {
		if !bound.current(claimed.ref) {
			t.Fatal("rejected replacement changed a current claim", slot)
		}
		select {
		case <-claimed.session.Done():
			t.Fatal("rejected replacement closed a current session", slot)
		default:
		}
	}
}
