package stream

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/testutil/connectorfixture"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestConnectorCleanupUsesOneOriginalStopBudget(t *testing.T) {
	caller, stop := context.WithTimeout(t.Context(), time.Second)
	defer stop()
	cleanup := newConnectorCleanup(t.Context(), func() context.Context { return caller })
	defer cleanup.close()
	cleanup.observe(time.Now().Add(time.Minute))
	cleanup.begin()
	first := cleanup.context()
	deadline, bounded := first.Deadline()
	callerDeadline, _ := caller.Deadline()
	if !bounded || deadline.After(callerDeadline) || first.Err() != nil {
		t.Fatal("cleanup lost the caller's original bound")
	}
	cleanup.observe(time.Now().Add(time.Hour))
	if again := cleanup.context(); again != first {
		t.Fatal("cleanup created another context or five-second phase")
	}
	if got := cleanup.bound(time.Now().Add(time.Minute)); !got.Equal(deadline) {
		t.Fatal("cleanup retry extended the original terminal bound", got, deadline)
	}
}

func TestConnectorTerminalCleanupKeepsIndependentFailures(t *testing.T) {
	independent := errors.New("independent observed-write cleanup failure")
	failed := tunnel.ConnectorTerminalExchange{Matched: true, ObservedWritten: true,
		Result: tunnelv1.ConnectorVisitorTerminalResult{Outcome: tunnelv1.ConnectorTerminalFailed}}
	for _, test := range []struct {
		name     string
		exchange tunnel.ConnectorTerminalExchange
		err      error
		retained bool
	}{
		{"observed visitor failure", failed, tunnel.ErrConnectorTerminalFailed, false},
		{"independent joined failure", failed, errors.Join(tunnel.ErrConnectorTerminalFailed, independent), true},
		{"unmatched", tunnel.ConnectorTerminalExchange{}, tunnel.ErrConnectorTerminalFailed, true},
		{"observation not joined", tunnel.ConnectorTerminalExchange{Matched: true, Result: failed.Result}, tunnel.ErrConnectorTerminalFailed, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := &connectorConnection{}
			p.recordTerminalCleanup(test.exchange, test.err)
			if (p.useErr != nil) != test.retained {
				t.Fatal("terminal cleanup confused a visitor decision with failed owner work", p.useErr)
			}
			if test.retained && !errors.Is(p.useErr, test.err) {
				t.Fatal("terminal cleanup replaced its original failure", p.useErr, test.err)
			}
		})
	}
}

func TestConnectorStoppedSuspendedBindingRetiresWithoutWaitingForImpossibleReply(t *testing.T) {
	f := newConnectorFixture(t, "quic")
	setup, stop := context.WithTimeout(t.Context(), 3*time.Second)
	defer stop()
	p, err := prepareConnectorConnection(t.Context(), setup, f.config, f.device)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close(context.WithoutCancel(t.Context()))
	independent := errors.New("independent authority stop")
	p.cancel(independent)
	p.requestRecovery(connectorRebinding)
	first := p.cleanup.context()
	deadline, _ := first.Deadline()
	if err := p.terminalUse(p.warm, independent); !errors.Is(err, independent) || !errors.Is(err, ErrServiceConnection) {
		t.Fatal("unavailable terminal exchange lost its original operation or claimed success", err)
	}
	if err := p.Close(first); !errors.Is(err, ErrServiceConnection) || errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("stopped binding hid its unavailable exchange or exhausted the cleanup budget", err)
	}
	f.mu.Lock()
	peer := f.peers[p.pair.PairId]
	retired := peer != nil && peer.retired
	f.mu.Unlock()
	if !retired {
		t.Fatal("stopped packet binding consumed the budget before authenticated retirement")
	}
	if next, _ := p.cleanup.context().Deadline(); !next.Equal(deadline) {
		t.Fatal("retirement restarted the original cleanup budget", next, deadline)
	}
}

func TestConnectorRetirementUsesCapturedSignerAndIdenticalRetry(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{19}, ed25519.SeedSize))
	sessionKey := [32]byte{7, 9}
	pair := controlv1.ConnectorPeerPair{
		ServiceId: "svc_aaaaaaaaaaaaaaaaaaaaaa", ServiceRunId: "srun_aaaaaaaaaaaaaaaaaaaaaa", RunNumber: 1,
		PublisherIdentityId: "pub_aaaaaaaaaaaaaaaaaaaaaa", PairId: "cpp_aaaaaaaaaaaaaaaaaaaaaa",
		DeliveryId: "AQEBAQEBAQEBAQEBAQEBAQ", ObservedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute),
		SessionKey: base64.RawURLEncoding.EncodeToString(sessionKey[:]),
	}
	owner := "ik_aaaaaaaaaaaaaaaaaaaaaa"
	public := private.Public().(ed25519.PublicKey)
	fixture := connectorfixture.NewRetirement(pair, owner, public, sessionKey)
	config := unreachableControlConfig()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	var first controlv1.ConnectorPeerPairRetireRequest
	calls := 0
	config.RetirePair = func(got context.Context, service, pairID string, body controlv1.ConnectorPeerPairRetireRequest) (controlv1.ConnectorPeerPairRetirement, error) {
		if got != ctx || service != pair.ServiceId || pairID != pair.PairId {
			t.Fatal("retirement reselected its scope or cleanup context")
		}
		calls++
		if calls == 1 {
			first = body
			return controlv1.ConnectorPeerPairRetirement{}, io.ErrUnexpectedEOF
		}
		if body != first {
			t.Fatal("lost-reply retry changed its immutable signed request")
		}
		return fixture.Retire(got, service, pairID, body)
	}
	control, err := NewControlWithConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	r := &connectorRetirement{pair: pair, key: sessionKey, signer: Signer{PublicKey: public, Sign: func(message []byte) []byte {
		return ed25519.Sign(private, message)
	}}}
	if err := r.retire(ctx, control, owner); err != nil || calls != 2 {
		t.Fatal("captured signer could not retire after current authority became unavailable", err, calls)
	}
	spent, stop := context.WithCancel(ctx)
	stop()
	if err := r.retire(spent, control, owner); !errors.Is(err, context.Canceled) || calls != 2 {
		t.Fatal("spent cleanup started another retirement operation", err, calls)
	}
}
