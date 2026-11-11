package daemon

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/transport/peer"
)

func TestIntegrationConnectorDirectDefaultComposition(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	f := newServiceRuntimeFixture(t, false, nil)
	target := startPrivateEchoTarget(t)
	observations := connectorDirectObservations(t)
	options := connectorDirectOptions(observations)
	gate := make(chan struct{})
	release := sync.OnceFunc(func() { close(gate) })
	defer release()
	for side := range options {
		options[side].Observe = func(state peer.ConnectivityState) {
			observations[side].observe(state)
			if state == peer.ConnectivityChecking {
				select {
				case <-gate:
				case <-t.Context().Done():
				}
			}
		}
	}
	// no socket or relay connector override: both native owners create their own
	// shared physical UDP socket, and the daemon's real relay socket serves STUN.
	prepared := startConnectorDirectRuntime(t, f, target.address, [2]*peer.Socket{}, options)
	defer func() { release(); prepared.stop() }()
	waitConnectorDirectState(t, observations, peer.ConnectivityChecking)
	connection, err := net.DialTimeout("tcp", prepared.listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	connectorDirectExchange(t, connection, "before-default-ICE\n")
	before := readRebindingObservation(t, f, prepared.service.Id)
	if observations[0].count(peer.ConnectivityDirect) != 0 || observations[1].count(peer.ConnectivityDirect) != 0 {
		t.Fatal("application startup waited for or bypassed the held ICE check")
	}
	release()
	waitConnectorDirectState(t, observations, peer.ConnectivityDirect)
	connectorDirectExchange(t, connection, "after-default-ICE\n")
	assertConnectorDirectTarget(t, target, []string{"before-default-ICE\n", "after-default-ICE\n"})
	assertConnectorDirectOwner(t, f, prepared, before, false)
}

func TestIntegrationConnectorDirectRetriesAndRepeatedFallback(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	f := newServiceRuntimeFixture(t, false, nil)
	target := startPrivateEchoTarget(t)
	observations := connectorDirectObservations(t)
	sockets, packets := connectorDirectSockets(t, f, nil)
	for _, packet := range packets {
		// ICE may nominate the first attempt, but no authenticated packet probe
		// can complete. a later attempt must recover without another application.
		packet.rejectThrough.Store(^uint64(0))
	}
	prepared := startConnectorDirectRuntime(t, f, target.address, sockets, connectorDirectOptions(observations))
	defer prepared.stop()
	connection, err := net.DialTimeout("tcp", prepared.listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	var messages []string
	exchange := func(message string) {
		messages = append(messages, message)
		connectorDirectExchange(t, connection, message)
	}
	exchange("before-first-direct-attempt\n")
	before := readRebindingObservation(t, f, prepared.service.Id)
	privateWait(t, 10*time.Second, func(context.Context) (bool, error) {
		return packets[0].latestAttempt.Load() >= 1 && packets[1].latestAttempt.Load() >= 1 && packets[0].directDropped.Load() > 0 && packets[1].directDropped.Load() > 0, nil
	})
	for side, packet := range packets {
		if observations[side].count(peer.ConnectivityDirect) != 0 || packet.directDataSent.Load() != 0 || packet.directDataRead.Load() != 0 || packet.relaySent.Load() == 0 || packet.relayRead.Load() == 0 || packet.stunSent.Load() == 0 {
			t.Fatal("first withheld direct attempt did not leave real relay traffic usable", side)
		}
	}
	exchange("while-first-direct-attempt-is-withheld\n")
	for _, packet := range packets {
		packet.rejectThrough.Store(1)
	}
	waitConnectorDirectState(t, observations, peer.ConnectivityDirect)
	for _, packet := range packets {
		if packet.latestAttempt.Load() < 2 {
			t.Fatal("direct delivery did not retry with a fresh attempt")
		}
	}
	for round := range 2 {
		connectorDirectOnly(t, packets, func() { exchange(fmt.Sprintf("direct-only-%d\n", round)) })
		packets[0].blockDirect.Store(true)
		exchange(fmt.Sprintf("during-direct-loss-%d\n", round))
		waitConnectorDirectState(t, observations, peer.ConnectivityRelay)
		sent, read, relay := packets[0].directDataSent.Load(), packets[0].directDataRead.Load(), packets[0].relaySent.Load()
		exchange(fmt.Sprintf("relay-fallback-%d\n", round))
		if packets[0].directDataSent.Load() != sent || packets[0].directDataRead.Load() != read || packets[0].relaySent.Load() <= relay {
			t.Fatal("application fallback did not use relays while direct UDP was blocked")
		}
		packets[0].blockDirect.Store(false)
		waitConnectorDirectState(t, observations, peer.ConnectivityDirect)
	}
	connectorDirectOnly(t, packets, func() { exchange("after-repeated-direct-recovery\n") })
	assertConnectorDirectTarget(t, target, messages)
	assertConnectorDirectOwner(t, f, prepared, before, false)
}

func TestIntegrationConnectorDirectSourceRebinding(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	if runtime.GOOS != "linux" {
		t.Skip("real multi-source loopback sockets require Linux")
	}
	f := newServiceRuntimeFixture(t, false, nil)
	target := startPrivateEchoTarget(t)
	observations := connectorDirectObservations(t)
	source := new(atomic.Uint32)
	source.Store(1)
	sockets, packets := connectorDirectSockets(t, f, source)
	prepared := startConnectorDirectRuntime(t, f, target.address, sockets, connectorDirectOptions(observations))
	defer prepared.stop()
	connection, err := net.DialTimeout("tcp", prepared.listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	var messages []string
	exchange := func(message string) {
		messages = append(messages, message)
		connectorDirectExchange(t, connection, message)
	}
	exchange("before-source-change\n")
	before := readRebindingObservation(t, f, prepared.service.Id)
	waitConnectorDirectState(t, observations, peer.ConnectivityDirect)
	connectorDirectOnly(t, packets, func() { exchange("direct-before-source-change\n") })
	previous := before
	for round, next := range []uint32{2, 1} {
		// switch the physical sending socket beneath the same live outer QUIC
		// dialer. TCP is disabled, so no fallback can retain the departed source. no inner
		// session close, spoofed address, or control request triggers recovery.
		packets[0].blockDirect.Store(true)
		source.Store(next)
		privateWait(t, 25*time.Second, func(ctx context.Context) (bool, error) {
			var generation int64
			var sourceCurrent bool
			err := f.inspect.QueryRowContext(ctx, `SELECT p.delivery_generation,count(c.connection_slot)=2 AND bool_and(c.source_ip=$2::inet)
				FROM control.connector_peer_pairs p LEFT JOIN control.connector_peer_pair_leg_claims c ON c.pair_id=p.id AND c.delivery_generation=p.delivery_generation
				WHERE p.id=$1 GROUP BY p.delivery_generation`, before.pairID, fmt.Sprintf("127.0.0.%d", next)).Scan(&generation, &sourceCurrent)
			return generation > previous.generation && sourceCurrent, err
		})
		t.Logf("source handoff=%d address=127.0.0.%d previous generation=%d current generation=%d", round, next, previous.generation, readRebindingObservation(t, f, prepared.service.Id).generation)
		exchange(fmt.Sprintf("authorized-source-relay-%d\n", round))
		packets[0].blockDirect.Store(false)
		waitConnectorDirectState(t, observations, peer.ConnectivityDirect)
		connectorDirectOnly(t, packets, func() { exchange(fmt.Sprintf("direct-after-source-change-%d\n", round)) })
		previous = readRebindingObservation(t, f, prepared.service.Id)
	}
	assertConnectorDirectTarget(t, target, messages)
	assertConnectorDirectOwner(t, f, prepared, before, true)
}

func TestIntegrationConnectorDirectFailedChecksAndConsentExpiry(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	f := newServiceRuntimeFixture(t, false, nil)
	target := startPrivateEchoTarget(t)
	observations := connectorDirectObservations(t)
	sockets, packets := connectorDirectSockets(t, f, nil)
	packets[0].blockChecks.Store(true)
	prepared := startConnectorDirectRuntime(t, f, target.address, sockets, connectorDirectOptions(observations))
	defer prepared.stop()
	connection, err := net.DialTimeout("tcp", prepared.listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	var messages []string
	exchange := func(message string) {
		messages = append(messages, message)
		connectorDirectExchange(t, connection, message)
	}
	exchange("before-failed-ICE-checks\n")
	before := readRebindingObservation(t, f, prepared.service.Id)
	privateWait(t, 25*time.Second, func(context.Context) (bool, error) {
		return observations[0].count(peer.ConnectivityChecking) >= 2 && observations[1].count(peer.ConnectivityChecking) >= 2, nil
	})
	if packets[0].checksDropped.Load() == 0 || observations[0].count(peer.ConnectivityDirect) != 0 || observations[1].count(peer.ConnectivityDirect) != 0 {
		t.Fatal("initial ICE check failure was not isolated from relay delivery")
	}
	exchange("while-ICE-checks-fail\n")
	packets[0].blockChecks.Store(false)
	waitConnectorDirectState(t, observations, peer.ConnectivityDirect)
	connectorDirectOnly(t, packets, func() { exchange("after-failed-ICE-checks\n") })

	// only peer STUN checks stop: relay discovery, authenticated packet probes,
	// and application bytes keep flowing until consent independently expires.
	sent, read := packets[0].directDataSent.Load(), packets[0].directDataRead.Load()
	packets[0].blockChecks.Store(true)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for step := 0; !observations[0].relaying() || !observations[1].relaying(); step++ {
		exchange(fmt.Sprintf("while-consent-expires-%d\n", step))
		select {
		case <-ctx.Done():
			t.Fatal("direct delivery retained expired consent while payload continued")
		case <-ticker.C:
		}
	}
	if packets[0].directDataSent.Load() <= sent || packets[0].directDataRead.Load() <= read || packets[0].blockDirect.Load() {
		t.Fatal("consent fault also stopped direct application packets")
	}
	exchange("relay-after-consent-expiry\n")
	packets[0].blockChecks.Store(false)
	waitConnectorDirectState(t, observations, peer.ConnectivityDirect)
	connectorDirectOnly(t, packets, func() { exchange("after-consent-recovery\n") })
	assertConnectorDirectTarget(t, target, messages)
	assertConnectorDirectOwner(t, f, prepared, before, false)
}
