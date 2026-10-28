package daemon

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	"github.com/tnldotdev/tnl/internal/connector/workload"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/githubtest"
	"github.com/tnldotdev/tnl/internal/transport/peer"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// the local packet fault socket keeps the accepted source IP at 127.0.0.1.
// it drops datagrams, never supplies source metadata or changes signed claims.
func startNativePacketFaultSocket(t *testing.T, address, target string) *atomic.Bool {
	t.Helper()
	local, err := net.ResolveUDPAddr("udp4", address)
	if err != nil {
		t.Fatal(err)
	}
	remote, err := net.ResolveUDPAddr("udp4", target)
	if err != nil {
		t.Fatal(err)
	}
	socket, err := net.ListenUDP("udp4", local)
	if err != nil {
		t.Fatal(err)
	}
	drop := new(atomic.Bool)
	done := make(chan struct{})
	go func() {
		defer close(done)
		// preserve each sender's UDP mapping. the default publisher and connector
		// both use this advertised address; a last-sender proxy mixes their QUIC.
		upstreams := make(map[string]*net.UDPConn)
		var readers sync.WaitGroup
		defer func() {
			for _, upstream := range upstreams {
				_ = upstream.Close()
			}
			readers.Wait()
		}()
		packet := make([]byte, 64*1024)
		for {
			n, source, err := socket.ReadFromUDP(packet)
			if err != nil {
				return
			}
			if drop.Load() {
				continue
			}
			upstream := upstreams[source.String()]
			if upstream == nil {
				if len(upstreams) == 64 {
					continue
				}
				upstream, err = net.DialUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, remote)
				if err != nil {
					return
				}
				upstreams[source.String()] = upstream
				readers.Go(func() {
					response := make([]byte, 64*1024)
					for {
						n, err := upstream.Read(response)
						if err != nil {
							return
						}
						if !drop.Load() {
							_, _ = socket.WriteToUDP(response[:n], source)
						}
					}
				})
			}
			_, _ = upstream.Write(packet[:n])
		}
	}()
	t.Cleanup(func() { _ = socket.Close(); <-done })
	return drop
}

// the publisher is connected before the native connector starts. sequence
// snapshots let faults close only later accepted native sessions on this listener.
type nativeTrackedListener struct {
	net.Listener
	mu   sync.Mutex
	next uint64
	live map[*nativeTrackedConnection]uint64
}

type nativeTrackedConnection struct {
	net.Conn
	owner *nativeTrackedListener
}

func (l *nativeTrackedListener) Accept() (net.Conn, error) {
	connection, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	tracked := &nativeTrackedConnection{Conn: connection, owner: l}
	l.mu.Lock()
	l.next++
	l.live[tracked] = l.next
	l.mu.Unlock()
	return tracked, nil
}

func (c *nativeTrackedConnection) Close() error {
	err := c.Conn.Close()
	c.owner.mu.Lock()
	delete(c.owner.live, c)
	c.owner.mu.Unlock()
	return err
}

func (l *nativeTrackedListener) snapshot() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.next
}

func (l *nativeTrackedListener) after(sequence uint64) []*nativeTrackedConnection {
	l.mu.Lock()
	defer l.mu.Unlock()
	var connections []*nativeTrackedConnection
	for connection, accepted := range l.live {
		if accepted > sequence {
			connections = append(connections, connection)
		}
	}
	return connections
}

func TestIntegrationPeerPacketsKeepNativeTargetAcrossRelayPacketLoss(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	for _, publisher := range []string{"quic", "tls-tcp"} {
		t.Run(publisher, func(t *testing.T) {
			for _, carriers := range []struct {
				name    string
				tcp     [2]bool
				loseTCP int
			}{
				{"quic-quic", [2]bool{}, -1},
				{"quic-tcp", [2]bool{false, true}, 1},
				{"tcp-quic", [2]bool{true, false}, 0},
				{"tcp-tcp-lose-a", [2]bool{true, true}, 0},
				{"tcp-tcp-lose-b", [2]bool{true, true}, 1},
			} {
				t.Run(carriers.name, func(t *testing.T) {
					exerciseNativePacketContinuity(t, publisher, carriers.tcp, carriers.loseTCP, false, false)
				})
			}
		})
	}
}

func TestIntegrationPeerPacketsRenewNativeClaimsWithoutReopeningTarget(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	exerciseNativePacketContinuity(t, "quic", [2]bool{false, true}, 1, true, false)
}

func TestIntegrationPeerPacketsReconnectBothNativeCarriersWithoutReopeningTarget(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	for _, publisher := range []string{"quic", "tls-tcp"} {
		t.Run(publisher, func(t *testing.T) {
			exerciseNativePacketContinuity(t, publisher, [2]bool{true, true}, -2, false, false)
		})
	}
}

func TestIntegrationPeerPacketsUpgradeNativeTargetToDirectUDP(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	for _, publisher := range []string{"default", "tls-tcp"} {
		t.Run(publisher, func(t *testing.T) {
			exerciseNativePacketContinuity(t, publisher, [2]bool{}, -1, false, true)
		})
	}
}

func exerciseNativePacketContinuity(t *testing.T, publisher string, tcp [2]bool, loseTCP int, renew, direct bool) {
	t.Helper()
	f, issuer := newWorkloadTransportFixtureTopology(t, nil, serviceRuntimeTopologyOptions{nativePeers: true})
	var directReady [2]atomic.Bool
	iceGate := make(chan struct{})
	var release sync.Once
	releaseICE := func() { release.Do(func() { close(iceGate) }) }
	defer releaseICE()
	connectivity := func(side int) peer.ConnectivityOptions {
		return peer.ConnectivityOptions{DisableDirect: !direct, IncludeLoopback: true, Observe: func(state peer.ConnectivityState) {
			if state == peer.ConnectivityChecking {
				<-iceGate
			}
			directReady[side].Store(state == peer.ConnectivityDirect)
		}}
	}
	f.peerConnectivity = connectivity(1)
	// health probes may connect and close, but only a socket that receives
	// application bytes gets an ID. a reopened target cannot restart its counter.
	target := serviceRuntimeListener(t)
	var targets atomic.Uint64
	var workers sync.WaitGroup
	targetCtx, stopTarget := context.WithCancel(t.Context())
	workers.Go(func() {
		for {
			connection, err := target.Accept()
			if err != nil {
				return
			}
			workers.Go(func() {
				defer connection.Close()
				stop := context.AfterFunc(targetCtx, func() { _ = connection.Close() })
				defer stop()
				var id, counter uint64
				for {
					var input [1]byte
					if _, err := io.ReadFull(connection, input[:]); err != nil {
						return
					}
					if id == 0 {
						id = targets.Add(1)
					}
					counter++
					reply := binary.BigEndian.AppendUint64(nil, id)
					reply = binary.BigEndian.AppendUint64(reply, counter)
					if _, err := connection.Write(reply); err != nil {
						return
					}
				}
			})
		}
	})
	t.Cleanup(func() { stopTarget(); _ = target.Close(); workers.Wait() })
	group, protocol := "native", controlv1.Tcp
	policies := map[string]controlv1.ProjectWorkload{"test": {Provider: controlv1.WorkloadGitHub,
		Github:   &controlv1.ProjectWorkloadGitHub{Repository: "example/repository", RepositoryId: "12345", RepositoryOwnerId: "6789", WorkflowRef: "example/repository/.github/workflows/test.yml@refs/heads/main", Ref: "refs/heads/main", Events: []string{"push"}},
		Services: []string{"echo"}, MaxDurationSeconds: 60}}
	if renew {
		policy := policies["test"]
		policy.MaxDurationSeconds = 300
		policies["test"] = policy
	}
	_, err := f.identity.routes.ApplyProjectConfiguration(t.Context(), "workload", controlv1.ApplyProjectConfigurationRequest{TeamId: f.identity.teamID, SourceFingerprint: strings.Repeat("a", 64),
		Configuration: controlv1.ProjectConfiguration{Workloads: &policies, PublisherGroups: map[string]controlv1.ProjectPublisherGroup{group: {}},
			Services: map[string]controlv1.ProjectServiceConfiguration{"echo": {PublisherGroup: &group, Protocol: &protocol, Target: target.Addr().String()}}, Webhooks: map[string]controlv1.ProjectWebhook{}}})
	if err != nil {
		t.Fatal(err)
	}
	startWorkloadPublishers(t, f, group, publisher)
	job, err := workload.New(f.controlConfig.ControlOrigin(), f.publicHTTP)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := job.Exchange(t.Context(), f.identity.teamID, "workload", strings.Repeat("a", 64), "test", issuer.Sign(t, githubtest.Claims(f.controlConfig.ControlOrigin(), time.Now())), []string{"echo"}); err != nil {
		t.Fatal(err)
	}
	inventory, err := job.ListServices(t.Context())
	if err != nil || len(inventory.Services) != 1 {
		t.Fatal("native inventory", err)
	}
	control, err := connectorstream.NewWorkloadControl(job)
	if err != nil {
		t.Fatal(err)
	}
	run, err := control.ResolveService(t.Context(), inventory.Services[0].Id)
	if err != nil || run.PairReady == nil {
		t.Fatal("native pair selection", err)
	}
	var faults [2]*atomic.Bool
	var listeners [2]*nativeTrackedListener
	var accepted [2]uint64
	for slot, relay := range run.PairReady.Relays {
		faults[slot], listeners[slot] = f.nativePacketDrops[relay.RelayAddress], f.nativeTCPListeners[relay.RelayAddress]
		if faults[slot] == nil || listeners[slot] == nil {
			t.Fatal("missing exact relay fault listeners")
		}
		accepted[slot] = listeners[slot].snapshot()
		// UDP loss selects the ordinary joined TLS/TCP fallback at startup.
		faults[slot].Store(tcp[slot])
	}
	listener := serviceRuntimeListener(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ready, done := make(chan struct{}), make(chan error, 1)
	go func() {
		done <- connectorstream.Serve(ctx, listener, connectorstream.Config{Control: control, NativePeers: true, PeerConnectivity: connectivity(0), ServiceID: run.ServiceID, Protocol: run.Protocol,
			TrustRevision: run.TrustRevision, Endpoint: run.Endpoint, TransportTLS: f.roots, ServiceTLS: f.visitorRoots, Ready: func() error { close(ready); return nil }})
	}()
	defer func() {
		releaseICE()
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Error("native connector did not join")
		}
	}()
	select {
	case <-ready:
	case err := <-done:
		done <- err
		t.Fatal("native packet startup", err)
	case <-time.After(20 * time.Second):
		t.Fatal("native packet startup timed out")
	}
	for slot := range 2 {
		expected := 0
		if tcp[slot] {
			expected = 1
		}
		privateWait(t, time.Second, func(context.Context) (bool, error) {
			return len(listeners[slot].after(accepted[slot])) == expected, nil
		})
	}
	connection, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	check := func(counter uint64) {
		t.Helper()
		started := time.Now()
		// the default peer liveness window is three seconds. inner QUIC may
		// then need a retransmission timeout; this is a continuity bound, not
		// a five-second recovery SLO. retain the measured recovery in the log.
		_ = connection.SetDeadline(started.Add(10 * time.Second))
		if _, err := connection.Write([]byte{byte(counter)}); err != nil {
			t.Fatal(err)
		}
		var reply [16]byte
		if _, err := io.ReadFull(connection, reply[:]); err != nil {
			t.Fatalf("native packet continuity at counter %d (targets %d): %v", counter, targets.Load(), err)
		}
		if binary.BigEndian.Uint64(reply[:8]) != 1 || binary.BigEndian.Uint64(reply[8:]) != counter {
			t.Fatal("packet loss reopened the target or replayed application bytes")
		}
		t.Logf("native counter=%d recovery=%s", counter, time.Since(started).Round(time.Millisecond))
	}
	check(1)
	counter := uint64(1)
	if direct {
		if directReady[0].Load() || directReady[1].Load() {
			t.Fatal("ICE gate did not keep startup relay-first")
		}
		releaseICE()
		privateWait(t, 10*time.Second, func(context.Context) (bool, error) {
			return directReady[0].Load() && directReady[1].Load(), nil
		})
		// both relay UDP deliveries are unavailable: only the selected ICE path
		// can carry the retained inner connection's application bytes.
		for _, fault := range faults {
			fault.Store(true)
		}
		counter++
		check(counter)
		for _, fault := range faults {
			fault.Store(false)
		}
	}
	if renew {
		var original, firstClaim time.Time
		if err := f.inspect.QueryRowContext(t.Context(), `SELECT expires_at FROM control.native_peer_pairs WHERE service_id=$1`, run.ServiceID).Scan(&original); err != nil {
			t.Fatal(err)
		}
		if err := f.inspect.QueryRowContext(t.Context(), `SELECT max(requested_at) FROM control.native_peer_pair_leg_claims`).Scan(&firstClaim); err != nil {
			t.Fatal(err)
		}
		if original.After(time.Now().Add(95 * time.Second)) {
			t.Fatal("pair exceeded its original 90-second workload lease")
		}
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		nextRenewal := time.Now().Add(30 * time.Second)
		for time.Now().Before(original.Add(2 * time.Second)) {
			select {
			case <-ctx.Done():
				t.Fatal(context.Cause(ctx))
			case <-ticker.C:
			}
			if !time.Now().Before(nextRenewal) {
				if _, err := job.Renew(t.Context()); err != nil {
					t.Fatal("renew parent workload lease", err)
				}
				nextRenewal = time.Now().Add(30 * time.Second)
			}
			counter++
			check(counter)
		}
		var current, lastClaim time.Time
		if err := f.inspect.QueryRowContext(t.Context(), `SELECT expires_at FROM control.native_peer_pairs WHERE service_id=$1`, run.ServiceID).Scan(&current); err != nil {
			t.Fatal(err)
		}
		if err := f.inspect.QueryRowContext(t.Context(), `SELECT min(requested_at) FROM control.native_peer_pair_leg_claims`).Scan(&lastClaim); err != nil {
			t.Fatal(err)
		}
		if !current.After(original) || !lastClaim.After(firstClaim.Add(time.Second)) {
			t.Fatal("application survived without renewing both checked relay claims", original, current, firstClaim, lastClaim)
		}
		t.Logf("one target survived the original pair deadline; both relay claims advanced by at least %s", lastClaim.Sub(firstClaim).Round(time.Millisecond))
	}
	for slot := range 2 {
		if tcp[slot] || direct {
			continue
		}
		faults[slot].Store(true)
		counter++
		check(counter)
		faults[slot].Store(false)
		// allow a fresh delivery probe on the restored carrier before retiring
		// its sibling. this does not reopen or readmit the application stream.
		time.Sleep(1500 * time.Millisecond)
	}
	if loseTCP >= 0 {
		connections := listeners[loseTCP].after(accepted[loseTCP])
		if len(connections) != 1 {
			t.Fatal("native TCP fault did not select one exact outer session", len(connections))
		}
		if err := connections[0].Close(); err != nil {
			t.Fatal(err)
		}
		counter++
		check(counter)
	}
	if loseTCP == -2 {
		// require each recovered socket before closing both successors together.
		// no surviving old carrier can hide a failed handoff on either slot.
		for round := range 2 {
			for slot := range 2 {
				connections := listeners[slot].after(accepted[slot])
				if len(connections) != 1 {
					t.Fatal("reconnect fault did not select one exact native socket", slot, len(connections))
				}
				accepted[slot] = listeners[slot].snapshot()
				if err := connections[0].Close(); err != nil {
					t.Fatal(err)
				}
				if round == 0 {
					privateWait(t, 5*time.Second, func(context.Context) (bool, error) {
						return len(listeners[slot].after(accepted[slot])) == 1, nil
					})
					counter++
					check(counter)
				}
			}
			counter++
			check(counter)
		}
	}
	counter++
	check(counter)
	var pairs, claims, ingresses int
	var prepared bool
	if err := f.inspect.QueryRowContext(t.Context(), `SELECT count(*),bool_and(publisher_prepared_until>now()) FROM control.native_peer_pairs WHERE service_id=$1`, run.ServiceID).Scan(&pairs, &prepared); err != nil {
		t.Fatal(err)
	}
	if err := f.inspect.QueryRowContext(t.Context(), `SELECT count(*) FROM control.native_peer_pair_leg_claims`).Scan(&claims); err != nil {
		t.Fatal(err)
	}
	if err := f.inspect.QueryRowContext(t.Context(), `SELECT count(*) FROM control.ingress_leases`).Scan(&ingresses); err != nil {
		t.Fatal(err)
	}
	if targets.Load() != 1 || pairs != 1 || claims != 2 || !prepared || ingresses != 0 {
		t.Fatal("native continuity bypassed preparation, used ingress, or repeated target work", targets.Load(), pairs, claims, prepared, ingresses)
	}
}
