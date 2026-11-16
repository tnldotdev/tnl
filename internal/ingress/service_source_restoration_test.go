package ingress

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

var restorationSourceMaster = [32]byte{1}

// these connections capture ingress-created metadata without adding a relay,
// target protocol, capacity callback, or another signing implementation.
type restorationSourceConn struct {
	mu   sync.Mutex
	data []byte
}

func (*restorationSourceConn) Read([]byte) (int, error) { return 0, io.EOF }
func (c *restorationSourceConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data = append(c.data, p...)
	return len(p), nil
}
func (*restorationSourceConn) Close() error                     { return nil }
func (*restorationSourceConn) CloseWrite() error                { return nil }
func (*restorationSourceConn) LocalAddr() net.Addr              { return &net.TCPAddr{Port: 443} }
func (*restorationSourceConn) RemoteAddr() net.Addr             { return &net.TCPAddr{Port: 42000} }
func (*restorationSourceConn) SetDeadline(time.Time) error      { return nil }
func (*restorationSourceConn) SetReadDeadline(time.Time) error  { return nil }
func (*restorationSourceConn) SetWriteDeadline(time.Time) error { return nil }

type restorationSourceRecord struct {
	header tunnelv1.ServiceForwardingHeader
	stream *restorationSourceConn
}

type restorationSourceForwarder struct {
	mu      sync.Mutex
	records []restorationSourceRecord
}

func (f *restorationSourceForwarder) OpenService(_ context.Context, _ ingressv1.ServiceRelay, header tunnelv1.ServiceForwardingHeader, _ func(context.Context) error) (net.Conn, error) {
	stream := &restorationSourceConn{}
	f.mu.Lock()
	f.records = append(f.records, restorationSourceRecord{header: header, stream: stream})
	f.mu.Unlock()
	return stream, nil
}

func (f *restorationSourceForwarder) snapshot() []restorationSourceRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.records)
}

type restorationLease struct {
	mu    sync.Mutex
	value ingressv1.IngressLease
}

func (l *restorationLease) current() ingressv1.IngressLease {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.value
}

func (l *restorationLease) set(value ingressv1.IngressLease) {
	l.mu.Lock()
	l.value = value
	l.mu.Unlock()
}

type restorationServiceFixture struct {
	server    *Server
	forwarder *restorationSourceForwarder
	lease     *restorationLease
	snapshot  ingressv1.IngressServices
}

func restorationService(t *testing.T) *restorationServiceFixture {
	t.Helper()
	lease, snapshot := serviceRoutingFixture(t)
	config, _, _, _ := publicServiceTestConfig(t)
	current := &restorationLease{value: lease}
	forwarder := &restorationSourceForwarder{}
	config.CurrentLease, config.Forwarder = current.current, forwarder
	// the old signing workload has 100 concurrent callers. use an existing
	// approved ceiling, not a larger ceiling or a production capacity change.
	snapshot.Runs[0].Anonymous = true
	snapshot.Runs[0].Traffic = publicServiceTraffic(trafficFixture(t).config.Ceiling)
	return &restorationServiceFixture{server: serviceSelectionServer(t, config), forwarder: forwarder,
		lease: current, snapshot: snapshot}
}

func restorationDelegate(t *testing.T, lease ingressv1.IngressLease, run *ingressv1.IngressServiceRun, observed, expires time.Time) {
	t.Helper()
	authority, key, err := visitortoken.IssueVisitorSourceAuthority(restorationSourceMaster, tunnelv1.VisitorSourceAuthority{
		ServiceID: run.ServiceId, ServiceRunID: run.ServiceRunId, RunNumber: uint64(run.RunNumber),
		EndpointRevision: run.EndpointRevision, IngressID: lease.IngressId, IngressRunID: lease.IngressRunId,
		IngressLeaseRevision: uint64(lease.IngressLeaseRevision), VisitorPolicyRevision: 1, ValidUntil: expires.Unix(),
	}, observed)
	if err != nil {
		t.Fatal(err)
	}
	run.SourceAuthority, err = authority.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	run.SourceKey = slices.Clone(key[:])
}

func restorationAdvance(duration time.Duration) {
	synctest.Wait()
	time.Sleep(duration)
	synctest.Wait()
}

func restorationRequireClosed(t *testing.T, ch <-chan struct{}, boundary string) {
	t.Helper()
	select {
	case <-ch:
	default:
		t.Fatal("worker did not reach " + boundary)
	}
}

func restorationVerifySource(t *testing.T, record restorationSourceRecord, now time.Time) tunnelv1.VisitorSourceProof {
	t.Helper()
	record.stream.mu.Lock()
	wire := slices.Clone(record.stream.data)
	record.stream.mu.Unlock()
	metadata, _, err := proxyproto.Decode(bytes.NewReader(wire))
	if err != nil {
		t.Fatal("actual ingress did not write source metadata", err)
	}
	proof, err := tunnelv1.ReadVisitorSourceProof([]byte(metadata.VisitorSourceProof))
	if err != nil {
		t.Fatal("actual ingress did not sign source evidence", err)
	}
	header := record.header
	binding := tunnelv1.VisitorSourceBinding{ServiceID: header.ServiceID, ServiceRunID: header.ServiceRunID,
		RunNumber: header.RunNumber, VisitorConnectionID: header.VisitorConnectionID,
		Source: metadata.Source, Destination: metadata.Destination}
	if header.PublicService == nil || proof.Authority.IngressID != header.PublicService.IngressID ||
		proof.Authority.IngressRunID != header.PublicService.IngressRunID ||
		proof.Authority.IngressLeaseRevision != header.PublicService.IngressLeaseRevision {
		t.Fatal("source evidence was not bound to the actual ingress process")
	}
	if err := visitortoken.VerifyVisitorSource(restorationSourceMaster, proof, binding, 1, now); err != nil {
		t.Fatal("actual ingress source signature did not verify", err)
	}
	return proof
}

func restorationSignSource(t *testing.T, f *restorationServiceFixture) tunnelv1.VisitorSourceProof {
	t.Helper()
	before := len(f.forwarder.snapshot())
	err := f.server.AcceptPublic(t.Context(), &restorationSourceConn{},
		netip.MustParseAddrPort("192.0.2.4:42000"), netip.MustParseAddrPort("203.0.113.8:443"), "route.example", nil)
	if err != nil {
		t.Fatal("actual HTTP source signing failed", err)
	}
	records := f.forwarder.snapshot()
	if len(records) != before+1 {
		t.Fatal("source signing did not open exactly one metadata stream", len(records)-before)
	}
	return restorationVerifySource(t, records[before], time.Now())
}

func restorationRejectSource(t *testing.T, f *restorationServiceFixture) {
	t.Helper()
	before := len(f.forwarder.snapshot())
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	joined := make(chan struct{})
	var result error
	go func() {
		defer close(joined)
		result = f.server.AcceptPublic(ctx, &restorationSourceConn{},
			netip.MustParseAddrPort("192.0.2.4:42000"), netip.MustParseAddrPort("203.0.113.8:443"), "route.example", nil)
	}()
	// a first cache miss may wait for a background snapshot. observe that wait,
	// then cancel and join it without inventing a shorter setup timeout.
	synctest.Wait()
	cancel()
	synctest.Wait()
	restorationRequireClosed(t, joined, "rejected source visitor cleanup")
	if result == nil || len(f.forwarder.snapshot()) != before {
		t.Fatal("unavailable source evidence admitted a visitor or opened a relay", result)
	}
}

func TestServiceSourceRestorationRejectsInvalidDelegationsBeforeRelayOpen(t *testing.T) {
	for _, name := range []string{"missing_key", "zero_key", "missing_authority", "endpoint_revision", "shorter_run_expiry", "ingress_run"} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := restorationService(t)
				defer f.server.Close()
				run := &f.snapshot.Runs[0]
				switch name {
				case "missing_key":
					run.SourceKey = nil
				case "zero_key":
					run.SourceKey = make([]byte, 32)
				case "missing_authority":
					run.SourceAuthority = nil
				case "endpoint_revision":
					// the old duplicate policy-revision projection is gone.
					// the current independently approved revision is the endpoint.
					run.EndpointRevision++
				case "shorter_run_expiry":
					run.ValidUntil = f.snapshot.ObservedAt.Add(time.Second)
				case "ingress_run":
					authority, err := tunnelv1.ReadVisitorSourceAuthority(run.SourceAuthority)
					if err != nil {
						t.Fatal(err)
					}
					authority.IngressRunID = publicServiceTestID(t, "ir_")
					run.SourceAuthority, err = authority.MarshalBinary()
					if err != nil {
						t.Fatal(err)
					}
				}
				if err := f.server.services.apply(time.Now(), f.lease.current(), f.snapshot); !errors.Is(err, ErrServiceAdmission) {
					t.Fatal("invalid source delegation did not fail before publication", err)
				}
				f.server.services.mu.Lock()
				runs, endpoints, counters := len(f.server.services.runs), len(f.server.services.endpoints), len(f.server.services.sourceCounters)
				f.server.services.mu.Unlock()
				if runs != 0 || endpoints != 0 || counters != 0 || f.server.RoutingReady(time.Now()) {
					t.Fatal("invalid delegation installed routing or source authority", runs, endpoints, counters)
				}
				restorationRejectSource(t, f)
			})
		})
	}
}

func TestServiceSourceRestorationSigningFailureNeverOpensRelay(t *testing.T) {
	for _, name := range []string{"unavailable_key", "missing_proof_authority", "expired_proof_authority"} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := restorationService(t)
				defer f.server.Close()
				if err := f.server.services.apply(time.Now(), f.lease.current(), f.snapshot); err != nil {
					t.Fatal(err)
				}
				// inject a signer failure after otherwise valid installation. this
				// exercises the production signing error path, not a fake signer.
				f.server.services.mu.Lock()
				route := f.server.services.runs[f.snapshot.Runs[0].ServiceRunId]
				switch name {
				case "unavailable_key":
					route.sourceKey = [32]byte{}
				case "missing_proof_authority":
					route.source.MAC = nil
				case "expired_proof_authority":
					route.source.ValidUntil = time.Now().Unix()
				}
				f.server.services.mu.Unlock()
				restorationRejectSource(t, f)
			})
		})
	}
}

func TestServiceSourceRestorationConcurrentProofsSurviveSnapshotReplacement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := restorationService(t)
		defer f.server.Close()
		var previousMAC []byte
		seen := make(map[uint64]bool)
		for round := range 2 {
			if round != 0 {
				restorationAdvance(100 * time.Millisecond)
				f.snapshot.ObservedAt = time.Now()
				f.snapshot.ValidUntil = time.Now().Add(visitortoken.PolicyLifetime)
				f.snapshot.Runs[0].ValidUntil = f.snapshot.ValidUntil
			}
			if err := f.server.services.apply(time.Now(), f.lease.current(), f.snapshot); err != nil {
				t.Fatal(err)
			}
			start := make(chan struct{})
			var ready, workers sync.WaitGroup
			ready.Add(100)
			for index := range 100 {
				workers.Go(func() {
					ready.Done()
					<-start
					source := netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(index + 1)}), 42000)
					if err := f.server.AcceptPublic(t.Context(), &restorationSourceConn{}, source,
						netip.MustParseAddrPort("203.0.113.8:443"), "route.example", nil); err != nil {
						t.Error("concurrent actual source signing failed", err)
					}
				})
			}
			ready.Wait()
			close(start)
			workers.Wait()
			records := f.forwarder.snapshot()
			if len(records) != (round+1)*100 {
				t.Fatal("concurrent signing lost visitors", len(records))
			}
			for _, record := range records[round*100:] {
				proof := restorationVerifySource(t, record, time.Now())
				if seen[proof.Sequence] || proof.Sequence <= uint64(round*100) {
					t.Fatal("snapshot replacement reused a consumed sequence", proof.Sequence)
				}
				seen[proof.Sequence] = true
				if previousMAC != nil && !bytes.Equal(previousMAC, proof.Authority.MAC) {
					t.Fatal("fixture did not retain the exact delegation across replacement")
				}
				previousMAC = slices.Clone(proof.Authority.MAC)
			}
		}
		if len(seen) != 200 {
			t.Fatal("not all concurrent signatures were verified")
		}
		if err := f.server.Close(); err != nil {
			t.Fatal(err)
		}
		restorationRejectSource(t, f)
	})
}

func TestServiceSourceRestorationOmissionKeepsProofSequenceButNoAuthority(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := restorationService(t)
		defer f.server.Close()
		sibling := restorationCloneSnapshot(t, f.snapshot).Runs[0]
		sibling.ServiceRunId, sibling.RunNumber, sibling.Hostname = publicServiceTestID(t, "srun_"), 2, "sibling.example"
		restorationDelegate(t, f.lease.current(), &sibling, f.snapshot.ObservedAt, f.snapshot.ValidUntil)
		f.snapshot.Runs = append(f.snapshot.Runs, sibling)
		if err := f.server.services.apply(time.Now(), f.lease.current(), f.snapshot); err != nil {
			t.Fatal(err)
		}
		first := restorationSignSource(t, f)
		recovering := restorationCloneSnapshot(t, f.snapshot)
		restorationAdvance(100 * time.Millisecond)
		f.snapshot.ObservedAt = time.Now()
		f.snapshot.ValidUntil = time.Now().Add(visitortoken.PolicyLifetime)
		f.snapshot.Runs = []ingressv1.IngressServiceRun{sibling}
		if err := f.server.services.apply(time.Now(), f.lease.current(), f.snapshot); err != nil {
			t.Fatal(err)
		}
		if len(f.server.services.lookup("route.example", 443, f.lease.current(), time.Now())) != 0 ||
			len(f.server.services.lookup("sibling.example", 443, f.lease.current(), time.Now())) != 1 {
			t.Fatal("omission retained target authority or removed its sibling")
		}
		restorationRejectSource(t, f)
		restorationAdvance(100 * time.Millisecond)
		recovering.ObservedAt, recovering.ValidUntil = time.Now(), time.Now().Add(visitortoken.PolicyLifetime)
		for index := range recovering.Runs {
			recovering.Runs[index].ValidUntil = recovering.ValidUntil
		}
		if err := f.server.services.apply(time.Now(), f.lease.current(), recovering); err != nil {
			t.Fatal(err)
		}
		second := restorationSignSource(t, f)
		if !bytes.Equal(first.Authority.MAC, second.Authority.MAC) || second.Sequence <= first.Sequence {
			t.Fatal("actual proof continuity was lost across omission and recovery")
		}
		// keep the actual refresh worker running while all runs are omitted.
		// only an applied newer observation may prune an expired source counter.
		restorationAdvance(100 * time.Millisecond)
		worker := restorationStartRefresh(t, f, func(context.Context, string, ingressv1.IngressLeaseIdentity) (ingressv1.IngressServices, error) {
			return ingressv1.IngressServices{ObservedAt: time.Now(), ValidUntil: time.Now().Add(visitortoken.PolicyLifetime)}, nil
		})
		defer worker.stop(t)
		synctest.Wait()
		restorationRejectSource(t, f)
		f.server.services.mu.Lock()
		beforePrune := len(f.server.services.sourceCounters)
		f.server.services.mu.Unlock()
		if beforePrune != 2 {
			t.Fatal("omission prematurely discarded still-live replay counters", beforePrune)
		}
		restorationAdvance(visitortoken.PolicyLifetime + time.Second)
		f.server.services.mu.Lock()
		retained := len(f.server.services.sourceCounters)
		f.server.services.mu.Unlock()
		if retained != 0 {
			t.Fatal("expired absent delegations retained source counters", retained)
		}
	})
}

func TestServiceSourceRestorationTamperedPolicyRevisionCannotVerify(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := restorationService(t)
		defer f.server.Close()
		if err := f.server.services.apply(time.Now(), f.lease.current(), f.snapshot); err != nil {
			t.Fatal(err)
		}
		proof := restorationSignSource(t, f)
		record := f.forwarder.snapshot()[0]
		binding := tunnelv1.VisitorSourceBinding{ServiceID: record.header.ServiceID, ServiceRunID: record.header.ServiceRunID,
			RunNumber: record.header.RunNumber, VisitorConnectionID: record.header.VisitorConnectionID,
			Source: netip.MustParseAddrPort("192.0.2.4:42000"), Destination: netip.MustParseAddrPort("203.0.113.8:443")}
		proof.Authority.VisitorPolicyRevision++
		if err := visitortoken.VerifyVisitorSource(restorationSourceMaster, proof, binding, 2, time.Now()); !errors.Is(err, visitortoken.ErrVisitorSource) {
			t.Fatal("changing the signed policy revision retained authentic source evidence", err)
		}
	})
}
