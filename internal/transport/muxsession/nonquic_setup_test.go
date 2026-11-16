package muxsession

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	quic "github.com/quic-go/quic-go"
)

// the fixture uses one literal address and calls its borrowed dialer serially.
// retain the native result before dialSharedQUIC applies caller cancellation.
type nonQUICSetupDialEvidence struct {
	dialer            QUICDialer
	calls             int
	entered, returned time.Time
	deadline          time.Time
	entryCause, err   error
}

func (d *nonQUICSetupDialEvidence) DialQUIC(ctx context.Context, address net.Addr, trust *tls.Config, config *quic.Config) (*quic.Conn, error) {
	d.calls++
	d.entered, d.entryCause = time.Now(), context.Cause(ctx)
	d.deadline, _ = ctx.Deadline()
	connection, err := d.dialer.DialQUIC(ctx, address, trust, config)
	d.returned, d.err = time.Now(), err
	return connection, err
}

func (d *nonQUICSetupDialEvidence) facts() string {
	if d.calls == 0 {
		return "calls=0"
	}
	return fmt.Sprintf("calls=%d budget_at_entry=%s duration=%s entry_cause=%v error=%T:%v",
		d.calls, d.deadline.Sub(d.entered), d.returned.Sub(d.entered), d.entryCause, d.err, d.err)
}

func TestNonQUICSetupEvidenceDistinguishesSpentSetupFromNativeWait(t *testing.T) {
	for _, mode := range []string{"spent before native dial", "native dial consumes budget"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				_, roots := testTLSConfigs(t)
				evidence := &nonQUICSetupDialEvidence{dialer: testQUICDialFunc(func(ctx context.Context, _ net.Addr, _ *tls.Config, _ *quic.Config) (*quic.Conn, error) {
					<-ctx.Done()
					return nil, context.Cause(ctx)
				})}
				if mode == "spent before native dial" {
					<-ctx.Done()
				}
				session, err := (QUICConnector{TLSConfig: roots, Dialer: evidence}).Connect(ctx,
					Endpoint{Address: "127.0.0.1:443", ServerName: "relay.test"})
				if session != nil || !errors.Is(err, context.DeadlineExceeded) ||
					err.Error() != "muxsession: dial QUIC: context deadline exceeded" {
					t.Fatal("contrast did not preserve the original ambiguous deadline result", err)
				}
				switch mode {
				case "spent before native dial":
					if evidence.calls != 0 {
						t.Fatal("spent setup entered native QUIC", evidence.facts())
					}
				case "native dial consumes budget":
					if evidence.calls != 1 || evidence.entryCause != nil || evidence.err != context.DeadlineExceeded ||
						evidence.deadline.Sub(evidence.entered) != 5*time.Second || evidence.returned.Sub(evidence.entered) != 5*time.Second {
						t.Fatal("native evidence lost the original entry budget or result", evidence.facts())
					}
				}
				t.Logf("expected deadline contrast: mode=%q result=%v native=%s", mode, err, evidence.facts())
			})
		})
	}
}

func TestNonQUICSetupDeadlineDoesNotOwnSourceListener(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		budget, finish := context.WithTimeout(t.Context(), 5*time.Second)
		defer finish()
		serverTLS, _ := testTLSConfigs(t)
		packet := &scriptedQUICSocket{packets: make(chan sourceQUICPacket, 2), done: make(chan struct{})}
		listener, err := ListenQUICPacket(packet, serverTLS, QUICConfig{PinnedRemoteIPLimit: 4})
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		child := listener.NonQUICPackets(budget)
		defer child.Close()
		duplicate := listener.NonQUICPackets(budget)
		defer duplicate.Close()
		if _, _, err := duplicate.ReadFrom(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
			t.Fatal("duplicate view did not close independently", err)
		}
		firstIP := netip.MustParseAddr("192.0.2.1")
		send := func(ip netip.Addr) {
			data := make([]byte, 1200)
			data[0] = 0xc0
			packet.packets <- sourceQUICPacket{data: data,
				address: net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, 443))}
			synctest.Wait()
		}
		send(firstIP)
		s := listener.sources
		s.mu.Lock()
		first := s.sources[firstIP]
		s.mu.Unlock()
		if first == nil {
			t.Fatal("possible handshake did not create its bounded pending source")
		}
		<-budget.Done()
		synctest.Wait()
		s.mu.Lock()
		retained := s.sources[firstIP] == first && first.pending && first.active == 0 &&
			s.pending == 1 && context.Cause(first.ctx) == nil && !s.stopped && s.err == nil
		s.mu.Unlock()
		if !retained || context.Cause(s.ctx) != nil || time.Until(first.created.Add(10*time.Second)) != 5*time.Second {
			t.Fatal("the five-second borrower budget retired the ten-second pending-source owner", nonQUICSetupSourceFacts(listener))
		}
		if _, _, err := child.ReadFrom(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
			t.Fatal("spent borrower view did not stop", err)
		}
		send(netip.MustParseAddr("192.0.2.2"))
		s.mu.Lock()
		receiving := len(s.sources) == 2 && s.pending == 2
		s.mu.Unlock()
		if !receiving || packet.read.Load() != 2 {
			t.Fatal("borrower expiry stopped physical source dispatch", nonQUICSetupSourceFacts(listener))
		}
		t.Logf("after original five-second bound: %v", nonQUICSetupSourceFacts(listener))
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}
		select {
		case <-packet.done:
		default:
			t.Fatal("explicit listener close did not close its physical packet owner")
		}
		if context.Cause(s.ctx) == nil {
			t.Fatal("explicit listener close left its owner live")
		}
	})
}

type nonQUICSetupFailedReader struct {
	*scriptedQUICSocket
	fail  <-chan struct{}
	cause error
}

func (p *nonQUICSetupFailedReader) ReadFrom([]byte) (int, net.Addr, error) {
	select {
	case <-p.fail:
		return 0, nil, p.cause
	case <-p.done:
		return 0, nil, net.ErrClosed
	}
}

func TestNonQUICSetupSourceEvidenceKeepsIndependentReaderFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		budget, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		serverTLS, _ := testTLSConfigs(t)
		fail := make(chan struct{})
		failed := errors.New("independent physical reader failure")
		packet := &nonQUICSetupFailedReader{scriptedQUICSocket: &scriptedQUICSocket{done: make(chan struct{})},
			fail: fail, cause: failed}
		listener, err := ListenQUICPacket(packet, serverTLS, QUICConfig{PinnedRemoteIPLimit: 4})
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		child := listener.NonQUICPackets(budget)
		defer child.Close()
		synctest.Wait()
		if context.Cause(listener.sources.ctx) != nil {
			t.Fatal("physical reader failed before its controlled boundary")
		}
		close(fail)
		synctest.Wait()
		facts := strings.Join(nonQUICSetupSourceFacts(listener), " ")
		if context.Cause(budget) != nil || !strings.Contains(facts, "owner_cause=context canceled") ||
			!strings.Contains(facts, "owner_error="+failed.Error()) || !strings.Contains(facts, "stopped=false") {
			t.Fatal("source evidence lost the independent physical error before the caller deadline", facts)
		}
		if _, _, err := child.ReadFrom(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
			t.Fatal("failed source owner left its borrowed discovery read live", err)
		}
		if err := listener.Close(); !errors.Is(err, failed) {
			t.Fatal("source cleanup hid its independent reader failure", err)
		}
		facts = strings.Join(nonQUICSetupSourceFacts(listener), " ")
		if !strings.Contains(facts, "owner_error="+failed.Error()) || !strings.Contains(facts, "stopped=true") {
			t.Fatal("explicit close erased the prior physical failure", facts)
		}
		t.Logf("controlled physical-reader failure before caller deadline: %s", facts)
	})
}
