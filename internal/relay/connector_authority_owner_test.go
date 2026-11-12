package relay

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestConnectorCandidateRenewalCannotPromoteOrExtendItsOpening(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newConnectorBindingFixture(t)
		f.duration = 5 * time.Second
		d, outer := f.candidate(t, 1, "192.0.2.1:12345")
		opening := d.claim
		data := tunnelv1.PeerPacket{Kind: tunnelv1.PeerData}
		probe := tunnelv1.PeerPacket{Kind: tunnelv1.PeerProbe}
		if d.admit(data) || !d.admit(probe) {
			t.Fatal("an unselected opening carried data or blocked preparation probes")
		}
		f.duration = 20 * time.Second
		receipt, err := d.renew(d.ctx, f.acceptor, outer, d.proof)
		if err != nil || receipt.ExpiresAt != opening.receipt.ExpiresAt || d.claim != opening || d.bridge.Load() != nil || d.admit(data) {
			t.Fatal("preactivation renewal changed immutable preparation authority", err)
		}
		time.Sleep(time.Until(opening.receipt.ExpiresAt))
		synctest.Wait()
		if d.ctx.Err() == nil || d.admit(probe) || len(f.publisher.bridges) != 0 {
			t.Fatal("unselected opening outlived its original deadline")
		}
		_, err = f.activate(t, d, tunnelv1.ConnectorHandoffID{})
		var denied *tunnel.ProtocolError
		if !errors.As(err, &denied) || denied.Code != tunnelv1.Unauthenticated {
			t.Fatal("expired opening activated a bridge or lost its exact deadline", err)
		}
	})
}

func TestConnectorCandidateNarrowerRenewalRetiresTheImmutableOpening(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newConnectorBindingFixture(t)
		f.duration = 5 * time.Second
		d, outer := f.candidate(t, 2, "192.0.2.1:12345")
		opening := d.claim
		f.duration = time.Second
		receipt, err := d.renew(d.ctx, f.acceptor, outer, d.proof)
		var unavailable *tunnel.ProtocolError
		if !errors.As(err, &unavailable) || unavailable.Code != tunnelv1.Unavailable || receipt != (tunnelv1.ConnectorPairLegAccepted{}) || d.ctx.Err() == nil || d.claim != opening {
			t.Fatal("a shortened preparation grant left an activatable older opening", err)
		}
		time.Sleep(2 * time.Second)
		if !opening.receipt.ExpiresAt.After(time.Now()) {
			t.Fatal("proof did not cross only the shorter returned deadline")
		}
		if _, err := f.activate(t, d, tunnelv1.ConnectorHandoffID{9}); err == nil || d.bridge.Load() != nil || len(f.publisher.bridges) != 0 {
			t.Fatal("retired candidate activated after the shorter grant expired", err)
		}
	})
}

func TestConnectorPublisherTransportLossRetiresPreparationAndActiveBridge(t *testing.T) {
	for _, selected := range []bool{false, true} {
		t.Run(map[bool]string{false: "preparation", true: "active"}[selected], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newConnectorBindingFixture(t)
				d, outer := f.candidate(t, 1, "192.0.2.1:12345")
				opening := d.claim
				var b *connectorBridge
				if selected {
					var err error
					b, err = f.activate(t, d, tunnelv1.ConnectorHandoffID{})
					if err != nil {
						t.Fatal(err)
					}
				}
				// close only the borrowed physical transport. the packet owner is
				// deliberately not closed until fixture cleanup after this proof.
				if err := f.publisherTransport.Close(); err != nil {
					t.Fatal(err)
				}
				synctest.Wait()
				if f.publisher.closed || !time.Now().Before(opening.receipt.ExpiresAt) || d.ctx.Err() == nil || d.claim != opening {
					t.Fatal("transport loss waited for explicit owner Close or the original preparation expiry")
				}
				select {
				case <-f.publisher.Done():
				default:
					t.Fatal("packet owner did not observe its borrowed transport exit")
				}
				if b != nil {
					select {
					case <-b.done:
					default:
						t.Fatal("active bridge did not join after the publisher transport exited")
					}
					if len(f.publisher.bridges) != 0 {
						t.Fatal("transport exit retained its forwarding registration")
					}
				}
				receipt, err := d.renew(d.ctx, f.acceptor, outer, d.proof)
				var unavailable *tunnel.ProtocolError
				if !errors.As(err, &unavailable) || unavailable.Code != tunnelv1.Unavailable || receipt != (tunnelv1.ConnectorPairLegAccepted{}) {
					t.Fatal("physical transport loss became a subject denial or returned authority", err)
				}
			})
		})
	}
}

func TestConnectorPreparationTracksBorrowedPublisherTLSTransport(t *testing.T) {
	f := newConnectorBindingFixture(t)
	certificate := httptest.NewTLSServer(nil)
	t.Cleanup(certificate.Close)
	roots := x509.NewCertPool()
	roots.AddCert(certificate.Certificate())
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	opened := make(chan *connectorPacketSession, 1)
	released := make(chan struct{})
	defer close(released)
	address := traceMuxServer(t, ctx, tunnel.TransportTLSTCP, certificate.TLS, func(ctx context.Context, transport muxsession.Session) error {
		packets, err := newConnectorPacketSession(ctx, transport)
		if err != nil {
			return err
		}
		defer packets.Close()
		opened <- packets
		// keep the role owner alive after physical transport loss. its explicit
		// Close must not be what releases the unselected connector candidate.
		select {
		case <-released:
		case <-ctx.Done():
		}
		return nil
	})
	transport, err := (muxsession.TLSYamuxConnector{TLSConfig: &tls.Config{RootCAs: roots}}).Connect(ctx, muxsession.Endpoint{Address: address, ServerName: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = transport.Close() })
	packets := relayAwait(t, opened)
	f.publisher, f.connection.packets = packets, packets
	d, outer := f.candidate(t, 1, "192.0.2.1:12345")
	if err := transport.Close(); err != nil {
		t.Fatal(err)
	}
	relayAwait(t, d.ctx.Done())
	packets.mu.Lock()
	explicitlyClosed := packets.closed
	packets.mu.Unlock()
	if ctx.Err() != nil || explicitlyClosed || !time.Now().Before(d.claim.receipt.ExpiresAt) {
		t.Fatal("preparation waited for role cleanup or its opening deadline instead of the borrowed transport exit")
	}
	receipt, err := d.renew(d.ctx, f.acceptor, outer, d.proof)
	var unavailable *tunnel.ProtocolError
	if !errors.As(err, &unavailable) || unavailable.Code != tunnelv1.Unavailable || receipt != (tunnelv1.ConnectorPairLegAccepted{}) {
		t.Fatal("publisher transport exit returned authority or became a subject denial", err)
	}
}

func TestConnectorBridgeAloneOwnsRenewedDeadlineAndDataAdmission(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newConnectorBindingFixture(t)
		f.duration = 5 * time.Second
		d, outer := f.candidate(t, 1, "192.0.2.1:12345")
		opening := d.claim
		b, err := f.activate(t, d, tunnelv1.ConnectorHandoffID{})
		if err != nil {
			t.Fatal(err)
		}
		f.duration = 20 * time.Second
		receipt, err := d.renew(d.ctx, f.acceptor, outer, d.proof)
		if err != nil || !receipt.ExpiresAt.After(opening.receipt.ExpiresAt) || d.claim != opening {
			t.Fatal("active renewal changed the opening instead of bridge authority", err)
		}
		time.Sleep(time.Until(opening.receipt.ExpiresAt) + time.Second)
		synctest.Wait()
		data := tunnelv1.PeerPacket{Kind: tunnelv1.PeerData}
		if d.ctx.Err() != nil || b.ctx.Err() != nil || !d.admit(data) || !b.admit(data) {
			t.Fatal("the spent preparation timer retired a renewed bridge")
		}
		time.Sleep(time.Until(receipt.ExpiresAt))
		synctest.Wait()
		if d.admit(data) || b.admit(data) || d.ctx.Err() == nil || b.ctx.Err() == nil {
			t.Fatal("binding data or carrier lifetime escaped the confirmed deadline")
		}
		select {
		case <-b.done:
		default:
			t.Fatal("expired binding did not join its forwarding workers")
		}
		if len(f.publisher.bridges) != 0 || d.claim != opening {
			t.Fatal("retirement retained the registration or changed the immutable opening")
		}
	})
}

func TestConnectorCandidatePublisherLossClosesOnlyPhysicalPreparation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newConnectorBindingFixture(t)
		d, outer := f.candidate(t, 1, "192.0.2.1:12345")
		opening := d.claim
		f.publisher.Close()
		synctest.Wait()
		receipt, err := d.renew(d.ctx, f.acceptor, outer, d.proof)
		var protocol *tunnel.ProtocolError
		if d.ctx.Err() == nil || !errors.As(err, &protocol) || protocol.Code != tunnelv1.Unavailable || !errors.Is(err, context.Canceled) {
			t.Fatal("publisher loss became an authorization decision", err)
		}
		if receipt != (tunnelv1.ConnectorPairLegAccepted{}) || d.claim != opening || d.bridge.Load() != nil {
			t.Fatal("lost preparation returned or changed authority")
		}
	})
}

func TestConnectorBridgeExpiryDuringCarrierInstallCannotReturnAuthority(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b, next := reconnectBridgeFixture(t)
		b.until = time.Now().Add(5 * time.Second)
		until := b.until
		held := &heldReconnectClose{reconnectCarrier: newReconnectCarrier(), entered: make(chan struct{}), release: make(chan struct{})}
		release := sync.OnceFunc(func() { close(held.release) })
		defer release()
		if err := b.connector.Install(held); err != nil {
			t.Fatal(err)
		}
		d, selection := next(2)
		done := relayWorker(t, release, func() error { _, err := replaceBridgeBinding(t.Context(), b, d, selection); return err })
		<-held.entered
		time.Sleep(time.Until(until))
		release()
		err := relayAwait(t, done)
		var protocol *tunnel.ProtocolError
		if !errors.As(err, &protocol) || protocol.Code != tunnelv1.Unauthenticated || !errors.Is(err, context.DeadlineExceeded) || b.until != until || b.ctx.Err() == nil {
			t.Fatal("a blocked physical install revived expired binding authority", err)
		}
		if d.admit(tunnelv1.PeerPacket{Kind: tunnelv1.PeerData}) {
			t.Fatal("expired installation admitted application data")
		}
	})
}

func TestConnectorBridgeHandoffRejectionPrecedesPhysicalCancellation(t *testing.T) {
	for _, boundary := range []string{"predecessor", "revision", "key", "source", "expired binding"} {
		t.Run(boundary, func(t *testing.T) {
			b, next := reconnectBridgeFixture(t)
			d, selection := next(2)
			switch boundary {
			case "predecessor":
				selection.PreviousNonce = append([]byte(nil), selection.PreviousNonce...)
				selection.PreviousNonce[0]++
			case "revision":
				selection.HandoffRevision++
			case "key":
				d.claim.key[0]++
			case "source":
				d.claim.receipt.SourceIP = "192.0.2.2"
			case "expired binding":
				b.until = time.Now().Add(-time.Second)
			}
			before, until := b.handoff, b.until
			d.cancel()
			b.cancel()
			_, err := replaceBridgeBinding(t.Context(), b, d, selection)
			var denied *tunnel.ProtocolError
			if !errors.As(err, &denied) || denied.Code != tunnelv1.Unauthenticated || b.handoff != before || b.until != until || b.active != nil {
				t.Fatal("physical cancellation hid invalid authority or changed the binding", err)
			}
		})
	}
}

func TestConnectorBridgeLateRenewalCannotMutateSelectedCarrier(t *testing.T) {
	for _, controlDenial := range []bool{false, true} {
		t.Run(map[bool]string{false: "valid reply", true: "denied reply"}[controlDenial], func(t *testing.T) {
			f := newConnectorBindingFixture(t)
			old, outer := f.candidate(t, 1, "192.0.2.1:12345")
			b, err := f.activate(t, old, tunnelv1.ConnectorHandoffID{})
			if err != nil {
				t.Fatal(err)
			}
			selected, _ := f.candidate(t, 1, "192.0.2.1:54321")
			until := b.until
			entered, released := make(chan struct{}), make(chan struct{})
			release := sync.OnceFunc(func() { close(released) })
			defer release()
			denied := &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
			prior := f.acceptor.Claim
			f.acceptor.Claim = connectorClaimFunc(func(ctx context.Context, lease relayv1.RelayLease, source netip.Addr, proof tunnelv1.ConnectorPairLegProof, signature []byte) (relayv1.ConnectorPeerPairLegClaim, error) {
				claim, err := prior.ClaimConnectorPeerPairLegFromAcceptedSocket(ctx, lease, source, proof, signature)
				close(entered)
				<-released
				if controlDenial {
					return relayv1.ConnectorPeerPairLegClaim{}, denied
				}
				return claim, err
			})
			var receipt tunnelv1.ConnectorPairLegAccepted
			done := relayWorker(t, release, func() error {
				var err error
				receipt, err = old.renew(old.ctx, f.acceptor, outer, old.proof)
				return err
			})
			<-entered
			handoff, err := tunnelv1.NewConnectorHandoff(b.handoff.selected, tunnelv1.ConnectorHandoffID{9}, 1)
			if err != nil {
				t.Fatal(err)
			}
			hello, err := tunnelv1.ParseConnectorHelloNonce(selected.proof.Nonce)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := b.replaceCarrier(t.Context(), selected, tunnelv1.InitialConnectorActivation(hello).Replacing(handoff)); err != nil {
				t.Fatal(err)
			}
			release()
			err = relayAwait(t, done)
			var protocol *tunnel.ProtocolError
			want := tunnelv1.Unavailable
			if controlDenial {
				want = tunnelv1.Unauthenticated
			}
			if !errors.As(err, &protocol) || protocol.Code != want || controlDenial && !errors.Is(err, denied) || receipt != (tunnelv1.ConnectorPairLegAccepted{}) {
				t.Fatal("late claim lost its actual outcome or returned authority", err)
			}
			data := tunnelv1.PeerPacket{Kind: tunnelv1.PeerData}
			if b.active != selected || b.until != until || selected.ctx.Err() != nil || !selected.admit(data) || old.admit(data) {
				t.Fatal("retired carrier renewal changed selected binding authority")
			}
		})
	}
}
