package tunnel

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	yamux "github.com/libp2p/go-yamux/v5"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type helloStopSession struct {
	muxsession.Session
	control      *activationStopStream
	closeEntered chan struct{}
	closeRelease <-chan struct{}
}

func (s helloStopSession) OpenStream(ctx context.Context) (muxsession.Stream, error) {
	stream, err := s.Session.OpenStream(ctx)
	if err != nil {
		return nil, err
	}
	s.control.Stream = stream
	return s.control, nil
}

func (s helloStopSession) Close() error {
	if s.closeEntered != nil {
		close(s.closeEntered)
		<-s.closeRelease
	}
	return s.Session.Close()
}

func TestConnectorHelloLocalStopKeepsRawResultAndOwnedCleanup(t *testing.T) {
	for _, phase := range []string{"write", "reply read"} {
		for _, failedClose := range []bool{false, true} {
			t.Run(phase+map[bool]string{false: "/clean close", true: "/failed close"}[failedClose], func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					_, _, proof, receipt := connectorRenewalPair(t)
					left, right := newMemoryPair(t)
					budget, finish := context.WithTimeout(t.Context(), 5*time.Second)
					defer finish()
					call, cancel := context.WithCancelCause(budget)
					cause := errors.New("connector owner stopped during hello")
					defer cancel(cause)
					control := &activationStopStream{writeEntered: make(chan struct{})}
					probe := &connectorDialCleanupProbe{Session: helloStopSession{Session: left, control: control}}
					physical := errors.New("independent hello transport close failed")
					if failedClose {
						probe.cleanup = physical
					}
					result := tunnelWorker(t, func() { cancel(cause); _ = left.Close() }, func() error {
						session, _, err := DialConnector(call, probe, tunnelv1.Message{Type: tunnelv1.Hello,
							ProtocolVersion: tunnelv1.Version, Role: tunnelv1.Connector, ConnectorPairLegProof: &proof}, receipt.DeliveryID)
						if session != nil {
							return errors.Join(err, errors.New("stopped hello exposed a session"), session.Close())
						}
						return err
					})
					<-control.writeEntered
					if phase == "reply read" {
						stream, err := right.AcceptStream(budget)
						if err != nil {
							t.Fatal(err)
						}
						if hello, err := tunnelv1.ReadControl(stream); err != nil || hello.Type != tunnelv1.Hello {
							t.Fatal("hello did not reach its reply boundary", err)
						}
					}
					synctest.Wait()
					cancel(cause)
					err := await(t, result)
					if !errors.Is(err, cause) || !errors.Is(err, os.ErrDeadlineExceeded) || probe.closes.Load() != 1 ||
						ConnectorHelloStopped(err, cause) == failedClose || ConnectorActivationStopped(err, cause) {
						t.Fatal("hello stop lost its exact phase, raw result, or owned close", err)
					}
					if failedClose && !errors.Is(err, physical) {
						t.Fatal("hello stop hid independently failed physical cleanup", err)
					}
					if ConnectorHelloStopped(errors.Join(err, errors.New("independent caller failure")), cause) {
						t.Fatal("hello stop evidence escaped into an unrelated aggregate")
					}
				})
			})
		}
	}
}

func TestConnectorHelloReceivedRejectionSurvivesLaterStop(t *testing.T) {
	for _, code := range []tunnelv1.ErrorCode{tunnelv1.Unauthenticated, tunnelv1.Unavailable} {
		t.Run(string(code), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				_, _, proof, receipt := connectorRenewalPair(t)
				left, right := newMemoryPair(t)
				call, cancel := context.WithCancelCause(t.Context())
				defer cancel(nil)
				probe := helloStopSession{Session: left,
					control: &activationStopStream{cancelReply: cancel}}
				replied := tunnelWorker(t, func() { _ = right.Close() }, func() error {
					stream, err := right.AcceptStream(t.Context())
					if err != nil {
						return err
					}
					if _, err := tunnelv1.ReadControl(stream); err != nil {
						return err
					}
					return tunnelv1.WriteControl(stream, tunnelv1.Message{Type: tunnelv1.Error,
						ProtocolVersion: tunnelv1.Version, Code: code})
				})
				session, _, err := DialConnector(call, probe, tunnelv1.Message{Type: tunnelv1.Hello,
					ProtocolVersion: tunnelv1.Version, Role: tunnelv1.Connector, ConnectorPairLegProof: &proof}, receipt.DeliveryID)
				var rejected *ProtocolError
				if session != nil || ConnectorHelloStopped(err, context.Canceled) || !errors.As(err, &rejected) ||
					rejected.Code != code || !errors.Is(err, context.Canceled) {
					t.Fatal("a received hello rejection became a later local stop", err)
				}
				if err := await(t, replied); err != nil {
					t.Fatal(err)
				}
			})
		})
	}
}

func TestConnectorHelloStopCannotOutliveItsOriginalBudgetDuringClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, _, proof, receipt := connectorRenewalPair(t)
		left, _ := newMemoryPair(t)
		call, cancel := context.WithCancelCause(t.Context())
		defer cancel(nil)
		budget, finish := context.WithTimeout(call, 2*time.Second)
		defer finish()
		until, _ := budget.Deadline()
		control := &activationStopStream{writeEntered: make(chan struct{})}
		closeEntered, closeRelease := make(chan struct{}), make(chan struct{})
		probe := &connectorDialCleanupProbe{Session: helloStopSession{Session: left, control: control,
			closeEntered: closeEntered, closeRelease: closeRelease}}
		release := sync.OnceFunc(func() { close(closeRelease) })
		defer release()
		result := tunnelWorker(t, func() { release(); _ = left.Close() }, func() error {
			_, _, err := DialConnector(budget, probe, tunnelv1.Message{Type: tunnelv1.Hello,
				ProtocolVersion: tunnelv1.Version, Role: tunnelv1.Connector, ConnectorPairLegProof: &proof}, receipt.DeliveryID)
			return err
		})
		<-control.writeEntered
		synctest.Wait()
		cancel(context.Canceled)
		<-closeEntered
		time.Sleep(time.Until(until))
		release()
		err := await(t, result)
		if !errors.Is(err, context.Canceled) || !errors.Is(err, os.ErrDeadlineExceeded) ||
			ConnectorHelloStopped(err, context.Canceled) || probe.closes.Load() != 1 {
			t.Fatal("a close past the original budget retained local hello-stop permission", err)
		}
	})
}

func TestYamuxConnectorHelloStopRetainsNativeDeadlineAndOwnedCleanup(t *testing.T) {
	for _, failedClose := range []bool{false, true} {
		t.Run(map[bool]string{false: "clean close", true: "failed close"}[failedClose], func(t *testing.T) {
			_, _, proof, receipt := connectorRenewalPair(t)
			budget := tunnelContext(t)
			serverTLS, clientTLS := realTunnelTLS(t)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			helloRead, closeServer := make(chan struct{}), make(chan struct{})
			release := sync.OnceFunc(func() { close(closeServer) })
			defer release()
			accepted := tunnelWorker(t, func() { release(); _ = listener.Close() }, func() error {
				network, err := listener.Accept()
				if err != nil {
					return err
				}
				transport, err := muxsession.AcceptTLSYamux(budget, network, serverTLS, muxsession.TLSYamuxConfig{})
				if err != nil {
					return err
				}
				defer transport.Close()
				stream, err := transport.AcceptStream(budget)
				if err != nil {
					return err
				}
				if hello, err := tunnelv1.ReadControl(stream); err != nil || hello.Type != tunnelv1.Hello {
					return errors.Join(err, errors.New("native hello did not reach its reply boundary"))
				}
				close(helloRead)
				<-closeServer
				return nil
			})
			transport, err := (muxsession.TLSYamuxConnector{TLSConfig: clientTLS}).Connect(budget,
				muxsession.Endpoint{Address: listener.Addr().String(), ServerName: "relay.test"})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = transport.Close() })
			probe := &connectorDialCleanupProbe{Session: transport}
			physical := errors.New("independent native hello close failed")
			if failedClose {
				probe.cleanup = physical
			}
			call, cancel := context.WithCancel(budget)
			defer cancel()
			result := tunnelWorker(t, func() { cancel(); _ = transport.Close() }, func() error {
				session, _, err := DialConnector(call, probe, tunnelv1.Message{Type: tunnelv1.Hello,
					ProtocolVersion: tunnelv1.Version, Role: tunnelv1.Connector, ConnectorPairLegProof: &proof}, receipt.DeliveryID)
				if session != nil {
					return errors.Join(err, errors.New("native stopped hello exposed a session"), session.Close())
				}
				return err
			})
			select {
			case <-helloRead:
			case err := <-accepted:
				t.Fatal("native server failed before reading hello", err)
			case <-budget.Done():
				t.Fatal("native hello did not reach its reply boundary", context.Cause(budget))
			}
			cancel()
			err = await(t, result)
			if !errors.Is(err, context.Canceled) || !errors.Is(err, yamux.ErrTimeout) ||
				errors.Is(err, os.ErrDeadlineExceeded) || probe.closes.Load() != 1 ||
				ConnectorHelloStopped(err, context.Canceled) == failedClose || ConnectorActivationStopped(err, context.Canceled) {
				t.Fatal("native hello lost its exact deadline, phase, or joined close", err)
			}
			if failedClose && !errors.Is(err, physical) {
				t.Fatal("native hello stop hid an independent physical close failure", err)
			}
			release()
			if err := await(t, accepted); err != nil {
				t.Fatal(err)
			}
		})
	}
}
