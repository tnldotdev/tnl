package stream

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"testing/synctest"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type terminalDenialStream struct{ net.Conn }

func (s terminalDenialStream) CloseWrite() error  { return s.Close() }
func (s terminalDenialStream) Reset(uint32) error { return s.Close() }

type terminalDenialSession struct {
	muxsession.Session
	stream muxsession.Stream
}

func (s terminalDenialSession) OpenStream(context.Context) (muxsession.Stream, error) {
	return s.stream, nil
}
func (s terminalDenialSession) AcceptStream(context.Context) (muxsession.Stream, error) {
	return s.stream, nil
}

func TestConnectorTerminalDenialFencesOnlyUnenteredWork(t *testing.T) {
	for _, entered := range []bool{false, true} {
		t.Run(map[bool]string{false: "denied before entry", true: "denied after entry"}[entered], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newOwnerStopFixture(t)
				p := f.p
				setup, finish := context.WithTimeout(t.Context(), time.Second)
				defer finish()
				left, right := net.Pipe()
				defer left.Close()
				decoded := make(chan tunnelv1.ConnectorVisitorTerminalRequest, 1)
				serverReady := make(chan error, 1)
				serverDone := make(chan struct{})
				go func() {
					defer close(serverDone)
					control, err := tunnel.AcceptConnectorPermissionControl(setup, terminalDenialSession{stream: terminalDenialStream{right}})
					serverReady <- err
					if err != nil {
						return
					}
					message, err := tunnelv1.ReadConnectorControlMessage(control)
					if err == nil {
						decoded <- message.(tunnelv1.ConnectorVisitorAbort).TerminalRequest()
					}
				}()
				defer func() {
					_ = right.Close()
					<-serverDone
				}()
				var err error
				p.permissions, err = tunnel.OpenConnectorPermissionControl(p.packetCtx, setup,
					terminalDenialSession{stream: terminalDenialStream{left}}, connectorTestControlScope())
				if err != nil {
					t.Fatal(err)
				}
				defer p.permissions.Close()
				// the client can read the hello before the server clears its setup
				// deadline. do not close the pipe while the server is still doing that.
				if err := <-serverReady; err != nil {
					t.Fatal(err)
				}
				denial := &clientcontrol.ProblemError{Status: http.StatusForbidden, Problem: controlv1.Problem{Code: controlv1.Forbidden}}
				use := &connectorUse{admitted: true, until: p.until, terminalKey: tunnelv1.ConnectorVisitorTerminalKey{
					VisitorConnectionID: "vc_aaaaaaaaaaaaaaaaaaaaaa", DeliveryGeneration: 1}}
				started := time.Now()
				if !entered {
					p.observeControlDenial(denial)
					p.cancel(denial)
				}
				done := make(chan error, 1)
				go func() { done <- p.terminalUse(use, context.Canceled) }()
				if entered {
					request := <-decoded
					if request.Key != use.terminalKey || request.TerminalNumber != 1 {
						t.Fatal("terminal request lost its exact admission", request)
					}
					p.observeControlDenial(denial)
					p.cancel(denial)
				}
				result := <-done
				if entered {
					if !errors.Is(result, context.DeadlineExceeded) || !errors.Is(p.useErr, context.DeadlineExceeded) ||
						time.Since(started) != 5*time.Second {
						t.Fatal("later denial hid entered missing-result failure or changed its bound", result, p.useErr)
					}
				} else {
					if result != context.Canceled || context.Cause(p.ctx) != denial || p.useErr != nil || !time.Now().Equal(started) {
						t.Fatal("denied authority entered terminal work or lost its serving result", result, p.useErr, time.Since(started))
					}
					if err := p.terminalUse(use, nil); !errors.Is(err, denial) || !errors.Is(err, ErrServiceConnection) {
						t.Fatal("denial fabricated successful completion", err)
					}
					select {
					case request := <-decoded:
						t.Fatal("revoked owner sent a new terminal request", request)
					default:
					}
					if err := p.Close(p.cleanup.context()); err != nil || f.retirements != 1 {
						t.Fatal("unentered terminal work consumed signed retirement's original budget", err, f.retirements)
					}
				}
			})
		})
	}
}

func TestConnectorReceivedDenialRemainsServingFailureThroughJoinedCleanup(t *testing.T) {
	for _, boundary := range []string{"clean", "physical", "retirement", "joined result", "foreign owner"} {
		t.Run(boundary, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newOwnerStopFixture(t)
				p := f.p
				second := &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
				received := &connectorReceivedLegDenial{owner: p, err: second}
				independent := errors.New("independent joined cleanup")
				var result error = received
				switch boundary {
				case "physical":
					p.session.(*actionExpirySession).err = &muxsession.QUICTransportCloseError{Err: independent}
				case "retirement":
					f.retireErr = independent
				case "joined result":
					result = errors.Join(received, independent)
				case "foreign owner":
					received.owner = &connectorConnection{}
				}
				p.cancel(f.cause)
				p.recordLegRecoveryFailure(result, context.Cause(p.ctx))
				operation, cleanup := p.close(p.cleanup.context())
				if boundary == "joined result" || boundary == "foreign owner" {
					if operation != nil || !errors.Is(cleanup, second) {
						t.Fatal("joined or foreign operation acquired serving-only provenance", operation, cleanup)
					}
				} else if !errors.Is(operation, second) {
					t.Fatal("completed serving denial was erased", operation, cleanup)
				}
				if boundary == "clean" {
					if cleanup != nil {
						t.Fatal("received serving denial became failed cleanup", cleanup)
					}
				} else if boundary != "foreign owner" && !errors.Is(cleanup, independent) {
					t.Fatal("serving denial hid physical or retirement failure", cleanup)
				}
				if err := p.Close(p.cleanup.context()); !errors.Is(err, second) ||
					context.Cause(p.ctx) != f.cause || f.retirements != 1 {
					t.Fatal("direct close lost either serving decision or repeated retirement", err, f.retirements)
				}
			})
		})
	}
}
