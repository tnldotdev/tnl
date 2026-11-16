package tunnel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type activationStopStream struct {
	muxsession.Stream
	writeEntered chan struct{}
	once         sync.Once
	reply        []byte
	cancelReply  context.CancelCauseFunc
	readErr      error
}

func (s *activationStopStream) Write(p []byte) (int, error) {
	if s.writeEntered != nil {
		s.once.Do(func() { close(s.writeEntered) })
	}
	return s.Stream.Write(p)
}

func (s *activationStopStream) Read(p []byte) (int, error) {
	if s.readErr != nil {
		return 0, s.readErr
	}
	n, err := s.Stream.Read(p)
	if n > 0 && s.cancelReply != nil {
		s.reply = append(s.reply, p[:n]...)
		if _, parsed := tunnelv1.ReadControl(bytes.NewReader(s.reply)); parsed == nil {
			s.cancelReply(context.Canceled)
		}
	}
	return n, err
}

func TestConnectorActivationLocalStopProvenance(t *testing.T) {
	for _, phase := range []string{"before entry", "write", "reply read"} {
		for _, cause := range []error{context.Canceled, context.DeadlineExceeded, errors.New("activation owner stopped")} {
			t.Run(phase+"/"+cause.Error(), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					client, server, _, _ := connectorRenewalPair(t)
					budget, finish := context.WithTimeout(t.Context(), 5*time.Second)
					defer finish()
					call, cancel := context.WithCancelCause(budget)
					defer cancel(nil)
					probe := &activationStopStream{Stream: client.control, writeEntered: make(chan struct{})}
					client.control = probe
					if phase == "before entry" {
						cancel(cause)
					}
					result := tunnelWorker(t, func() { cancel(cause); _ = client.Close() }, func() error {
						return client.ActivateConnectorLeg(call, "stopped")
					})
					if phase != "before entry" {
						<-probe.writeEntered
						if phase == "reply read" {
							request, err := tunnelv1.ReadControl(server.control)
							if err != nil || request.Type != tunnelv1.ConnectorLegActivate {
								t.Fatal("activation did not reach its physical reply boundary", err)
							}
						}
						synctest.Wait()
						cancel(cause)
					}
					err := await(t, result)
					var unavailable *ProtocolError
					if !ConnectorActivationStopped(err, cause) || !errors.Is(err, cause) ||
						!errors.As(err, &unavailable) || unavailable.Code != tunnelv1.Unavailable {
						t.Fatal("activation lost its observed local stop or diagnostic", err)
					}
					if phase != "before entry" && !errors.Is(err, os.ErrDeadlineExceeded) {
						t.Fatal("activation discarded its interrupted physical i/o result", err)
					}
					for _, unrelated := range []error{
						fmt.Errorf("unowned operation: %w", err), errors.Join(err),
						errors.Join(err, errors.New("independent operation")),
					} {
						if ConnectorActivationStopped(unrelated, cause) {
							t.Fatal("stop evidence escaped its exact activation result", unrelated)
						}
					}
					if ConnectorActivationStopped(err, errors.New("other owner stop")) {
						t.Fatal("activation stop evidence changed its origin")
					}
				})
			})
		}
	}
}

func TestConnectorActivationReceivedFailureSurvivesLaterStop(t *testing.T) {
	for _, code := range []tunnelv1.ErrorCode{tunnelv1.Unauthenticated, tunnelv1.Unavailable} {
		t.Run(string(code), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				client, server, _, _ := connectorRenewalPair(t)
				call, cancel := context.WithCancelCause(t.Context())
				defer cancel(nil)
				client.control = &activationStopStream{Stream: client.control, cancelReply: cancel}
				replied := tunnelWorker(t, func() { _ = server.Close() }, func() error {
					request, err := tunnelv1.ReadControl(server.control)
					if err != nil {
						return err
					}
					return tunnelv1.WriteControl(server.control, tunnelv1.Message{
						Type: tunnelv1.Error, ProtocolVersion: tunnelv1.Version, RequestID: request.RequestID, Code: code,
					})
				})
				err := client.ActivateConnectorLeg(call, "denied")
				var denied *ProtocolError
				if ConnectorActivationStopped(err, context.Canceled) || !errors.As(err, &denied) ||
					denied.Code != code || !errors.Is(err, context.Canceled) {
					t.Fatal("later cancellation rewrote a received failure", err)
				}
				if err := await(t, replied); err != nil {
					t.Fatal(err)
				}
			})
		})
	}
}

func TestConnectorActivationEarlierOperationSurvivesLaterStop(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client, server, _, _ := connectorRenewalPair(t)
		call, cancel := context.WithCancelCause(t.Context())
		defer cancel(nil)
		client.control = &activationStopStream{Stream: client.control, readErr: os.ErrDeadlineExceeded}
		read := tunnelWorker(t, func() { _ = server.Close() }, func() error {
			_, err := tunnelv1.ReadControl(server.control)
			return err
		})
		err := client.ActivateConnectorLeg(call, "earlier-timeout")
		if context.Cause(call) != nil || !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal("contrast did not observe an operation failure while live", err)
		}
		cancel(context.Canceled)
		if ConnectorActivationStopped(err, context.Canceled) {
			t.Fatal("a later stop supplied provenance to an earlier operation", err)
		}
		if err := await(t, read); err != nil {
			t.Fatal(err)
		}
	})
}

func TestConnectorActivationAcceptedReplyStoppedBeforeInstallationIsLocal(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client, server, _, _ := connectorRenewalPair(t)
		call, cancel := context.WithCancelCause(t.Context())
		defer cancel(nil)
		client.control = &activationStopStream{Stream: client.control, cancelReply: cancel}
		replied := tunnelWorker(t, func() { _ = server.Close() }, func() error {
			request, err := tunnelv1.ReadControl(server.control)
			if err != nil {
				return err
			}
			return tunnelv1.WriteControl(server.control, tunnelv1.Message{
				Type: tunnelv1.ConnectorLegActivated, ProtocolVersion: tunnelv1.Version,
				RequestID: request.RequestID, ConnectorLegBinding: request.ConnectorLegBinding,
			})
		})
		err := client.ActivateConnectorLeg(call, "accepted-before-stop")
		if !ConnectorActivationStopped(err, context.Canceled) || !errors.Is(err, context.Canceled) {
			t.Fatal("a validated reply lost its subsequent local installation stop", err)
		}
		var invalid *ProtocolError
		if err := client.ActivateConnectorLeg(t.Context(), "second-activation"); !errors.As(err, &invalid) ||
			invalid.Code != tunnelv1.InvalidMessage {
			t.Fatal("local stop made the already-used physical activation reusable", err)
		}
		if err := await(t, replied); err != nil {
			t.Fatal(err)
		}
	})
}

func TestConnectorActivationSpentCallBudgetIsNotALaterOwnerStop(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client, _, _, _ := connectorRenewalPair(t)
		call, finish := context.WithTimeout(t.Context(), 2*time.Second)
		defer finish()
		<-call.Done()
		err := client.ActivateConnectorLeg(call, "spent-call")
		if !errors.Is(err, context.DeadlineExceeded) || ConnectorActivationStopped(err, context.DeadlineExceeded) {
			t.Fatal("a spent call budget gained provenance from a later matching owner cause", err)
		}
	})
}
