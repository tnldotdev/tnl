package tunnel

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestNativeLegActivationSelectsOriginalHelloAfterPassiveRenewal(t *testing.T) {
	client, server, proof, receipt := nativeRenewalPair(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var activations, renewals atomic.Int32
	done := tunnelWorker(t, func() { cancel(); _ = server.Close() }, func() error {
		return server.HandleNativeLegControl(ctx, func(context.Context) error {
			activations.Add(1)
			return nil
		}, func(context.Context, tunnelv1.NativePairLegProof) (tunnelv1.NativePairLegAccepted, error) {
			renewals.Add(1)
			return receipt, nil
		})
	})
	fresh := proof
	fresh.Nonce = bytes.Repeat([]byte{2}, 32)
	if _, err := client.RenewNativeLeg(t.Context(), "passive", fresh, receipt); err != nil {
		t.Fatal(err)
	}
	if activations.Load() != 0 {
		t.Fatal("renewal selected a passive candidate")
	}
	if err := client.ActivateNativeLeg(t.Context(), "winner"); err != nil {
		t.Fatal(err)
	}
	if err := client.ActivateNativeLeg(t.Context(), "again"); err == nil {
		t.Fatal("client replayed activation")
	}
	// bypass the client's guard to verify the accepted control owner also rejects
	// a replay without calling its installer again.
	if err := tunnelv1.WriteControl(client.control, tunnelv1.Message{Type: tunnelv1.NativeLegActivate, ProtocolVersion: tunnelv1.Version,
		RequestID: "replay", Role: tunnelv1.NativeConnector, NativeLegBinding: &tunnelv1.NativeLegBinding{Nonce: proof.Nonce}}); err != nil {
		t.Fatal(err)
	}
	response, err := tunnelv1.ReadControl(client.control)
	if err != nil || response.Type != tunnelv1.Error || response.Code != tunnelv1.Unauthenticated || response.RequestID != "replay" {
		t.Fatal("server did not reject replay", response.Type, response.Code, err)
	}
	if err := await(t, done); err == nil || activations.Load() != 1 || renewals.Load() != 1 {
		t.Fatal("activation repeated installation or authority renewal", err)
	}
}

func TestNativeLegActivationRejectsForeignCandidate(t *testing.T) {
	client, server, _, _ := nativeRenewalPair(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var calls atomic.Int32
	done := tunnelWorker(t, func() { cancel(); _ = server.Close() }, func() error {
		return server.HandleNativeLegControl(ctx, func(context.Context) error { calls.Add(1); return nil },
			func(context.Context, tunnelv1.NativePairLegProof) (tunnelv1.NativePairLegAccepted, error) {
				t.Error("selection renewed authority")
				return tunnelv1.NativePairLegAccepted{}, nil
			})
	})
	client.nativeLeg.Nonce = bytes.Repeat([]byte{1}, 32)
	err := client.ActivateNativeLeg(t.Context(), "foreign")
	var rejected *ProtocolError
	if !errors.As(err, &rejected) || rejected.Code != tunnelv1.Unauthenticated || await(t, done) == nil || calls.Load() != 0 {
		t.Fatal("foreign nonce reached installation", err)
	}
}

func TestNativeLegActivationKeepsCallbackClassificationCauseAndSafeWire(t *testing.T) {
	for _, code := range []tunnelv1.ErrorCode{tunnelv1.Unavailable, tunnelv1.StaleConnectionAssignment, tunnelv1.CapacityExceeded, "", tunnelv1.InvalidMessage} {
		t.Run(string(code), func(t *testing.T) {
			client, server, _, _ := nativeRenewalPair(t)
			cause := errors.New("private-provider-secret")
			var classification *ProtocolError
			want := tunnelv1.Unauthenticated
			if code != "" {
				classification = &ProtocolError{Code: code}
				if validAuthenticationError(code) {
					want = code
				}
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := tunnelWorker(t, func() { cancel(); _ = server.Close() }, func() error {
				return server.HandleNativeLegControl(ctx, func(context.Context) error {
					return errors.Join(classification, cause)
				}, func(context.Context, tunnelv1.NativePairLegProof) (tunnelv1.NativePairLegAccepted, error) {
					t.Error("selection renewed authority")
					return tunnelv1.NativePairLegAccepted{}, nil
				})
			})
			err := client.ActivateNativeLeg(t.Context(), "reject")
			var rejected *ProtocolError
			if !errors.As(err, &rejected) || rejected.Code != want || strings.Contains(err.Error(), "private-provider-secret") {
				t.Fatal("activation lost safe wire classification")
			}
			if original := await(t, done); !errors.Is(original, cause) {
				t.Fatal("activation discarded its callback cause")
			}
		})
	}
}

func TestNativeLegActivationChecksResponseBinding(t *testing.T) {
	for _, outcome := range []string{"nonce", "request", "kind"} {
		t.Run(outcome, func(t *testing.T) {
			client, server, _, _ := nativeRenewalPair(t)
			done := tunnelWorker(t, func() { _ = server.Close() }, func() error {
				request, err := tunnelv1.ReadControl(server.control)
				if err != nil {
					return err
				}
				response := tunnelv1.Message{Type: tunnelv1.NativeLegActivated, ProtocolVersion: tunnelv1.Version, RequestID: request.RequestID, NativeLegBinding: request.NativeLegBinding}
				switch outcome {
				case "nonce":
					response.NativeLegBinding.Nonce[0]++
				case "request":
					response.RequestID = "another"
				case "kind":
					response.Type, response.NativeLegBinding = tunnelv1.Pong, nil
				}
				return tunnelv1.WriteControl(server.control, response)
			})
			var rejected *ProtocolError
			if err := client.ActivateNativeLeg(t.Context(), "winner"); !errors.As(err, &rejected) || rejected.Code != tunnelv1.InvalidMessage {
				t.Fatal("activation trusted a foreign response", err)
			}
			if err := await(t, done); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNativeLegActivationCancellationAndDeadlineDoNotPermitRetry(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(map[bool]string{false: "canceled", true: "deadline"}[deadline], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				client, server, _, _ := nativeRenewalPair(t)
				cause := errors.New("activation owner stopped")
				ctx, cancel := context.WithCancelCause(t.Context())
				defer cancel(context.Canceled)
				want := cause
				if deadline {
					bounded, stop := context.WithTimeout(ctx, time.Second)
					defer stop()
					ctx, want = bounded, context.DeadlineExceeded
				}
				done := tunnelWorker(t, func() { cancel(cause); _ = server.Close() }, func() error {
					_, err := tunnelv1.ReadControl(server.control)
					if !deadline {
						cancel(cause)
					}
					return err // no activation response arrives before the owner stops.
				})
				err := client.ActivateNativeLeg(ctx, "pending")
				var unavailable *ProtocolError
				if !errors.Is(err, want) || !errors.As(err, &unavailable) || unavailable.Code != tunnelv1.Unavailable {
					t.Fatal("activation lost bounded cancellation or its cause", err)
				}
				if err := client.ActivateNativeLeg(t.Context(), "retry"); err == nil {
					t.Fatal("ambiguous activation was retried")
				}
				if err := await(t, done); err != nil {
					t.Fatal(err)
				}
			})
		})
	}
}
