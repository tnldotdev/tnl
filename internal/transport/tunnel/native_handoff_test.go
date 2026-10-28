package tunnel

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestNativeLegHandoffBindsBothCandidates(t *testing.T) {
	for _, outcome := range []string{"accepted", "wrong predecessor", "wrong response kind"} {
		t.Run(outcome, func(t *testing.T) {
			client, server, proof, _ := nativeRenewalPair(t)
			previous := bytes.Repeat([]byte{1}, 32)
			done := tunnelWorker(t, func() { _ = server.Close() }, func() error {
				request, err := tunnelv1.ReadControl(server.control)
				if err != nil {
					return err
				}
				if request.Type != tunnelv1.NativeLegHandoff || !request.NativeLegBinding.Matches(proof) || !bytes.Equal(request.NativeLegBinding.PreviousNonce, previous) {
					t.Error("handoff lost its exact old and new candidate bindings")
				}
				response := tunnelv1.Message{Type: tunnelv1.NativeLegHandedOff, ProtocolVersion: tunnelv1.Version,
					RequestID: request.RequestID, NativeLegBinding: request.NativeLegBinding}
				if outcome == "wrong predecessor" {
					response.NativeLegBinding.PreviousNonce = bytes.Repeat([]byte{2}, 32)
				}
				if outcome == "wrong response kind" {
					response.Type = tunnelv1.NativeLegActivated
					response.NativeLegBinding.PreviousNonce = nil
				}
				return tunnelv1.WriteControl(server.control, response)
			})
			err := client.HandoffNativeLeg(t.Context(), "handoff", previous)
			if outcome == "accepted" {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				var rejected *ProtocolError
				if !errors.As(err, &rejected) || rejected.Code != tunnelv1.InvalidMessage {
					t.Fatal("handoff trusted a mismatched acknowledgment", err)
				}
			}
			if err := client.HandoffNativeLeg(context.Background(), "again", previous); err == nil {
				t.Fatal("handoff was repeated")
			}
			if err := client.ActivateNativeLeg(context.Background(), "startup"); err == nil {
				t.Fatal("handoff retried as startup activation")
			}
			if err := await(t, done); err != nil {
				t.Fatal(err)
			}
		})
	}
}
