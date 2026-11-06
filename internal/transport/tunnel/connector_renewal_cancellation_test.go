package tunnel

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestConnectorLegInterruptedRenewalRetiresAmbiguousControl(t *testing.T) {
	for _, partial := range []bool{false, true} {
		for _, deadline := range []bool{false, true} {
			name := map[bool]string{false: "missing reply", true: "partial reply"}[partial] + "/" + map[bool]string{false: "cancel", true: "deadline"}[deadline]
			t.Run(name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					client, server, proof, receipt := connectorRenewalPair(t)
					entered, release := make(chan struct{}), make(chan struct{})
					unblock := sync.OnceFunc(func() { close(release) })
					replied := tunnelWorker(t, func() { unblock(); _ = server.Close() }, func() error {
						request, err := tunnelv1.ReadControl(server.control)
						if err != nil {
							return err
						}
						fresh := receipt
						fresh.ObservedAt, fresh.ExpiresAt = time.Now(), time.Now().Add(time.Minute)
						var wire bytes.Buffer
						if err := tunnelv1.WriteControl(&wire, tunnelv1.Message{Type: tunnelv1.ConnectorLegRenewed, ProtocolVersion: tunnelv1.Version, RequestID: request.RequestID, ConnectorPairLegAccepted: &fresh}); err != nil {
							return err
						}
						if partial {
							// net.Pipe joins consumption of this prefix before cancellation.
							if _, err := server.control.Write(wire.Next(8)); err != nil {
								return err
							}
						}
						close(entered)
						<-release
						_, err = server.control.Write(wire.Bytes())
						return err
					})
					ctx, cancel := context.WithTimeout(t.Context(), time.Second)
					defer cancel()
					type result struct {
						receipt tunnelv1.ConnectorPairLegAccepted
						err     error
					}
					renewed := tunnelWorker(t, func() { cancel(); _ = client.Close() }, func() result {
						updated, err := client.RenewConnectorLeg(ctx, "interrupted", proof, receipt)
						return result{updated, err}
					})
					await(t, entered)
					want := context.DeadlineExceeded
					if !deadline {
						want = context.Canceled
						cancel()
					}
					got := await(t, renewed)
					if !errors.Is(got.err, want) {
						t.Fatalf("interrupted renewal lost its cause: %v", got.err)
					}
					if got.receipt != (tunnelv1.ConnectorPairLegAccepted{}) {
						t.Fatal("interrupted renewal returned unconfirmed authority")
					}
					select {
					case <-client.Done():
					default:
						t.Fatal("interrupted renewal left its ambiguous control stream reusable")
					}
					unblock()
					if err := await(t, replied); err == nil {
						t.Fatal("late reply reached the interrupted control stream")
					}
				})
			})
		}
	}
}
