package tunnel

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func connectorRenewalPair(t *testing.T) (*Session, *Session, tunnelv1.ConnectorPairLegProof, tunnelv1.ConnectorPairLegAccepted) {
	t.Helper()
	proof := tunnelv1.ConnectorPairLegProof{PairID: "cpp_1234567890123456789012", DeliveryGeneration: 1,
		ServiceID: "svc_1234567890123456789012", ServiceRunID: "srun_1234567890123456789012", RunNumber: 1,
		PublisherIdentityID: "pub_1234567890123456789012", PublisherConnectionID: "pc_1234567890123456789012", AssignmentRevision: 1,
		RelayServiceID: "relay-a", RelayID: "node-a", RelayRunID: "run-a", RelayLeaseRevision: 1, RequestedAt: time.Now(), Nonce: make([]byte, 32), Signature: make([]byte, 64)}
	receipt := tunnelv1.ConnectorPairLegAccepted{PairID: proof.PairID, DeliveryID: "AQEBAQEBAQEBAQEBAQEBAQ", DeliveryGeneration: 1,
		SourceIP: "127.0.0.1", ObservedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}
	left, right := newMemoryPair(t)
	type result struct {
		session *Session
		err     error
	}
	accepted := tunnelWorker(t, func() { _ = right.Close() }, func() result {
		session, _, err := AcceptWithResult(t.Context(), right, func(context.Context, tunnelv1.Message) (*tunnelv1.ConnectorPairLegAccepted, error) {
			return &receipt, nil
		})
		return result{session, err}
	})
	client, _, err := DialConnector(t.Context(), left, tunnelv1.Message{Type: tunnelv1.Hello, ProtocolVersion: tunnelv1.Version,
		Role: tunnelv1.Connector, ConnectorPairLegProof: &proof}, receipt.DeliveryID)
	if err != nil {
		t.Fatal(err)
	}
	server := await(t, accepted)
	if server.err != nil {
		t.Fatal(server.err)
	}
	t.Cleanup(func() { _ = client.Close(); _ = server.session.Close() })
	return client, server.session, proof, receipt
}

func TestConnectorLegRenewalUsesExistingControlAndRejectsSubstitution(t *testing.T) {
	client, server, proof, initial := connectorRenewalPair(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	calls := 0
	done := tunnelWorker(t, func() { cancel(); _ = server.Close() }, func() error {
		return server.HandleConnectorLegControl(ctx, nil, func(_ context.Context, requested tunnelv1.ConnectorPairLegProof) (tunnelv1.ConnectorPairLegAccepted, error) {
			calls++
			if requested.Nonce[0] != byte(calls) {
				t.Error("renewal lost fresh nonce")
			}
			if calls == 1 {
				return tunnelv1.ConnectorPairLegAccepted{}, &ProtocolError{Code: tunnelv1.Unavailable}
			}
			receipt := initial
			receipt.ObservedAt, receipt.ExpiresAt = time.Now(), time.Now().Add(2*time.Minute)
			return receipt, nil
		})
	})
	changed := proof
	changed.AssignmentRevision++
	if _, err := client.RenewConnectorLeg(t.Context(), "wrong", changed, initial); err == nil {
		t.Fatal("renewal substituted the original assignment")
	}
	for index := 1; index <= 2; index++ {
		proof.Nonce = bytes.Repeat([]byte{byte(index)}, 32)
		proof.RequestedAt = time.Now()
		receipt, err := client.RenewConnectorLeg(t.Context(), "renew", proof, initial)
		if index == 1 {
			var unavailable *ProtocolError
			if !errors.As(err, &unavailable) || unavailable.Code != tunnelv1.Unavailable {
				t.Fatal("temporary error lost its synchronized retry boundary", err)
			}
		} else if err != nil || receipt.SourceIP != initial.SourceIP || !receipt.ExpiresAt.After(initial.ExpiresAt) {
			t.Fatal("checked renewal failed", err)
		}
	}
	cancel()
	if err := await(t, done); err == nil || calls != 2 {
		t.Fatal("connector renewal worker did not join", err, calls)
	}
}

func TestConnectorLegRenewalRejectsChangedReceiptSource(t *testing.T) {
	client, server, proof, initial := connectorRenewalPair(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := tunnelWorker(t, func() { cancel(); _ = server.Close() }, func() error {
		return server.HandleConnectorLegControl(ctx, nil, func(context.Context, tunnelv1.ConnectorPairLegProof) (tunnelv1.ConnectorPairLegAccepted, error) {
			receipt := initial
			receipt.SourceIP = "127.0.0.2"
			return receipt, nil
		})
	})
	if _, err := client.RenewConnectorLeg(t.Context(), "renew", proof, initial); err == nil {
		t.Fatal("renewal rebound the accepted source")
	}
	cancel()
	_ = await(t, done)
}
