package relay

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/pkg/api/relayv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestRelayAdmissionBindsPublisherAndCurrentVisitor(t *testing.T) {
	connection, peer := publisherFixture(t, "connection_1", 3)
	registry := NewRegistry()
	if err := registry.Insert(connection); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.Close() })
	forwarding := lifecycleHeader("connection_1", 3)
	forwarding.IPPolicyDenied = true
	lease := relayv1.RelayLease{RelayServiceId: forwarding.RelayServiceID, RelayId: forwarding.RelayID,
		RelayRunId: forwarding.RelayRunID, RelayLeaseRevision: int64(forwarding.RelayLeaseRevision),
		LeaseExpiresAt: time.Now().Add(time.Minute)}
	release, err := registry.registerAdmission(forwarding.VisitorConnectionID, &activeAdmission{
		header: forwarding, ingress: connection.session, connection: connection,
		currentLease: func() relayv1.RelayLease { return lease }, now: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	decision := tunnelv1.AdmissionHeader{ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.PublisherAdmissionStream,
		VisitorConnectionID: forwarding.VisitorConnectionID, PublicURLID: forwarding.PublicURLID,
		PublishRunID: forwarding.PublishRunID, PublishRunNumber: forwarding.PublishRunNumber,
		PublisherConnectionID:        forwarding.PublisherConnectionID,
		ConnectionAssignmentRevision: forwarding.ConnectionAssignmentRevision, RelayServiceID: forwarding.RelayServiceID,
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	respond := relayWorker(t, func() { cancel() }, func() error {
		incoming, err := peer.AcceptIngressAdmissionStream(ctx)
		if err != nil {
			return err
		}
		defer incoming.Stream.Close()
		if incoming.Header.Kind != tunnelv1.IngressAdmissionStream || incoming.Header.VisitorConnectionID != forwarding.VisitorConnectionID ||
			incoming.Header.RelayRunID != forwarding.RelayRunID {
			return errors.New("relay did not bind the ingress admission to its visitor")
		}
		if err := incoming.Accept(); err != nil {
			return err
		}
		return tunnelv1.WriteAdmissionResult(incoming.Stream, tunnelv1.AdmissionResult{Type: tunnelv1.StreamAccepted})
	})
	result, err := registry.forwardAdmission(ctx, connection, decision)
	if err != nil || result.Type != tunnelv1.StreamAccepted {
		t.Fatalf("forward current decision = %+v, %v", result, err)
	}
	if err := relayAwait(t, respond); err != nil {
		t.Fatal(err)
	}
	stale := decision
	stale.ConnectionAssignmentRevision++
	if _, err := registry.forwardAdmission(ctx, connection, stale); err == nil {
		t.Fatal("replaced connection assignment was allowed")
	}
	release()
	if _, err := registry.forwardAdmission(ctx, connection, decision); err == nil {
		t.Fatal("closed visitor was promoted")
	}
}

func TestRelayPublisherSidebandWaitsForIngressAcknowledgement(t *testing.T) {
	connection, publisher := publisherFixture(t, "connection_1", 3)
	registry := NewRegistry()
	if err := registry.Insert(connection); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.Close() })
	header := lifecycleHeader("connection_1", 3)
	header.IPPolicyDenied = true
	lease := relayv1.RelayLease{RelayServiceId: header.RelayServiceID, RelayId: header.RelayID,
		RelayRunId: header.RelayRunID, RelayLeaseRevision: int64(header.RelayLeaseRevision),
		LeaseExpiresAt: time.Now().Add(time.Minute)}
	release, err := registry.registerAdmission(header.VisitorConnectionID, &activeAdmission{
		header: header, ingress: connection.session, connection: connection,
		currentLease: func() relayv1.RelayLease { return lease }, now: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	server := relayWorker(t, func() { cancel(); _ = connection.session.Close() }, func() error {
		(&PublisherAcceptor{}).servePublisherAdmissions(ctx, connection.session, connection, registry)
		return nil
	})
	allowIngress := make(chan struct{})
	ingressAccepted := make(chan struct{})
	ingress := relayWorker(t, func() { cancel() }, func() error {
		incoming, err := publisher.AcceptIngressAdmissionStream(ctx)
		if err != nil {
			return err
		}
		defer incoming.Stream.Close()
		if err := incoming.Accept(); err != nil {
			return err
		}
		close(ingressAccepted)
		select {
		case <-allowIngress:
		case <-ctx.Done():
			return ctx.Err()
		}
		return tunnelv1.WriteAdmissionResult(incoming.Stream, tunnelv1.AdmissionResult{Type: tunnelv1.StreamAccepted})
	})
	decision := tunnelv1.AdmissionHeader{ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.PublisherAdmissionStream,
		VisitorConnectionID: header.VisitorConnectionID, PublicURLID: header.PublicURLID, PublishRunID: header.PublishRunID,
		PublishRunNumber: header.PublishRunNumber, PublisherConnectionID: header.PublisherConnectionID,
		ConnectionAssignmentRevision: header.ConnectionAssignmentRevision, RelayServiceID: header.RelayServiceID,
	}
	stream, err := publisher.OpenPublisherAdmissionStream(ctx, decision)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	result := make(chan tunnelv1.AdmissionResult, 1)
	read := relayWorker(t, func() { cancel() }, func() error {
		answer, err := tunnelv1.ReadAdmissionResult(stream)
		if err == nil {
			result <- answer
		}
		return err
	})
	select {
	case <-ingressAccepted:
	case <-ctx.Done():
		t.Fatal("relay did not open an ingress sideband")
	}
	select {
	case <-result:
		t.Fatal("publisher received an acknowledgement before ingress accepted")
	case <-time.After(20 * time.Millisecond):
	}
	close(allowIngress)
	if err := relayAwait(t, read); err != nil {
		t.Fatal(err)
	}
	if got := relayAwait(t, result); got.Type != tunnelv1.StreamAccepted {
		t.Fatalf("publisher result = %+v", got)
	}
	if err := relayAwait(t, ingress); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := relayAwait(t, server); err != nil {
		t.Fatal(err)
	}
}
