package ingress

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestRelayReplacementIgnoresRenewedLeaseAndRetainsAssignmentFacts(t *testing.T) {
	_, snapshot := serviceRoutingFixture(t)
	original := snapshot.Runs[0].ConnectedRelays
	renewed := slices.Clone(original)
	for index := range renewed {
		renewed[index].ServingUntil = renewed[index].ServingUntil.Add(time.Second)
		renewed[index].LeaseExpiresAt = renewed[index].LeaseExpiresAt.Add(time.Second)
	}
	if len(replacementRelays(original, renewed)) != 0 {
		t.Fatal("lease renewal retried a failed publisher connection")
	}
	renewed[0].ConnectionAssignmentRevision++
	replacements := replacementRelays(original, renewed)
	if len(replacements) != 1 || replacements[0] != renewed[0] {
		t.Fatal("replacement lost its exact relay/assignment tuple")
	}
}

func TestRelayReplacementWaitRetainsOriginalDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lease, snapshot := serviceRoutingFixture(t)
		routing := NewServiceRouting()
		defer routing.Close()
		if err := routing.apply(time.Now(), lease, snapshot); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Millisecond)
		previous := routing.lookup("route.example", 443, lease, time.Now())[0]
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		done := make(chan error, 1)
		go func() {
			_, err := routing.waitForRelayReplacement(ctx, previous, lease, netip.MustParseAddr("192.0.2.4"))
			done <- err
		}()
		synctest.Wait()
		time.Sleep(time.Second)
		if err := <-done; !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("replacement wait renewed setup or lost its deadline", err)
		}
	})
}

func TestHTTPRelayReplacementBeforeFirstByteKeepsVisitorAndSingleCapacityDebit(t *testing.T) {
	replacement := newServiceTLSRelay(t)
	failedHeaders := make(chan tunnelv1.ServiceForwardingHeader, 2)
	replacementHeader := make(chan tunnelv1.ServiceForwardingHeader, 1)
	replace := make(chan struct{}, 1)
	var first atomic.Bool
	config := serviceIngressConfig(t,
		func(ctx context.Context, header tunnelv1.ServiceForwardingHeader, capacity func(context.Context) error) (net.Conn, error) {
			if first.Swap(true) {
				replacementHeader <- header
				return replacement.open(ctx, header, capacity)
			}
			failedHeaders <- header
			return nil, ErrServiceAdmission
		},
		func(_ context.Context, header tunnelv1.ServiceForwardingHeader, _ func(context.Context) error) (net.Conn, error) {
			failedHeaders <- header
			replace <- struct{}{}
			return nil, ErrServiceAdmission
		})
	control := config.Control.(*httpsServiceControl)
	control.anonymous = true
	control.traffic.TotalConnections = new(int64(1))
	server, address := startIngress(t, config)
	lease := config.CurrentLease()
	original := server.services.lookup("route.example", 443, lease, time.Now())[0]
	installed, reads := installRelayReplacementFixture(t, server, replace, 0)
	client := ingressClient(t, address, "route.example", "192.0.2.4:42000")
	if err := client.Handshake(); err != nil {
		t.Fatal("first visitor did not use its same run's replacement", err)
	}
	exchangePing(t, client)
	if err := ingressAwait(t, installed); err != nil {
		t.Fatal(err)
	}
	result := ingressAwait(t, replacement.result)
	before, second, after := <-failedHeaders, <-failedHeaders, <-replacementHeader
	if result.err != nil || result.request != "ping" || replacement.opens.Load() != 1 ||
		before.VisitorConnectionID != second.VisitorConnectionID || result.visitorConnectionID != before.VisitorConnectionID ||
		after.ServiceID != before.ServiceID || after.ServiceRunID != before.ServiceRunID || after.RunNumber != before.RunNumber ||
		after.ExpiresAt.After(before.ExpiresAt) || !second.ExpiresAt.Equal(before.ExpiresAt) ||
		control.reads.Load() != reads || len(control.claims) != 0 {
		t.Fatal("relay replacement changed delivery, visitor identity, or used visitor control", result.err)
	}
	proof, err := tunnelv1.ReadVisitorSourceProof([]byte(result.header.VisitorSourceProof))
	originalAuthority, originalErr := original.source.MarshalBinary()
	actualAuthority, actualErr := proof.Authority.MarshalBinary()
	binding := tunnelv1.VisitorSourceBinding{
		ServiceID: before.ServiceID, ServiceRunID: before.ServiceRunID, RunNumber: before.RunNumber,
		VisitorConnectionID: before.VisitorConnectionID, Source: netip.MustParseAddrPort("192.0.2.4:42000"),
		Destination: netip.MustParseAddrPort("203.0.113.10:443"),
	}
	if err != nil || originalErr != nil || actualErr != nil || !bytes.Equal(actualAuthority, originalAuthority) ||
		visitortoken.VerifyVisitorSource([32]byte{1}, proof, binding, original.source.VisitorPolicyRevision, time.Now()) != nil {
		t.Fatal("relay replacement changed the original exact source authority", err)
	}
	server.StopAccepting()
	server.active.Wait()
	key := trafficKey{service: before.ServiceID, id: before.ServiceRunID, run: before.RunNumber}
	server.traffic.mu.Lock()
	budget := *server.traffic.runs[key]
	server.traffic.mu.Unlock()
	if budget.connections != 1 || budget.active != 0 {
		t.Fatal("relay replacement duplicated or retained the original capacity debit", budget)
	}
}

func TestHTTPRelayReplacementNeverRetriesCommittedVisitorByte(t *testing.T) {
	failed := newServiceFailureRelay(t, 1)
	replace := make(chan struct{}, 1)
	var first, second atomic.Int32
	config := serviceIngressConfig(t,
		func(ctx context.Context, header tunnelv1.ServiceForwardingHeader, capacity func(context.Context) error) (net.Conn, error) {
			if first.Add(1) == 1 {
				return nil, ErrServiceAdmission
			}
			return failed.open(ctx, header, capacity)
		},
		func(context.Context, tunnelv1.ServiceForwardingHeader, func(context.Context) error) (net.Conn, error) {
			if second.Add(1) == 1 {
				replace <- struct{}{}
			}
			return nil, ErrServiceAdmission
		})
	server, address := startIngress(t, config)
	installed, reads := installRelayReplacementFixture(t, server, replace, 0, 1)
	client := ingressClient(t, address, "route.example", "192.0.2.4:42000")
	if err := client.Handshake(); err == nil {
		t.Fatal("a committed replacement completed TLS")
	}
	if err := ingressAwait(t, installed); err != nil {
		t.Fatal(err)
	}
	server.StopAccepting()
	server.active.Wait()
	control := config.Control.(*httpsServiceControl)
	if first.Load() != 2 || second.Load() != 1 || failed.opens.Load() != 1 ||
		control.reads.Load() != reads || len(control.claims) != 0 {
		t.Fatal("retried a committed replacement or requested visitor control", first.Load(), second.Load())
	}
}

func installRelayReplacementFixture(t *testing.T, server *Server, replace <-chan struct{}, slots ...int) (<-chan error, int32) {
	t.Helper()
	control := server.config.Control.(*httpsServiceControl)
	lease := server.config.CurrentLease()
	fresh, err := control.ReadIngressServices(t.Context(), lease.IngressId, ingressv1.IngressLeaseIdentity{
		IngressId: lease.IngressId, IngressRunId: lease.IngressRunId, IngressLeaseRevision: lease.IngressLeaseRevision,
	})
	if err != nil {
		t.Fatal(err)
	}
	// a fresh policy delegation must not replace the visitor's original proof.
	authority, err := tunnelv1.ReadVisitorSourceAuthority(fresh.Runs[0].SourceAuthority)
	if err != nil {
		t.Fatal(err)
	}
	authority.VisitorPolicyRevision++
	authority, key, err := visitortoken.IssueVisitorSourceAuthority([32]byte{1}, authority, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	fresh.Runs[0].SourceAuthority, err = authority.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	fresh.Runs[0].SourceKey = key[:]
	fresh.Runs[0].ConnectedRelays = slices.Clone(fresh.Runs[0].ConnectedRelays)
	for _, slot := range slots {
		fresh.Runs[0].ConnectedRelays[slot].PublisherConnectionId = publicServiceTestID(t, "pc_")
		fresh.Runs[0].ConnectedRelays[slot].ConnectionAssignmentRevision++
	}
	update, cancel := context.WithCancel(t.Context())
	installed := ingressWorker(t, cancel, func() error {
		select {
		case <-replace:
		case <-update.Done():
			return nil
		}
		started := time.Now()
		fresh.ObservedAt = started
		return server.services.apply(started, lease, fresh)
	})
	return installed, control.reads.Load()
}
