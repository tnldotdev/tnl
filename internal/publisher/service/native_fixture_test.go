package service

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

var nativeFixtureSequence atomic.Uint64

func nativeFixtureKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{37}, ed25519.SeedSize))
}

func nativeFixtureSubject() tunnelv1.VisitorSubject {
	return tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, IdentityID: "ident_" + strings.Repeat("a", 22), DeviceID: "vdev_" + strings.Repeat("b", 22)}
}

func nativeFixtureReservation(ref tunnelv1.ServicePublisherConnectionRef, visitor string) tunnelv1.StreamReservation {
	sequence := nativeFixtureSequence.Add(1)
	reservation := tunnelv1.StreamReservation{ID: "sres_" + strings.Repeat("a", 22), AllocationID: "salloc_" + strings.Repeat("b", 22), Slot: uint32(sequence % 64), Sequence: sequence,
		ResourceKind: "service", ResourceID: ref.ServiceID, RunID: ref.ServiceRunID, RunNumber: ref.RunNumber, VisitorConnectionID: visitor, IngressID: "fixture-ingress", IngressRunID: "irun_" + strings.Repeat("c", 22), IngressLeaseRevision: 1}
	if err := visitortoken.SignReservation(bytes.Repeat([]byte{1}, 32), &reservation, netip.MustParseAddr("192.0.2.10")); err != nil {
		panic(err)
	}
	return reservation
}

func prepareNativeFixturePolicy(t *testing.T, p *Prepared) {
	t.Helper()
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: p.Preparation.ServiceId}
	lease, err := visitorlease.New(scope, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(lease.Close)
	now := time.Now()
	a := controlv1.StreamCapacityAllocation{Id: "salloc_" + strings.Repeat("b", 22), Resource: controlv1.VisitorResourceScope{Kind: "service", Id: scope.ID}, RunId: p.Preparation.ServiceRunId,
		RunNumber: p.Preparation.RunNumber, Capacity: 64, IngressId: "fixture-ingress", IngressRunId: "irun_" + strings.Repeat("c", 22), IngressLeaseRevision: 1, ObservedAt: now, ValidUntil: now.Add(10 * time.Second), ReservationKey: bytes.Repeat([]byte{1}, 32)}
	if err := lease.Apply(lease.Begin(), visitorlease.Update{Snapshot: true, KeyRevision: 1, Enabled: true, Allocations: map[string]controlv1.StreamCapacityAllocation{a.Id: a},
		View: visitortoken.View{Issuer: "https://control.example.test", Scope: scope, Hostname: p.managedHostname, Port: p.servicePort, MetadataRevision: 1, VisitorPolicyRevision: 1,
			ObservedAt: now, ValidUntil: now.Add(10 * time.Second), Keys: map[string]ed25519.PublicKey{"native-fixture": nativeFixtureKey().Public().(ed25519.PublicKey)}}}); err != nil {
		t.Fatal(err)
	}
	p.policy = lease
}

func nativeFixtureOpening(t *testing.T, header tunnelv1.ServiceForwardingHeader) tunnelv1.ConnectorVisitorEntry {
	t.Helper()
	key := nativeFixtureKey()
	digest, err := visitortoken.KeyDigest(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	permission := visitortoken.Permission{Scope: visitorscope.Scope{Kind: visitorscope.Service, ID: header.ServiceID}, Hostname: "service.worktree.member.example.test", Port: 25443, VisitorPolicyRevision: 1,
		Subject: visitortoken.Device{IdentityID: header.Connector.Subject.IdentityID, DeviceID: header.Connector.Subject.DeviceID, SessionID: "cs_" + strings.Repeat("d", 22), KeySHA256: digest}, ExpiresAt: now.Add(time.Minute)}
	token, err := visitortoken.Sign("https://control.example.test", "native-fixture", key, permission, now)
	if err != nil {
		t.Fatal(err)
	}
	message, err := visitortoken.NativeProofMessage(token, header.Connector.SessionID, header.VisitorConnectionID, header.ServiceRunID, header.RunNumber, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	return tunnelv1.ConnectorVisitorEntry{ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.ConnectorVisitorStream, ServiceID: header.ServiceID, ServiceRunID: header.ServiceRunID, RunNumber: header.RunNumber, VisitorConnectionID: header.VisitorConnectionID, MetadataRevision: 1,
		Permission: tunnelv1.NativeVisitorPermission{Token: token.Reveal(), PublicKey: base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey)), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, message))}}
}

func writeNativeFixtureOpening(t *testing.T, connection net.Conn, header tunnelv1.ServiceForwardingHeader) (net.Conn, error) {
	t.Helper()
	_, err := tunnelv1.WriteConnectorVisitorOpening(connection, nativeFixtureOpening(t, header), nil)
	return tunnel.NewNativeRequestWriter(connection), err
}
