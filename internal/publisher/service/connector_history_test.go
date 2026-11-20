package service

import (
	"strconv"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestConnectorOpeningHistoryExpiresWithoutLifetimeCeiling(t *testing.T) {
	now := time.Unix(1_000, 0)
	peer := &PeerSession{seen: map[string]time.Time{}, streams: map[*connectorAdmission]struct{}{}}
	last := now.Add(time.Minute)
	for i := range 4_097 {
		if !peer.rememberOpeningLocked(strconv.Itoa(i), now, last) {
			t.Fatalf("refused unique opening %d", i)
		}
	}
	if peer.rememberOpeningLocked("0", now, last) {
		t.Fatal("accepted a replay before the permission expired")
	}
	active := &connectorAdmission{terminalKey: tunnelv1.ConnectorVisitorTerminalKey{VisitorConnectionID: "0", DeliveryGeneration: 1}}
	peer.streams[active] = struct{}{}
	if peer.rememberOpeningLocked("0", last, last.Add(time.Minute)) {
		t.Fatal("reused a visitor ID while its admission still owned it")
	}
	delete(peer.streams, active)
	if len(peer.seen) != 0 || len(peer.seenExpirations) != 0 {
		t.Fatal("expired proofs still occupy history")
	}
	if peer.rememberOpeningLocked("1", now, last) {
		t.Fatal("a backward policy observation reopened an expired replay window")
	}
	if !peer.rememberOpeningLocked("new", last, last.Add(time.Minute)) {
		t.Fatal("expired history stopped a new opening")
	}
}

func TestConnectorRenewalExtendsOpeningReplayFence(t *testing.T) {
	start := time.Unix(1_000, 0)
	first, renewal := start.Add(time.Minute), start.Add(2*time.Minute)
	peer := &PeerSession{seen: map[string]time.Time{}}
	if !peer.rememberOpeningLocked("original", start, first) {
		t.Fatal("opening refused")
	}
	peer.extendOpeningLocked("original", renewal)
	if peer.rememberOpeningLocked("original", first, renewal) {
		t.Fatal("opening replayed a still-valid renewal")
	}
	if !peer.rememberOpeningLocked("new", renewal, renewal.Add(time.Minute)) || len(peer.seen) != 1 {
		t.Fatal("renewed proof kept history after expiry")
	}
}
