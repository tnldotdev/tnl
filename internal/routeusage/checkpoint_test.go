package routeusage

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

func TestCheckpointRoundTripAndMerge(t *testing.T) {
	var first Checkpoint
	if err := first.PublisherOpenLatency.Observe(25 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := first.TimeToFirstPublisherByte.Observe(time.Second); err != nil {
		t.Fatal(err)
	}
	key := [32]byte{1}
	if !first.VisitorNetworks.Observe(key, "route-a", netip.MustParseAddr("192.0.2.1")) {
		t.Fatal("first visitor was not observed")
	}
	encoded := first.MarshalBinary()
	if !bytes.Equal(encoded[:5], []byte{'T', 'N', 'L', 'U', 1}) {
		t.Fatalf("checkpoint header = %x", encoded[:5])
	}
	decoded, err := ParseCheckpoint(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.PublisherOpenLatency.Count() != 1 ||
		decoded.PublisherOpenLatency.SumNanoseconds() != uint64(25*time.Millisecond) ||
		decoded.TimeToFirstPublisherByte.Count() != 1 || decoded.VisitorNetworks.Estimate() != 1 {
		t.Fatalf("decoded checkpoint = %#v", decoded)
	}

	var second Checkpoint
	if err := second.PublisherOpenLatency.Observe(50 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if !second.VisitorNetworks.Observe(key, "route-a", netip.MustParseAddr("192.0.2.2")) {
		t.Fatal("second visitor was not observed")
	}
	if err := decoded.Merge(second); err != nil {
		t.Fatal(err)
	}
	if decoded.PublisherOpenLatency.Count() != 2 || decoded.VisitorNetworks.Estimate() != 2 {
		t.Fatalf("merged checkpoint = %#v", decoded)
	}
}

func TestVisitorSketchScopesNetworksByRouteAndKey(t *testing.T) {
	source := netip.MustParseAddr("2001:db8:1::1")
	sameNetwork := netip.MustParseAddr("2001:db8:1::ffff")
	key := [32]byte{1}
	var sketch VisitorSketch
	if !sketch.Observe(key, "route-a", source) || sketch.Observe(key, "route-a", sameNetwork) || sketch.Estimate() != 1 {
		t.Fatalf("IPv6 /64 estimate = %d", sketch.Estimate())
	}
	first, _ := visitorNetworkHash(key, "route-a", source)
	otherRoute, _ := visitorNetworkHash(key, "route-b", source)
	otherKey, _ := visitorNetworkHash([32]byte{2}, "route-a", source)
	if first == otherRoute || first == otherKey {
		t.Fatal("visitor hash was not scoped by route and date key")
	}
}

func TestParseCheckpointRejectsMalformedData(t *testing.T) {
	valid := (Checkpoint{}).MarshalBinary()
	invalidHistogram := append([]byte(nil), valid...)
	binary.BigEndian.PutUint16(invalidHistogram[5:], 1)
	invalidHistogram = append(invalidHistogram[:7], append([]byte{1}, invalidHistogram[7:]...)...)
	tests := [][]byte{
		nil,
		[]byte("TNLU\x02"),
		valid[:len(valid)-1],
		append(append([]byte(nil), valid...), 0),
		invalidHistogram,
	}
	for _, data := range tests {
		if _, err := ParseCheckpoint(data); err == nil {
			t.Fatalf("accepted malformed checkpoint %x", data)
		}
	}
}
