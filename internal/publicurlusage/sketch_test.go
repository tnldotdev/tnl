package publicurlusage

import (
	"bytes"
	"net/netip"
	"testing"
)

func TestVisitorSketchScopesNetworksByRouteAndKey(t *testing.T) {
	key := [32]byte{1}
	var sketch VisitorSketch
	for _, test := range []struct {
		source   string
		changed  bool
		estimate uint64
	}{
		{"2001:db8:1::1", true, 1}, {"2001:db8:1::ffff", false, 1},
		{"2001:db8:1:1::1", true, 2}, {"192.0.2.1", true, 3},
		{"::ffff:192.0.2.1", false, 3}, {"192.0.2.2", true, 4},
	} {
		if changed := sketch.Observe(key, "route-a", netip.MustParseAddr(test.source)); changed != test.changed || sketch.Estimate() != test.estimate {
			t.Fatalf("%s: changed=%t estimate=%d", test.source, changed, sketch.Estimate())
		}
	}
	before := sketch
	if sketch.Observe(key, "", netip.MustParseAddr("192.0.2.3")) || sketch.Observe(key, "route-a", netip.Addr{}) || sketch != before {
		t.Fatal("invalid input changed sketch")
	}
	source := netip.MustParseAddr("2001:db8:1::1")
	first, _ := visitorNetworkHash(key, "route-a", source)
	otherPublicURL, _ := visitorNetworkHash(key, "route-b", source)
	otherKey, _ := visitorNetworkHash([32]byte{2}, "route-a", source)
	if first == otherPublicURL || first == otherKey {
		t.Fatal("visitor hash was not scoped by route and date key")
	}
}

func TestVisitorSketchSparseAndDenseVectors(t *testing.T) {
	// version 1, precision 12, sparse; registers 0=1, 2048=7, 4095=53.
	sparse := []byte{1, 12, 0, 0, 3, 0, 0, 1, 8, 0, 7, 15, 255, 53}
	var want VisitorSketch
	want.registers[0], want.registers[2048], want.registers[4095] = 1, 7, 53
	got, err := parseVisitorSketch(sparse)
	if err != nil || got != want || !bytes.Equal(want.MarshalBinary(), sparse) {
		t.Fatalf("sparse vector: %v", err)
	}
	// every register is populated, so the dense vector is deterministic.
	dense := append([]byte{1, 12, 1}, bytes.Repeat([]byte{1}, 4096)...)
	for index := range want.registers {
		want.registers[index] = 1
	}
	got, err = parseVisitorSketch(dense)
	if err != nil || got != want || !bytes.Equal(want.MarshalBinary(), dense) || got.Estimate() != 5907 {
		t.Fatalf("dense vector: estimate=%d error=%v", got.Estimate(), err)
	}
	// sparse costs 5+3n bytes, dense costs 4099: transition at n=1365.
	for _, count := range []int{1364, 1365} {
		var sketch VisitorSketch
		for index := range count {
			sketch.registers[index] = 1
		}
		encoded := sketch.MarshalBinary()
		if count == 1364 && (encoded[2] != 0 || len(encoded) != 4097) || count == 1365 && (encoded[2] != 1 || len(encoded) != 4099) {
			t.Fatalf("%d registers: encoding=%d size=%d", count, encoded[2], len(encoded))
		}
	}
}

func TestVisitorSketchMergeVectors(t *testing.T) {
	sparse := []byte{1, 12, 0, 0, 3, 0, 0, 1, 8, 0, 7, 15, 255, 53}
	dense := append([]byte{1, 12, 1}, bytes.Repeat([]byte{2}, 4096)...)
	for _, pair := range []struct {
		name        string
		left, right []byte
	}{
		{"sparse sparse", sparse, []byte{1, 12, 0, 0, 2, 0, 0, 3, 0, 1, 2}},
		{"sparse dense", sparse, dense}, {"dense sparse", dense, sparse}, {"dense dense", dense, dense},
	} {
		t.Run(pair.name, func(t *testing.T) {
			left, err := parseVisitorSketch(pair.left)
			if err != nil {
				t.Fatal(err)
			}
			right, err := parseVisitorSketch(pair.right)
			if err != nil {
				t.Fatal(err)
			}
			before := right
			left.merge(right)
			var want VisitorSketch
			switch pair.name {
			case "sparse sparse":
				want.registers[0], want.registers[1], want.registers[2048], want.registers[4095] = 3, 2, 7, 53
			case "dense dense":
				for index := range want.registers {
					want.registers[index] = 2
				}
			default:
				for index := range want.registers {
					want.registers[index] = 2
				}
				want.registers[2048], want.registers[4095] = 7, 53
			}
			if left != want || right != before {
				t.Fatal("merge did not produce independent register maxima")
			}
			left.merge(right)
			if left != want {
				t.Fatal("merge is not idempotent")
			}
		})
	}
}

func TestParseVisitorSketchRejectsMalformedVectors(t *testing.T) {
	for name, data := range map[string][]byte{
		"short header": {1, 12}, "version": {2, 12, 0, 0, 0}, "precision": {1, 11, 0, 0, 0},
		"encoding": {1, 12, 2}, "short sparse": {1, 12, 0, 0}, "count mismatch": {1, 12, 0, 0, 1},
		"trailing sparse": {1, 12, 0, 0, 0, 0}, "zero register": {1, 12, 0, 0, 1, 0, 0, 0},
		"rank too high": {1, 12, 0, 0, 1, 0, 0, 54}, "index too high": {1, 12, 0, 0, 1, 16, 0, 1},
		"duplicate index": {1, 12, 0, 0, 2, 0, 1, 1, 0, 1, 2}, "unordered index": {1, 12, 0, 0, 2, 0, 2, 1, 0, 1, 2},
		"short dense":        append([]byte{1, 12, 1}, make([]byte, 4095)...),
		"long dense":         append([]byte{1, 12, 1}, make([]byte, 4097)...),
		"invalid dense rank": append([]byte{1, 12, 1}, bytes.Repeat([]byte{54}, 4096)...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseVisitorSketch(data); err == nil {
				t.Fatal("accepted malformed sketch")
			}
		})
	}
}
