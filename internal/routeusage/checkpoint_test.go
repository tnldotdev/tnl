package routeusage

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// Wire v1: TNLU/version, four uint16-sized sections. Each histogram has a
// uint64 nanosecond sum followed by 22 cumulative uint64 counts, big endian.
// The three observations are 1ns, 2ns, 3ns; sparse sketch register 0 is 1.
const populatedCheckpointHex = `
544e4c5501
00b8
0000000000000001
0000000000000001 0000000000000001 0000000000000001 0000000000000001
0000000000000001 0000000000000001 0000000000000001 0000000000000001
0000000000000001 0000000000000001 0000000000000001 0000000000000001
0000000000000001 0000000000000001 0000000000000001 0000000000000001
0000000000000001 0000000000000001 0000000000000001 0000000000000001
0000000000000001 0000000000000001
00b8
0000000000000002
0000000000000001 0000000000000001 0000000000000001 0000000000000001
0000000000000001 0000000000000001 0000000000000001 0000000000000001
0000000000000001 0000000000000001 0000000000000001 0000000000000001
0000000000000001 0000000000000001 0000000000000001 0000000000000001
0000000000000001 0000000000000001 0000000000000001 0000000000000001
0000000000000001 0000000000000001
00b8
0000000000000003
0000000000000001 0000000000000001 0000000000000001 0000000000000001
0000000000000001 0000000000000001 0000000000000001 0000000000000001
0000000000000001 0000000000000001 0000000000000001 0000000000000001
0000000000000001 0000000000000001 0000000000000001 0000000000000001
0000000000000001 0000000000000001 0000000000000001 0000000000000001
0000000000000001 0000000000000001
0008 010c000001000001
`

func checkpointGolden(t *testing.T) []byte {
	t.Helper()
	data, err := hex.DecodeString(strings.Join(strings.Fields(populatedCheckpointHex), ""))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestCheckpointBinaryGolden(t *testing.T) {
	var want Checkpoint
	want.VisitorNetworks.registers[0] = 1
	for index, histogram := range []*DurationHistogram{&want.PublisherOpenLatency, &want.TimeToFirstPublisherByte, &want.SuccessfulConnectionDuration} {
		if err := histogram.Observe(time.Duration(index + 1)); err != nil {
			t.Fatal(err)
		}
	}
	golden := checkpointGolden(t)
	if encoded := want.MarshalBinary(); !bytes.Equal(encoded, golden) {
		t.Fatalf("encoding = %x, want %x", encoded, golden)
	}
	got, err := ParseCheckpoint(golden)
	if err != nil || got != want {
		t.Fatalf("parse = %#v, %v; want %#v", got, err, want)
	}
	// Empty sections are absent histograms, but the sketch still has a header.
	empty := []byte{'T', 'N', 'L', 'U', 1, 0, 0, 0, 0, 0, 0, 0, 5, 1, 12, 0, 0, 0}
	if !bytes.Equal((Checkpoint{}).MarshalBinary(), empty) {
		t.Fatal("empty checkpoint encoding changed")
	}
	if got, err := ParseCheckpoint(empty); err != nil || got != (Checkpoint{}) {
		t.Fatalf("empty parse = %#v, %v", got, err)
	}
}

func TestCheckpointMerge(t *testing.T) {
	first, err := ParseCheckpoint(checkpointGolden(t))
	if err != nil {
		t.Fatal(err)
	}
	second := first
	first.VisitorNetworks.registers[0] = 1
	second.VisitorNetworks.registers[0], second.VisitorNetworks.registers[4095] = 2, 3
	if err := first.Merge(second); err != nil {
		t.Fatal(err)
	}
	for index, histogram := range []DurationHistogram{first.PublisherOpenLatency, first.TimeToFirstPublisherByte, first.SuccessfulConnectionDuration} {
		if histogram.Count() != 2 || histogram.SumNanoseconds() != uint64(2*(index+1)) {
			t.Fatalf("histogram %d = %#v", index, histogram)
		}
		for bucket, count := range histogram.CumulativeCounts() {
			if count != 2 {
				t.Errorf("histogram %d bucket %d = %d, want 2", index, bucket, count)
			}
		}
	}
	var want VisitorSketch
	want.registers[0], want.registers[4095] = 2, 3
	if first.VisitorNetworks != want {
		t.Fatal("checkpoint did not merge visitor registers by maximum")
	}
	for _, field := range []string{"publisher open", "first byte", "successful duration"} {
		t.Run(field+" overflow", func(t *testing.T) {
			var destination, source Checkpoint
			left, right := &destination.PublisherOpenLatency, &source.PublisherOpenLatency
			switch field {
			case "first byte":
				left, right = &destination.TimeToFirstPublisherByte, &source.TimeToFirstPublisherByte
			case "successful duration":
				left, right = &destination.SuccessfulConnectionDuration, &source.SuccessfulConnectionDuration
			}
			left.sumNanoseconds, right.sumNanoseconds = 1<<63-1, 1
			if err := destination.Merge(source); err == nil {
				t.Fatal("histogram overflow accepted")
			}
		})
	}
}

func TestParseCheckpointRejectsMalformedData(t *testing.T) {
	valid := checkpointGolden(t)
	for length := range len(valid) {
		if _, err := ParseCheckpoint(valid[:length]); err == nil {
			t.Fatalf("accepted truncation at byte %d", length)
		}
	}
	for _, test := range []struct {
		name   string
		offset int
		value  byte
	}{
		{"magic", 0, 'X'}, {"version", 4, 2},
		{"first histogram size", 6, 183}, {"second histogram size", 192, 183}, {"third histogram size", 378, 183},
		{"sketch version", 565, 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := bytes.Clone(valid)
			data[test.offset] = test.value
			if _, err := ParseCheckpoint(data); err == nil {
				t.Fatal("accepted malformed checkpoint")
			}
		})
	}
	if _, err := ParseCheckpoint(append(valid, 0)); err == nil {
		t.Fatal("accepted trailing data")
	}
}
