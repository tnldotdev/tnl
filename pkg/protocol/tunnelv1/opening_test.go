package tunnelv1

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

type openingWriter struct {
	bytes.Buffer
	calls int
	limit int
}

func TestOpeningPublicReservationKeepsExactBinding(t *testing.T) {
	h, err := ReadVisitorStreamHeader(bytes.NewReader(goldenWire(t, "visitor-stream-header")))
	if err != nil {
		t.Fatal(err)
	}
	h.PublicURLID, h.PublishRunID, h.VisitorConnectionID = "url_"+strings.Repeat("A", 22), "pr_"+strings.Repeat("B", 22), "vc_"+strings.Repeat("C", 22)
	h.Reservation = StreamReservation{ID: "sres_" + strings.Repeat("D", 22), AllocationID: "salloc_" + strings.Repeat("E", 22), Sequence: 1, ResourceKind: "public_url", ResourceID: h.PublicURLID,
		RunID: h.PublishRunID, RunNumber: h.PublishRunNumber, VisitorConnectionID: h.VisitorConnectionID, IngressID: "ingress", IngressRunID: "process", IngressLeaseRevision: 1}
	w := &openingWriter{limit: -1}
	if _, err := WriteVisitorOpening(w, h, []byte("encrypted initial bytes")); err != nil {
		t.Fatal(err)
	}
	got, payload, err := ReadVisitorOpening(bytes.NewReader(w.Bytes()))
	if err != nil || got != h || string(payload) != "encrypted initial bytes" || w.calls != 1 {
		t.Fatal("combined opening changed reservation or initial bytes", err)
	}
	for _, change := range []func(*StreamReservation){
		func(r *StreamReservation) { r.ResourceID = "url_" + strings.Repeat("F", 22) },
		func(r *StreamReservation) { r.RunID = "pr_" + strings.Repeat("F", 22) },
		func(r *StreamReservation) { r.RunNumber++ },
		func(r *StreamReservation) { r.VisitorConnectionID = "vc_" + strings.Repeat("F", 22) },
		func(r *StreamReservation) { r.Sequence = 0 },
	} {
		bad := h
		change(&bad.Reservation)
		if err := bad.Validate(); !errors.Is(err, ErrInvalidStreamReservation) {
			t.Fatal("opening accepted a replaced reservation binding", err)
		}
	}
}

func TestOpeningNativePermissionAndInitialBytesStayBoundedAndSeparate(t *testing.T) {
	entry := nativeTestEntry()
	initial := []byte{0x16, 3, 1, 0, 2, 1, 0}
	writer := &openingWriter{limit: -1}
	if committed, err := WriteConnectorVisitorOpening(writer, entry, initial); err != nil || !committed || writer.calls != 1 {
		t.Fatal("native opening did not combine permission and initial bytes", err)
	}
	wire := bytes.Clone(writer.Bytes())
	reader := bytes.NewReader(append(wire, []byte("subsequent native bytes")...))
	got, payload, err := ReadConnectorVisitorOpening(reader)
	if err != nil || got != entry || !bytes.Equal(payload, initial) {
		t.Fatal("native opening changed signed proof or initial bytes", err)
	}
	rest, _ := io.ReadAll(reader)
	if string(rest) != "subsequent native bytes" {
		t.Fatal("native opening consumed following protocol bytes")
	}
	for length := range len(wire) {
		if _, _, err := ReadConnectorVisitorOpening(bytes.NewReader(wire[:length])); err == nil {
			t.Fatalf("native opening accepted truncation at %d", length)
		}
	}
	writer.Reset()
	writer.calls = 0
	if _, err := WriteConnectorVisitorOpening(writer, entry, make([]byte, MaxInitialBytes+1)); err == nil || writer.calls != 0 {
		t.Fatal("oversized native initial bytes reached the stream")
	}
	for _, change := range []func(*ConnectorVisitorEntry){
		func(e *ConnectorVisitorEntry) { e.MetadataRevision = 0 },
		func(e *ConnectorVisitorEntry) { e.VisitorConnectionID = "" },
		func(e *ConnectorVisitorEntry) { e.Permission.Token = strings.Repeat("a", 2049) },
		func(e *ConnectorVisitorEntry) { e.Permission.PublicKey = "invalid" },
		func(e *ConnectorVisitorEntry) { e.Permission.Signature = "invalid" },
	} {
		bad := entry
		change(&bad)
		writer.Reset()
		writer.calls = 0
		if _, err := WriteConnectorVisitorOpening(writer, bad, nil); err == nil || writer.calls != 0 {
			t.Fatal("incomplete native proof reached the stream")
		}
	}
}

func (w *openingWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.limit >= 0 && len(p) > w.limit {
		n, _ := w.Buffer.Write(p[:w.limit])
		return n, io.ErrClosedPipe
	}
	return w.Buffer.Write(p)
}

func TestOpeningCombinesHeaderAndInitialBytesAtExactRetryBoundary(t *testing.T) {
	h, err := ReadVisitorStreamHeader(bytes.NewReader(goldenWire(t, "visitor-stream-header")))
	if err != nil {
		t.Fatal(err)
	}
	initial := []byte{0x16, 3, 1}
	w := &openingWriter{limit: -1}
	committed, err := WriteVisitorOpening(w, h, initial)
	if err != nil || !committed || w.calls != 1 {
		t.Fatal("metadata and initial bytes were not sent in one write", err)
	}
	want := append(goldenWire(t, "visitor-stream-header"), []byte{0, 0, 0, 3, 0x16, 3, 1}...)
	if !bytes.Equal(w.Bytes(), want) {
		t.Fatalf("opening wire = %x; want %x", w.Bytes(), want)
	}
	for _, offset := range []int{-1, 0, 1, 2} {
		boundary := len(want) - len(initial)
		short := &openingWriter{limit: boundary + offset}
		crossed, err := WriteVisitorOpening(short, h, initial)
		if !errors.Is(err, io.ErrClosedPipe) || crossed != (offset > 0) {
			t.Fatalf("partial write offset %d: committed=%t error=%v", offset, crossed, err)
		}
	}
	r := bytes.NewReader(append(bytes.Clone(want), []byte("next request bytes")...))
	got, payload, err := ReadVisitorOpening(r)
	if err != nil || got != h || !bytes.Equal(payload, initial) {
		t.Fatal("opening changed metadata or bytes", err)
	}
	rest, _ := io.ReadAll(r)
	if string(rest) != "next request bytes" {
		t.Fatal("opening consumed subsequent request bytes")
	}
	for length := range len(want) {
		if _, _, err := ReadVisitorOpening(bytes.NewReader(want[:length])); err == nil {
			t.Fatalf("accepted opening truncated at %d", length)
		}
	}
}

func TestOpeningBoundsInitialBytesBeforePayloadReadOrWrite(t *testing.T) {
	h, err := ReadVisitorStreamHeader(bytes.NewReader(goldenWire(t, "visitor-stream-header")))
	if err != nil {
		t.Fatal(err)
	}
	w := &openingWriter{limit: -1}
	if _, err := WriteVisitorOpening(w, h, make([]byte, MaxInitialBytes+1)); err == nil || w.calls != 0 {
		t.Fatal("oversized initial payload reached the transport")
	}
	for _, length := range []uint32{0, MaxInitialBytes, MaxInitialBytes + 1} {
		wire := binary.BigEndian.AppendUint32(goldenWire(t, "visitor-stream-header"), length)
		if length <= MaxInitialBytes {
			wire = append(wire, make([]byte, length)...)
		}
		_, _, err := ReadVisitorOpening(bytes.NewReader(wire))
		if (err == nil) != (length <= MaxInitialBytes) {
			t.Fatalf("initial length %d: %v", length, err)
		}
	}
}

func TestOpeningProxyMetadataDoesNotCrossVisitorRetryBoundary(t *testing.T) {
	h, err := ReadInternalForwardingHeader(bytes.NewReader(goldenWire(t, "internal-forwarding-header")))
	if err != nil {
		t.Fatal(err)
	}
	proxy, hello := []byte("trusted proxy metadata"), []byte("visitor hello")
	full := &openingWriter{limit: -1}
	if _, err := WriteForwardingOpening(full, h, proxy, hello); err != nil {
		t.Fatal(err)
	}
	for _, offset := range []int{-len(proxy), -1, 0, 1} {
		partial := &openingWriter{limit: full.Len() - len(hello) + offset}
		committed, err := WriteForwardingOpening(partial, h, proxy, hello)
		if !errors.Is(err, io.ErrClosedPipe) || committed != (offset > 0) {
			t.Fatalf("offset from first visitor byte %d: committed=%t error=%v", offset, committed, err)
		}
	}
	_, _, initial, err := ReadForwardingOpening(bytes.NewReader(full.Bytes()))
	if err != nil || string(initial) != string(proxy)+string(hello) {
		t.Fatal("opening changed or duplicated ingress metadata", err)
	}
}

func TestReturnFrameGoldenWireAndTruncation(t *testing.T) {
	for _, test := range []struct {
		frame ReturnFrame
		hex   string
	}{
		{ReturnFrame{Kind: ReturnAccepted}, "0100000000"},
		{ReturnFrame{Kind: ReturnRejected, Code: CapacityExceeded}, "020000001163617061636974795f6578636565646564"},
		{ReturnFrame{Kind: ReturnData, Data: []byte{0x16, 3, 1}}, "0400000003160301"},
		{ReturnFrame{Kind: ReturnEnded}, "0500000000"},
	} {
		want, err := hex.DecodeString(test.hex)
		if err != nil {
			t.Fatal(err)
		}
		var b bytes.Buffer
		if err := WriteReturnFrame(&b, test.frame); err != nil || !bytes.Equal(b.Bytes(), want) {
			t.Fatalf("return frame = %x, want %x: %v", b.Bytes(), want, err)
		}
		got, err := ReadReturnFrame(bytes.NewReader(want))
		if err != nil || !reflect.DeepEqual(got, test.frame) {
			t.Fatalf("return frame round trip: %#v %v", got, err)
		}
		for length := range len(want) {
			if _, err := ReadReturnFrame(bytes.NewReader(want[:length])); err == nil {
				t.Fatalf("accepted return frame truncated at %d", length)
			}
		}
	}
	for _, name := range []string{"publisher-admission-header", "ingress-admission-header"} {
		want := append([]byte{byte(ReturnPromoted)}, goldenWire(t, name)...)
		frame, err := ReadReturnFrame(bytes.NewReader(want))
		if err != nil || frame.Kind != ReturnPromoted {
			t.Fatal("promotion golden could not be decoded", err)
		}
		var b bytes.Buffer
		if err := WriteReturnFrame(&b, frame); err != nil || !bytes.Equal(b.Bytes(), want) {
			t.Fatal("promotion changed its golden identity or framing", err)
		}
	}
}

func TestReturnFrameRejectsUnknownAndOversizedPayloadBeforeReading(t *testing.T) {
	for _, test := range []struct {
		kind ReturnFrameKind
		size uint32
	}{
		{0, 0}, {255, 1}, {ReturnAccepted, 1}, {ReturnEnded, 1},
		{ReturnRejected, 129}, {ReturnData, 0}, {ReturnData, MaxStreamDataBytes + 1}, {ReturnPromoted, MaxHeaderBytes + 1},
	} {
		prefix := binary.BigEndian.AppendUint32([]byte{byte(test.kind)}, test.size)
		r := &headerOnlyReader{header: bytes.NewReader(prefix)}
		if _, err := ReadReturnFrame(r); !errors.Is(err, ErrReturnFrame) || r.payloadReads != 0 {
			t.Fatalf("kind=%d length=%d read its invalid payload: %v", test.kind, test.size, err)
		}
	}
}

func FuzzReadOpeningsAndReturnFrames(f *testing.F) {
	f.Add(uint8(0), append(goldenWire(f, "visitor-stream-header"), 0, 0, 0, 0))
	f.Add(uint8(1), []byte{1, 0, 0, 0, 0})
	var native bytes.Buffer
	if _, err := WriteConnectorVisitorOpening(&native, nativeTestEntry(), []byte{0x16, 3, 1}); err != nil {
		f.Fatal(err)
	}
	f.Add(uint8(2), native.Bytes())
	f.Fuzz(func(t *testing.T, kind uint8, wire []byte) {
		r := bytes.NewReader(wire)
		switch kind % 3 {
		case 0:
			_, _, _ = ReadVisitorOpening(r)
		case 1:
			_, _ = ReadReturnFrame(r)
		case 2:
			_, _, _ = ReadConnectorVisitorOpening(r)
		}
	})
}
