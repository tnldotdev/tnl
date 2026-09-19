package tunnelv1

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"
)

func readControl(r io.Reader) error    { _, err := ReadControl(r); return err }
func readVisitor(r io.Reader) error    { _, err := ReadVisitorStreamHeader(r); return err }
func readForwarding(r io.Reader) error { _, err := ReadInternalForwardingHeader(r); return err }
func readResponse(r io.Reader) error   { _, err := ReadStreamResponse(r); return err }

var frameReaders = []struct {
	name  string
	limit int
	read  func(io.Reader) error
}{
	{"control-hello", MaxControlBytes, readControl},
	{"visitor-stream-header", MaxHeaderBytes, readVisitor},
	{"internal-forwarding-header", MaxHeaderBytes, readForwarding},
	{"stream-response", MaxHeaderBytes, readResponse},
}

func frame(payload string) io.Reader {
	wire := binary.BigEndian.AppendUint32(nil, uint32(len(payload)))
	return bytes.NewReader(append(wire, payload...))
}

func TestFramedWireFixturesRejectEveryTruncation(t *testing.T) {
	for _, test := range frameReaders {
		t.Run(test.name, func(t *testing.T) {
			wire := goldenWire(t, test.name)
			for length := 0; length < len(wire); length++ {
				if err := test.read(bytes.NewReader(wire[:length])); err == nil {
					t.Fatalf("accepted frame truncated to %d of %d bytes", length, len(wire))
				}
			}
		})
	}
}

func goldenWire(t testing.TB, name string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimSpace(string(readFixture(t, name+".frame.hex"))))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A payload read is itself a failure: an EOF-only fixture would also pass if
// the size guard were deleted and the reader tried to consume the payload.
type headerOnlyReader struct {
	header       *bytes.Reader
	payloadReads int
}

func (r *headerOnlyReader) Read(p []byte) (int, error) {
	if r.header.Len() != 0 {
		return r.header.Read(p)
	}
	r.payloadReads++
	return 0, errors.New("unexpected payload read")
}

func TestFrameLengthBoundariesAndConsumption(t *testing.T) {
	for _, test := range frameReaders {
		t.Run(test.name, func(t *testing.T) {
			for _, size := range []int{0, test.limit + 1} {
				r := &headerOnlyReader{header: bytes.NewReader(binary.BigEndian.AppendUint32(nil, uint32(size)))}
				if err := test.read(r); err == nil || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || r.payloadReads != 0 {
					t.Fatalf("length %d: error %v, payload reads %d", size, err, r.payloadReads)
				}
			}
			wire := goldenWire(t, test.name)
			// JSON whitespace is legal and lets every public reader reach its exact limit.
			payload := append(bytes.Clone(wire[4:]), bytes.Repeat([]byte(" "), test.limit-len(wire)+4)...)
			atLimit := append(binary.BigEndian.AppendUint32(nil, uint32(test.limit)), payload...)
			r := bytes.NewReader(append(atLimit, []byte("next frame or visitor bytes")...))
			if err := test.read(r); err != nil {
				t.Fatalf("exact limit rejected: %v", err)
			}
			rest, _ := io.ReadAll(r)
			if string(rest) != "next frame or visitor bytes" {
				t.Fatalf("overconsumed: %q", rest)
			}
			for _, suffix := range []string{"{}", "null", "garbage"} {
				if err := test.read(frame(string(wire[4:]) + suffix)); err == nil {
					t.Fatalf("accepted trailing %q", suffix)
				}
			}
		})
	}
}

type failingWriter struct {
	call, failAt, consumed int
	failure                error
	short                  bool
}

func (w *failingWriter) Write(p []byte) (int, error) {
	w.call++
	if w.call == w.failAt {
		if w.short {
			w.consumed += len(p) - 1
			return len(p) - 1, nil
		}
		return 0, w.failure
	}
	w.consumed += len(p)
	return len(p), nil
}

func TestFrameWritersPropagateErrorsAndShortWrites(t *testing.T) {
	for _, test := range []struct {
		name  string
		write func(io.Writer) error
	}{
		{"control", func(w io.Writer) error {
			return WriteControl(w, Message{Type: HelloAccepted, ProtocolVersion: Version})
		}},
		{"publisher", func(w io.Writer) error {
			h, _ := ReadVisitorStreamHeader(bytes.NewReader(goldenWire(t, "visitor-stream-header")))
			return WriteVisitorStreamHeader(w, h)
		}},
		{"forwarding", func(w io.Writer) error {
			h, _ := ReadInternalForwardingHeader(bytes.NewReader(goldenWire(t, "internal-forwarding-header")))
			return WriteInternalForwardingHeader(w, h)
		}},
		{"response", func(w io.Writer) error { return WriteStreamResponse(w, StreamResponse{Type: StreamAccepted}) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			var complete bytes.Buffer
			if err := test.write(&complete); err != nil {
				t.Fatal(err)
			}
			for _, failAt := range []int{1, 2} {
				for _, short := range []bool{false, true} {
					failure := errors.New("writer failure")
					w := &failingWriter{failAt: failAt, failure: failure, short: short}
					want := failure
					if short {
						want = io.ErrShortWrite
					}
					if err := test.write(w); !errors.Is(err, want) || w.call != failAt {
						t.Fatalf("write %d short=%t: %v, calls %d", failAt, short, err, w.call)
					}
					if !short && w.consumed != (failAt-1)*4 {
						t.Fatalf("consumed %d bytes", w.consumed)
					}
					if short {
						wantConsumed := 3
						if failAt == 2 {
							wantConsumed = complete.Len() - 1
						}
						if w.consumed != wantConsumed {
							t.Fatalf("short writer consumed %d, want %d", w.consumed, wantConsumed)
						}
					}
				}
			}
		})
	}
}

func TestStreamWriterRejectsOversizeBeforeWriting(t *testing.T) {
	h, err := ReadInternalForwardingHeader(bytes.NewReader(goldenWire(t, "internal-forwarding-header")))
	if err != nil {
		t.Fatal(err)
	}
	h.RouteID, h.RouteSessionID, h.VisitorConnectionID = strings.Repeat("r", 256), strings.Repeat("s", 256), strings.Repeat("v", 256)
	if err := h.Validate(); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := WriteInternalForwardingHeader(&out, h); err == nil || out.Len() != 0 {
		t.Fatalf("oversized write: %v, %d bytes", err, out.Len())
	}
	publisher, err := ReadVisitorStreamHeader(bytes.NewReader(goldenWire(t, "visitor-stream-header")))
	if err != nil {
		t.Fatal(err)
	}
	publisher.RouteID, publisher.RouteSessionID, publisher.VisitorConnectionID, publisher.PublisherConnectionID = strings.Repeat("r", 256), strings.Repeat("s", 256), strings.Repeat("v", 256), strings.Repeat("p", 256)
	if err := publisher.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := WriteVisitorStreamHeader(&out, publisher); err == nil || out.Len() != 0 {
		t.Fatalf("oversized publisher write: %v, %d bytes", err, out.Len())
	}
}
