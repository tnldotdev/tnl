package tunnel

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type returnFrameReader struct {
	muxsession.Stream
	reader *bytes.Reader
	closed bool
}

func (s *returnFrameReader) Read(p []byte) (int, error) { return s.reader.Read(p) }
func (s *returnFrameReader) Close() error               { s.closed = true; return nil }

func TestReturnFramesRejectAmbiguousCompletionAndDecisionOrder(t *testing.T) {
	accepted := tunnelv1.ReturnFrame{Kind: tunnelv1.ReturnAccepted}
	data := tunnelv1.ReturnFrame{Kind: tunnelv1.ReturnData, Data: []byte("TLS")}
	promoted := tunnelv1.ReturnFrame{Kind: tunnelv1.ReturnPromoted, Promotion: decisionPromotion()}
	ended := tunnelv1.ReturnFrame{Kind: tunnelv1.ReturnEnded}
	for _, test := range []struct {
		name   string
		frames []tunnelv1.ReturnFrame
		want   error
		data   string
		calls  int
	}{
		{"missing acceptance", []tunnelv1.ReturnFrame{data}, tunnelv1.ErrReturnFrame, "", 0},
		{"promotion before acceptance", []tunnelv1.ReturnFrame{promoted}, tunnelv1.ErrReturnFrame, "", 0},
		{"end before acceptance", []tunnelv1.ReturnFrame{ended}, tunnelv1.ErrReturnFrame, "", 0},
		{"duplicate acceptance", []tunnelv1.ReturnFrame{accepted, accepted}, tunnelv1.ErrReturnFrame, "", 0},
		{"duplicate promotion", []tunnelv1.ReturnFrame{accepted, promoted, promoted, data}, tunnelv1.ErrReturnFrame, "", 1},
		{"bare EOF", []tunnelv1.ReturnFrame{accepted}, io.ErrUnexpectedEOF, "", 0},
		{"payload then bare EOF", []tunnelv1.ReturnFrame{accepted, data}, io.ErrUnexpectedEOF, "TLS", 0},
		{"explicit half-close", []tunnelv1.ReturnFrame{accepted, data, ended}, nil, "TLS", 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			var wire bytes.Buffer
			for _, frame := range test.frames {
				if err := tunnelv1.WriteReturnFrame(&wire, frame); err != nil {
					t.Fatal(err)
				}
			}
			underlying := &returnFrameReader{reader: bytes.NewReader(wire.Bytes())}
			calls := 0
			stream := &returnStream{Stream: underlying, events: ReturnEvents{Promoted: func(tunnelv1.AdmissionHeader) error { calls++; return nil }}}
			got, err := io.ReadAll(stream)
			if !errors.Is(err, test.want) || string(got) != test.data || calls != test.calls || underlying.closed != (test.want != nil) {
				t.Fatal("ambiguous completion or decision escaped", string(got), err, calls, underlying.closed)
			}
		})
	}
}

func TestReturnRejectionRetainsProtocolAndCallbackCauses(t *testing.T) {
	var wire bytes.Buffer
	for _, frame := range []tunnelv1.ReturnFrame{{Kind: tunnelv1.ReturnAccepted}, {Kind: tunnelv1.ReturnRejected, Code: tunnelv1.CapacityExceeded}, {Kind: tunnelv1.ReturnData, Data: []byte("forbidden")}} {
		if err := tunnelv1.WriteReturnFrame(&wire, frame); err != nil {
			t.Fatal(err)
		}
	}
	cause := errors.New("rejection forwarding failed")
	stream := &returnStream{Stream: &returnFrameReader{reader: bytes.NewReader(wire.Bytes())}, events: ReturnEvents{Rejected: func(code tunnelv1.ErrorCode) error {
		if code != tunnelv1.CapacityExceeded {
			t.Error("rejection code changed")
		}
		return cause
	}}}
	got, err := io.ReadAll(stream)
	var rejected *ProtocolError
	if len(got) != 0 || !errors.Is(err, cause) || !errors.As(err, &rejected) || rejected.Code != tunnelv1.CapacityExceeded {
		t.Fatal("rejection lost its causes or leaked data", err)
	}
}

type failedEndStream struct {
	muxsession.Stream
	written bytes.Buffer
	failure error
	ends    int
}

func (s *failedEndStream) Write(p []byte) (int, error)      { return s.written.Write(p) }
func (s *failedEndStream) SetWriteDeadline(time.Time) error { return nil }
func (s *failedEndStream) CloseWrite() error {
	s.ends++
	return s.failure
}

func TestReturnEndRetainsHalfCloseFailureWithoutReplay(t *testing.T) {
	cause := errors.New("half-close failed")
	wire := &failedEndStream{failure: cause}
	reply := &replyStream{Stream: wire, accepted: true}
	for range 2 {
		if err := reply.end(t.Context()); !errors.Is(err, cause) {
			t.Fatal("end lost its supported half-close cause", err)
		}
	}
	if wire.ends != 1 || wire.written.Len() != 5 {
		t.Fatal("failed end replayed the frame or physical half-close", wire.ends, wire.written.Len())
	}
}
