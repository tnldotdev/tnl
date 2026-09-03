package proxyproto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestIPv4WireFormatAndReplay(t *testing.T) {
	header := Header{
		Source:      netip.MustParseAddrPort("192.0.2.1:12345"),
		Destination: netip.MustParseAddrPort("198.51.100.2:443"),
	}
	expected := append([]byte(v2Signature),
		0x21, 0x11, 0x00, 0x0c,
		192, 0, 2, 1,
		198, 51, 100, 2,
		0x30, 0x39, 0x01, 0xbb,
	)

	encoded, err := Encode(header)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, expected) {
		t.Fatalf("got %x, want %x", encoded, expected)
	}

	payload := []byte("TLS bytes")
	decoded, replay, err := Decode(bytes.NewReader(append(encoded, payload...)))
	if err != nil {
		t.Fatal(err)
	}
	if decoded != header {
		t.Fatalf("got %+v, want %+v", decoded, header)
	}
	assertReplay(t, replay, payload)
}

func TestIPv6RoundTrip(t *testing.T) {
	header := Header{
		Source:      netip.MustParseAddrPort("[2001:db8::1]:12345"),
		Destination: netip.MustParseAddrPort("[2001:db8::2]:443"),
	}
	encoded, err := Encode(header)
	if err != nil {
		t.Fatal(err)
	}
	decoded, replay, err := Decode(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if decoded != header {
		t.Fatalf("got %+v, want %+v", decoded, header)
	}
	assertReplay(t, replay, nil)
}

func TestDecodeAllowsTLVsAndReplaysPayload(t *testing.T) {
	tests := []Header{
		{
			Source:      netip.MustParseAddrPort("192.0.2.1:12345"),
			Destination: netip.MustParseAddrPort("198.51.100.2:443"),
		},
		{
			Source:      netip.MustParseAddrPort("[2001:db8::1]:12345"),
			Destination: netip.MustParseAddrPort("[2001:db8::2]:443"),
		},
	}
	// A registered ALPN TLV followed by an application-specific TLV.
	tlvs := []byte{0x01, 0x00, 0x02, 'h', '2', 0xee, 0x00, 0x01, 0xff}
	for _, want := range tests {
		encoded, err := Encode(want)
		if err != nil {
			t.Fatal(err)
		}
		input := appendTLVs(encoded, tlvs)
		payload := []byte("TLS bytes")
		input = append(input, payload...)

		got, replay, err := Decode(bytes.NewReader(input))
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("got %+v, want %+v", got, want)
		}
		assertReplay(t, replay, payload)
	}
}

func TestDecodeRejectsMalformedAndOversizedTLVs(t *testing.T) {
	valid, err := Encode(Header{
		Source:      netip.MustParseAddrPort("192.0.2.1:12345"),
		Destination: netip.MustParseAddrPort("198.51.100.2:443"),
	})
	if err != nil {
		t.Fatal(err)
	}
	malformed := appendTLVs(valid, []byte{0x01, 0x00, 0x02, 'h'})
	oversized := bytes.Clone(valid)
	binary.BigEndian.PutUint16(oversized[14:16], maxV2Length+1)
	for name, input := range map[string][]byte{"malformed": malformed, "oversized": oversized} {
		t.Run(name, func(t *testing.T) {
			_, _, err := Decode(bytes.NewReader(input))
			var protocolError *ProtocolError
			if !errors.As(err, &protocolError) || protocolError.Code != ErrorInvalidLength {
				t.Fatalf("got error %v, want %s", err, ErrorInvalidLength)
			}
		})
	}
}

func TestDecodeRejectsUnsupportedHeaders(t *testing.T) {
	valid, err := Encode(Header{
		Source:      netip.MustParseAddrPort("192.0.2.1:12345"),
		Destination: netip.MustParseAddrPort("198.51.100.2:443"),
	})
	if err != nil {
		t.Fatal(err)
	}
	mapped, err := Encode(Header{
		Source:      netip.MustParseAddrPort("[2001:db8::1]:12345"),
		Destination: netip.MustParseAddrPort("[2001:db8::2]:443"),
	})
	if err != nil {
		t.Fatal(err)
	}
	mappedSource := netip.MustParseAddr("::ffff:192.0.2.1").As16()
	mappedDestination := netip.MustParseAddr("::ffff:198.51.100.2").As16()
	copy(mapped[16:32], mappedSource[:])
	copy(mapped[32:48], mappedDestination[:])

	tests := []struct {
		name  string
		input []byte
		code  ErrorCode
	}{
		{name: "v1", input: []byte("PROXY TCP4 192.0.2.1 198.51.100.2 12345 443\r\n"), code: ErrorInvalidSignature},
		{name: "LOCAL", input: changed(valid, 12, 0x20), code: ErrorUnsupportedCommand},
		{name: "datagram", input: changed(valid, 13, 0x12), code: ErrorUnsupportedTransport},
		{name: "unspecified family", input: changed(valid, 13, 0x01), code: ErrorUnsupportedTransport},
		{name: "truncated payload", input: changed(valid, 15, 0x0d), code: ErrorInvalidLength},
		{name: "truncated", input: valid[:20], code: ErrorTruncatedHeader},
		{name: "zero source port", input: changed(changed(valid, 24, 0), 25, 0), code: ErrorInvalidAddress},
		{name: "mapped IPv6 address", input: mapped, code: ErrorInvalidAddress},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := Decode(bytes.NewReader(test.input))
			protocolError, ok := err.(*ProtocolError)
			if !ok {
				t.Fatalf("got error %v", err)
			}
			if protocolError.Code != test.code {
				t.Fatalf("got %s, want %s", protocolError.Code, test.code)
			}
		})
	}
}

func TestDecodeReturnsBeforePayload(t *testing.T) {
	encoded, err := Encode(Header{
		Source:      netip.MustParseAddrPort("192.0.2.1:12345"),
		Destination: netip.MustParseAddrPort("198.51.100.2:443"),
	})
	if err != nil {
		t.Fatal(err)
	}
	server, client := net.Pipe()
	t.Cleanup(func() {
		server.Close()
		client.Close()
	})
	if err := server.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	go client.Write(encoded)

	if _, _, err := Decode(server); err != nil {
		t.Fatal(err)
	}
}

func TestReplayRejectsDuplicateHeader(t *testing.T) {
	encoded, err := Encode(Header{
		Source:      netip.MustParseAddrPort("192.0.2.1:12345"),
		Destination: netip.MustParseAddrPort("198.51.100.2:443"),
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, duplicate := range [][]byte{
		encoded,
		[]byte("PROXY TCP4 192.0.2.1 198.51.100.2 12345 443\r\n"),
	} {
		_, replay, err := Decode(bytes.NewReader(append(bytes.Clone(encoded), duplicate...)))
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.ReadAll(replay)
		protocolError, ok := err.(*ProtocolError)
		if !ok || protocolError.Code != ErrorDuplicateHeader {
			t.Fatalf("got error %v, want %s", err, ErrorDuplicateHeader)
		}
	}
}

func FuzzDecode(f *testing.F) {
	for _, header := range []Header{
		{
			Source:      netip.MustParseAddrPort("192.0.2.1:12345"),
			Destination: netip.MustParseAddrPort("198.51.100.2:443"),
		},
		{
			Source:      netip.MustParseAddrPort("[2001:db8::1]:12345"),
			Destination: netip.MustParseAddrPort("[2001:db8::2]:443"),
		},
	} {
		encoded, _ := Encode(header)
		f.Add(append(encoded, "TLS bytes"...))
		f.Add(append(bytes.Clone(encoded), encoded...))
	}
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, input []byte) {
		header, replay, err := Decode(bytes.NewReader(input))
		if err != nil {
			return
		}
		encoded, err := Encode(header)
		if err != nil {
			t.Fatal(err)
		}
		roundTrip, _, err := Decode(bytes.NewReader(encoded))
		if err != nil || roundTrip != header {
			t.Fatalf("decoded header changed during encoding: got %+v, %v", roundTrip, err)
		}
		headerLength := 16 + int(binary.BigEndian.Uint16(input[14:16]))
		payload := input[headerLength:]
		duplicate := bytes.HasPrefix(payload, []byte(v1Signature)) || bytes.HasPrefix(payload, []byte(v2Signature))
		remaining, err := io.ReadAll(replay)
		if err != nil {
			var protocolError *ProtocolError
			if !duplicate || !errors.As(err, &protocolError) || protocolError.Code != ErrorDuplicateHeader {
				t.Fatal(err)
			}
			return
		}
		if duplicate {
			t.Fatal("duplicate header was replayed")
		}
		if !bytes.Equal(remaining, payload) {
			t.Fatal("replayed bytes differ from input")
		}
	})
}

func appendTLVs(header, tlvs []byte) []byte {
	result := append(bytes.Clone(header), tlvs...)
	length := int(binary.BigEndian.Uint16(result[14:16])) + len(tlvs)
	binary.BigEndian.PutUint16(result[14:16], uint16(length))
	return result
}

func changed(input []byte, index int, value byte) []byte {
	output := bytes.Clone(input)
	output[index] = value
	return output
}

func assertReplay(t *testing.T, replay io.Reader, expected []byte) {
	t.Helper()
	actual, err := io.ReadAll(replay)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, expected) {
		t.Fatalf("got replay %x, want %x", actual, expected)
	}
}
