package router

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"testing"
)

func TestInspectClientHelloFromTLSClient(t *testing.T) {
	clientConnection, serverConnection := net.Pipe()
	t.Cleanup(func() {
		clientConnection.Close()
		serverConnection.Close()
	})
	done := make(chan error, 1)
	go func() {
		client := tls.Client(clientConnection, &tls.Config{
			ServerName: "demo.example",
			NextProtos: []string{"h2", "http/1.1"},
			MinVersion: tls.VersionTLS12,
		})
		done <- client.Handshake()
	}()

	result, err := InspectClientHello(serverConnection)
	if err != nil {
		t.Fatal(err)
	}
	if result.ServerName != "demo.example" {
		t.Fatalf("got SNI %q", result.ServerName)
	}
	if result.OffersACMETLSALPN {
		t.Fatal("unexpected ACME ALPN")
	}

	serverConnection.Close()
	clientConnection.Close()
	<-done
}

func TestInspectClientHelloFragmentsAndReplays(t *testing.T) {
	handshake := buildClientHello(
		sni("demo.example"),
		alpnExtension("h2", acmeTLSALPN),
	)
	input := append(tlsRecords(handshake, 2, 17), []byte("remaining TLS bytes")...)

	result, err := inspectClientHello(&shortReader{Reader: bytes.NewReader(input)})
	if err != nil {
		t.Fatal(err)
	}
	if result.ServerName != "demo.example" {
		t.Fatalf("got SNI %q", result.ServerName)
	}
	if !result.OffersACMETLSALPN {
		t.Fatal("ACME ALPN was not detected")
	}
	replayed, err := io.ReadAll(result.Replay)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(replayed, input) {
		t.Fatal("replayed bytes differ from input")
	}
}

func TestInspectClientHelloAllowsEightRecords(t *testing.T) {
	handshake := buildClientHello(
		sni("demo.example"),
	)
	input := tlsRecords(handshake, 1, 2, 3, 4, 5, 6, 7)
	if _, err := inspectClientHello(bytes.NewReader(input)); err != nil {
		t.Fatal(err)
	}
}

func TestInspectClientHelloRejectsInvalidInput(t *testing.T) {
	validSNI := sni("demo.example")
	tests := []struct {
		name  string
		input []byte
		code  ClientHelloErrorCode
	}{
		{
			name:  "missing SNI",
			input: tlsRecords(buildClientHello()),
			code:  ErrorMissingSNI,
		},
		{
			name:  "duplicate SNI extension",
			input: tlsRecords(buildClientHello(validSNI, validSNI)),
			code:  ErrorDuplicateSNI,
		},
		{
			name:  "multiple host names",
			input: tlsRecords(buildClientHello(sni("one.example", "two.example"))),
			code:  ErrorDuplicateSNI,
		},
		{
			name:  "ECH",
			input: tlsRecords(buildClientHello(validSNI, extension{kind: echExt})),
			code:  ErrorECHUnsupported,
		},
		{
			name:  "truncated record",
			input: []byte{handshakeRecord, 3, 1, 0, 10, 1},
			code:  ErrorMalformedClientHello,
		},
		{
			name:  "oversized record",
			input: []byte{handshakeRecord, 3, 1, 0x40, 0x01},
			code:  ErrorClientHelloTooLarge,
		},
		{
			name:  "unexpected record",
			input: []byte{23, 3, 3, 0, 0},
			code:  ErrorUnexpectedTLSRecord,
		},
		{
			name:  "too many records",
			input: repeatEmptyRecords(MaxClientHelloRecords),
			code:  ErrorTooManyTLSRecords,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := inspectClientHello(bytes.NewReader(test.input))
			clientHelloError, ok := err.(*ClientHelloError)
			if !ok {
				t.Fatalf("got error %v", err)
			}
			if clientHelloError.Code != test.code {
				t.Fatalf("got %s, want %s", clientHelloError.Code, test.code)
			}
		})
	}
}

func FuzzInspectClientHello(f *testing.F) {
	valid := tlsRecords(buildClientHello(
		sni("demo.example"),
	), 7)
	f.Add(valid)
	f.Add([]byte{})
	f.Add([]byte{handshakeRecord, 3, 1, 0xff, 0xff})

	f.Fuzz(func(t *testing.T, input []byte) {
		result, err := inspectClientHello(bytes.NewReader(input))
		if err != nil {
			return
		}
		replayed, err := io.ReadAll(result.Replay)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(replayed, input) {
			t.Fatal("replayed bytes differ from input")
		}
	})
}

type extension struct {
	kind uint16
	data []byte
}

type shortReader struct {
	io.Reader
}

func (r *shortReader) Read(buffer []byte) (int, error) {
	if len(buffer) > 1 {
		buffer = buffer[:1]
	}
	return r.Reader.Read(buffer)
}

func buildClientHello(extensions ...extension) []byte {
	body := []byte{3, 3}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)
	body = append(body, 0, 2, 0x13, 0x01)
	body = append(body, 1, 0)

	var extensionBytes []byte
	for _, extension := range extensions {
		extensionBytes = appendUint16(extensionBytes, extension.kind)
		extensionBytes = appendVector16(extensionBytes, extension.data)
	}
	body = appendVector16(body, extensionBytes)

	handshake := []byte{clientHelloType, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(handshake, body...)
}

func sni(names ...string) extension {
	return extension{kind: serverNameExt, data: serverNames(names...)}
}

func serverNames(names ...string) []byte {
	var entries []byte
	for _, name := range names {
		entries = append(entries, 0)
		entries = appendVector16(entries, []byte(name))
	}
	return appendVector16(nil, entries)
}

func alpnExtension(protocols ...string) extension {
	var entries []byte
	for _, protocol := range protocols {
		entries = append(entries, byte(len(protocol)))
		entries = append(entries, protocol...)
	}
	return extension{kind: alpnExt, data: appendVector16(nil, entries)}
}

func tlsRecords(handshake []byte, cuts ...int) []byte {
	var records []byte
	start := 0
	for _, end := range cuts {
		records = appendTLSRecord(records, handshake[start:end])
		start = end
	}
	return appendTLSRecord(records, handshake[start:])
}

func appendTLSRecord(destination, payload []byte) []byte {
	destination = append(destination, handshakeRecord, 3, 1)
	destination = appendUint16(destination, uint16(len(payload)))
	return append(destination, payload...)
}

func appendVector16(destination, value []byte) []byte {
	destination = appendUint16(destination, uint16(len(value)))
	return append(destination, value...)
}

func appendUint16(destination []byte, value uint16) []byte {
	return binary.BigEndian.AppendUint16(destination, value)
}

func repeatEmptyRecords(count int) []byte {
	var records []byte
	for range count {
		records = appendTLSRecord(records, nil)
	}
	return records
}
