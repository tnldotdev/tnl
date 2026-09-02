package sourceauth

import (
	"bytes"
	"io"
	"net"
	"net/netip"
	"testing"

	"github.com/tnldotdev/tnl/internal/proxyproto"
)

func TestSourceAuthenticationRoundTrip(t *testing.T) {
	for _, source := range []string{"192.0.2.10:1234", "[2001:db8::10]:1234"} {
		t.Run(source, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			key := [32]byte{1, 2, 3}
			header := testHeader(t, source)
			clientResult := make(chan error, 1)
			go func() { clientResult <- Client(client, key, PurposeApplication, header) }()
			claim, err := Server(server, key)
			if err != nil || claim.Purpose != PurposeApplication || claim.Header != header {
				t.Fatalf("claim = %#v, error = %v", claim, err)
			}
			if err := <-clientResult; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSourceAuthenticationRejectsWrongKey(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	clientResult := make(chan error, 1)
	go func() { clientResult <- Client(client, [32]byte{1}, PurposeACME, testHeader(t, "192.0.2.10:1234")) }()
	if _, err := Server(server, [32]byte{2}); err == nil {
		t.Fatal("wrong source authentication key accepted")
	}
	if err := <-clientResult; err != nil {
		t.Fatal(err)
	}
}

func TestSourceAuthenticationRejectsReplayedResponse(t *testing.T) {
	key := [32]byte{1, 2, 3}
	header := testHeader(t, "192.0.2.10:1234")
	client, server := net.Pipe()
	var captured bytes.Buffer
	clientResult := make(chan error, 1)
	go func() {
		clientResult <- Client(struct {
			io.Reader
			io.Writer
		}{Reader: client, Writer: io.MultiWriter(client, &captured)}, key, PurposeApplication, header)
	}()
	if _, err := Server(server, key); err != nil {
		t.Fatal(err)
	}
	if err := <-clientResult; err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	_ = server.Close()

	replay, verifier := net.Pipe()
	defer replay.Close()
	defer verifier.Close()
	go func() {
		challenge := make([]byte, len(requestMagic)+32)
		_, _ = io.ReadFull(replay, challenge)
		_, _ = replay.Write(captured.Bytes())
	}()
	if _, err := Server(verifier, key); err == nil {
		t.Fatal("replayed source authentication response accepted")
	}
}

func testHeader(t *testing.T, source string) proxyproto.Header {
	t.Helper()
	parsed, err := netip.ParseAddrPort(source)
	if err != nil {
		t.Fatal(err)
	}
	destination := netip.MustParseAddrPort("127.0.0.1:443")
	if parsed.Addr().Is6() {
		destination = netip.MustParseAddrPort("[2001:db8::20]:443")
	}
	return proxyproto.Header{Source: parsed, Destination: destination}
}
