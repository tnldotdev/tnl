package relay

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/pion/stun/v4"
)

type stunObservations chan string

func (o stunObservations) ObserveSTUNBinding(result string) { o <- result }

func TestSTUNBindingOnlyAnswersDiscoveryRequests(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		_ = server.Close()
		t.Fatal(err)
	}
	defer client.Close()
	observed := make(stunObservations, 10)
	done := make(chan error, 1)
	go func() { done <- ServeSTUN(ctx, server, observed) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	badFingerprint := stun.MustBuild(stun.TransactionID, stun.BindingRequest, stun.Fingerprint)
	badFingerprint.Raw[len(badFingerprint.Raw)-1] ^= 1
	for _, packet := range [][]byte{
		[]byte("not STUN"), make([]byte, 513), badFingerprint.Raw,
		stun.MustBuild(stun.TransactionID, stun.BindingRequest, stun.NewUsername("private-ice-credentials")).Raw,
		stun.MustBuild(stun.TransactionID, stun.BindingSuccess).Raw,
	} {
		if _, err := client.WriteTo(packet, server.LocalAddr()); err != nil {
			t.Fatal(err)
		}
		select {
		case result := <-observed:
			if result != "invalid" {
				t.Fatal("non-discovery packet answered", result)
			}
		case <-time.After(time.Second):
			t.Fatal("request was not classified")
		}
	}
	request := stun.MustBuild(stun.TransactionID, stun.BindingRequest, stun.Fingerprint)
	if _, err := client.WriteTo(request.Raw, server.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	var buffer [512]byte
	n, _, err := client.ReadFrom(buffer[:])
	if err != nil {
		t.Fatal(err)
	}
	response := &stun.Message{Raw: buffer[:n]}
	if err := response.Decode(); err != nil {
		t.Fatal(err)
	}
	if response.Type != stun.BindingSuccess || response.TransactionID != request.TransactionID || stun.Fingerprint.Check(response) != nil {
		t.Fatal("incorrect binding response")
	}
	var mapped stun.XORMappedAddress
	if err := mapped.GetFrom(response); err != nil {
		t.Fatal(err)
	}
	if mapped.Port != client.LocalAddr().(*net.UDPAddr).Port || !mapped.IP.Equal(client.LocalAddr().(*net.UDPAddr).IP) {
		t.Fatal("response did not observe the actual source socket")
	}
	if result := <-observed; result != "accepted" {
		t.Fatal(result)
	}
}

type failedSTUNReader struct {
	net.PacketConn
	cause error
}

func (c failedSTUNReader) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, c.cause }
func (c failedSTUNReader) Close() error                           { return nil }

func TestSTUNReadFailureRetainsCause(t *testing.T) {
	cause := errors.New("private socket failure detail")
	if err := ServeSTUN(t.Context(), failedSTUNReader{cause: cause}, nil); !errors.Is(err, cause) {
		t.Fatal("read failure lost its cause", err)
	}
}
