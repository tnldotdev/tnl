package tunnel

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type interruptedNativeConn struct {
	net.Conn
	wire              []byte
	offset, interrupt int
	reported          bool
}

func (c *interruptedNativeConn) Read(p []byte) (int, error) {
	if c.offset == c.interrupt && !c.reported {
		c.reported = true
		return 0, os.ErrDeadlineExceeded
	}
	if c.offset == len(c.wire) {
		return 0, io.EOF
	}
	end := len(c.wire)
	if !c.reported {
		end = min(end, c.interrupt)
	}
	n := copy(p, c.wire[c.offset:end])
	c.offset += n
	return n, nil
}

func TestNativeRequestDeadlineInterruptionResumesPartialHeaderAndPayload(t *testing.T) {
	var wire bytes.Buffer
	if err := tunnelv1.WriteNativeRequestFrame(&wire, tunnelv1.NativeRequestFrame{Kind: tunnelv1.NativeRequestData, Data: []byte("visitor TLS bytes")}); err != nil {
		t.Fatal(err)
	}
	renewal := wire.Len()
	if err := tunnelv1.WriteNativeRequestFrame(&wire, tunnelv1.NativeRequestFrame{Kind: tunnelv1.NativeRequestPermission, Permission: nativeRequestPermissionFixture()}); err != nil {
		t.Fatal(err)
	}
	if err := tunnelv1.WriteNativeRequestFrame(&wire, tunnelv1.NativeRequestFrame{Kind: tunnelv1.NativeRequestEnded}); err != nil {
		t.Fatal(err)
	}
	for _, offset := range []int{0, 1, 4, 5, 8, renewal + 1, renewal + 4, renewal + 5, renewal + 20} {
		conn := &interruptedNativeConn{wire: wire.Bytes(), interrupt: offset}
		renewed := 0
		reader := NewNativeRequestReader(conn, nil, func(tunnelv1.NativeVisitorPermission) error { renewed++; return nil })
		var data bytes.Buffer
		var buffer [64]byte
		for {
			n, err := reader.Read(buffer[:])
			data.Write(buffer[:n])
			if errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			}
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatalf("interrupted at %d: %v", offset, err)
			}
		}
		if data.String() != "visitor TLS bytes" || renewed != 1 || !conn.reported {
			t.Fatalf("deadline at %d lost bytes or renewal: data=%q renewed=%d", offset, data.String(), renewed)
		}
	}
}

func nativeRequestPermissionFixture() tunnelv1.NativeVisitorPermission {
	return tunnelv1.NativeVisitorPermission{Token: "signed-visitor-token", PublicKey: strings.Repeat("A", 43), Signature: strings.Repeat("A", 86)}
}

func TestNativeRequestRenewalNeverEntersVisitorTLSBytes(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	writer := NewNativeRequestWriter(client)
	permission := nativeRequestPermissionFixture()
	renewed := false
	reader := NewNativeRequestReader(server, []byte("initial TLS record"), func(got tunnelv1.NativeVisitorPermission) error {
		if got != permission {
			return errors.New("renewal proof changed")
		}
		renewed = true
		return nil
	})
	done := make(chan error, 1)
	go func() {
		if _, err := writer.Write(bytes.Repeat([]byte{0x16}, tunnelv1.MaxInitialBytes+7)); err != nil {
			done <- err
			return
		}
		if err := writer.Renew(permission); err != nil {
			done <- err
			return
		}
		if _, err := writer.Write([]byte("following TLS record")); err != nil {
			done <- err
			return
		}
		done <- writer.CloseWrite()
	}()
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte("initial TLS record"), bytes.Repeat([]byte{0x16}, tunnelv1.MaxInitialBytes+7)...)
	want = append(want, []byte("following TLS record")...)
	if !renewed || !bytes.Equal(got, want) {
		t.Fatal("native renewal leaked into, changed, or reordered visitor bytes")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := writer.Renew(permission); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("ended native stream accepted a renewal", err)
	}
}

func TestNativeRequestRejectedRenewalStopsBeforeFollowingData(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	denied := errors.New("permission revoked")
	reader := NewNativeRequestReader(server, nil, func(tunnelv1.NativeVisitorPermission) error { return denied })
	done := make(chan error, 1)
	go func() { done <- NewNativeRequestWriter(client).Renew(nativeRequestPermissionFixture()) }()
	if n, err := reader.Read(make([]byte, 32)); n != 0 || !errors.Is(err, denied) {
		t.Fatal("rejected renewal became application data", n, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if n, err := reader.Read(make([]byte, 32)); n != 0 || !errors.Is(err, denied) {
		t.Fatal("native stream resumed after rejected renewal", n, err)
	}
}
