package tunnel

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type interruptedConnectorConn struct {
	net.Conn
	wire              []byte
	offset, interrupt int
	reported          bool
}

func (*interruptedConnectorConn) Close() error { return nil }

func (c *interruptedConnectorConn) Read(p []byte) (int, error) {
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

func TestConnectorRequestDeadlineInterruptionResumesPartialHeaderAndPayload(t *testing.T) {
	var wire bytes.Buffer
	if err := tunnelv1.WriteConnectorRequestFrame(&wire, tunnelv1.ConnectorRequestFrame{Kind: tunnelv1.ConnectorRequestData, Data: []byte("visitor TLS bytes")}); err != nil {
		t.Fatal(err)
	}
	renewal := wire.Len()
	if err := tunnelv1.WriteConnectorRequestFrame(&wire, tunnelv1.ConnectorRequestFrame{Kind: tunnelv1.ConnectorRequestPermission, Permission: connectorRequestPermissionFixture()}); err != nil {
		t.Fatal(err)
	}
	if err := tunnelv1.WriteConnectorRequestFrame(&wire, tunnelv1.ConnectorRequestFrame{Kind: tunnelv1.ConnectorRequestEnded}); err != nil {
		t.Fatal(err)
	}
	for _, offset := range []int{0, 1, 4, 5, 8, renewal + 1, renewal + 4, renewal + 5, renewal + 20} {
		conn := &interruptedConnectorConn{wire: wire.Bytes(), interrupt: offset}
		renewed := 0
		reader := NewConnectorRequestReader(conn, nil, func(tunnelv1.ConnectorVisitorPermission) error { renewed++; return nil })
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

func TestConnectorRequestReaderSerializesConcurrentReads(t *testing.T) {
	var wire bytes.Buffer
	const count = 64
	for range count {
		if err := tunnelv1.WriteConnectorRequestFrame(&wire, tunnelv1.ConnectorRequestFrame{Kind: tunnelv1.ConnectorRequestData, Data: []byte{'x'}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := tunnelv1.WriteConnectorRequestFrame(&wire, tunnelv1.ConnectorRequestFrame{Kind: tunnelv1.ConnectorRequestEnded}); err != nil {
		t.Fatal(err)
	}
	reader := NewConnectorRequestReader(&interruptedConnectorConn{wire: wire.Bytes(), interrupt: wire.Len() + 1}, nil, nil)
	var workers sync.WaitGroup
	counts := make(chan int, 8)
	for range 8 {
		workers.Go(func() {
			var count int
			var b [1]byte
			for {
				n, err := reader.Read(b[:])
				if n > 0 && b[0] != 'x' {
					t.Error("native framing leaked into visitor bytes")
				}
				count += n
				if err == io.EOF {
					counts <- count
					return
				}
				if err != nil {
					t.Error(err)
					return
				}
			}
		})
	}
	workers.Wait()
	close(counts)
	var read int
	for n := range counts {
		read += n
	}
	if read != count {
		t.Fatalf("concurrent readers received %d of %d visitor bytes", read, count)
	}
}

func connectorRequestPermissionFixture() tunnelv1.ConnectorVisitorPermission {
	return tunnelv1.ConnectorVisitorPermission{Token: "signed-visitor-token", PublicKey: strings.Repeat("A", 43), Signature: strings.Repeat("A", 86)}
}

type connectorDeadlineConn struct {
	net.Conn
	deadlines chan time.Time
	writes    chan struct{}
}

func (c *connectorDeadlineConn) Write(p []byte) (int, error) {
	c.writes <- struct{}{}
	return c.Conn.Write(p)
}

func (c *connectorDeadlineConn) SetWriteDeadline(at time.Time) error {
	c.deadlines <- at
	return c.Conn.SetWriteDeadline(at)
}

func TestConnectorRequestRenewalDeadlineDoesNotInterruptApplicationWrite(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	tracked := &connectorDeadlineConn{Conn: client, deadlines: make(chan time.Time, 4), writes: make(chan struct{}, 8)}
	writer := NewConnectorRequestWriter(tracked)
	written := make(chan error, 1)
	go func() { _, err := writer.Write([]byte("application")); written <- err }()
	<-tracked.writes // the application's framed write owns the writer gate.
	until := time.Now().Add(time.Second)
	renewed := make(chan error, 1)
	go func() { renewed <- writer.RenewUntil(connectorRequestPermissionFixture(), until) }()
	select {
	case <-tracked.deadlines:
		t.Fatal("renewal changed an entered application write's deadline")
	case <-time.After(20 * time.Millisecond):
	}
	frame, err := tunnelv1.ReadConnectorRequestFrame(server)
	if err != nil || string(frame.Data) != "application" {
		t.Fatal("application write was interrupted", err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	frame, err = tunnelv1.ReadConnectorRequestFrame(server)
	if err != nil || frame.Kind != tunnelv1.ConnectorRequestPermission {
		t.Fatal("renewal lost its frame", err)
	}
	if err := <-renewed; err != nil {
		t.Fatal(err)
	}
	if at := <-tracked.deadlines; !at.Equal(until) {
		t.Fatal("renewal reset its original deadline")
	}
	if at := <-tracked.deadlines; !at.IsZero() {
		t.Fatal("renewal left its deadline on application writes")
	}
}

func TestConnectorRequestRenewalCannotResetExpiredBudget(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	tracked := &connectorDeadlineConn{Conn: client, deadlines: make(chan time.Time, 4), writes: make(chan struct{}, 8)}
	writer := NewConnectorRequestWriter(tracked)
	written := make(chan error, 1)
	go func() { _, err := writer.Write([]byte("application")); written <- err }()
	<-tracked.writes
	renewed := make(chan error, 1)
	until := time.Now().Add(20 * time.Millisecond)
	go func() { renewed <- writer.RenewUntil(connectorRequestPermissionFixture(), until) }()
	select {
	case err := <-renewed:
		if !errors.Is(err, os.ErrDeadlineExceeded) || len(tracked.deadlines) != 0 {
			t.Fatal("waiting renewal reset its expired budget", err)
		}
	case <-time.After(time.Second):
		t.Fatal("renewal waited for the application write beyond its budget")
	}
	if _, err := tunnelv1.ReadConnectorRequestFrame(server); err != nil {
		t.Fatal(err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
}

func TestConnectorOpeningCarriesBoundedInitialDataWithoutReturnAcceptance(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	_ = client.SetDeadline(time.Now().Add(time.Second))
	_ = server.SetDeadline(time.Now().Add(time.Second))
	entry := tunnelv1.ConnectorPeerVisitorEntry{ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.ConnectorPeerVisitorStream,
		PairID: "cpp_aaaaaaaaaaaaaaaaaaaaaa", DeliveryID: "AQEBAQEBAQEBAQEBAQEBAQ", DeliveryGeneration: 1,
		ServiceID: "svc_aaaaaaaaaaaaaaaaaaaaaa", ServiceRunID: "srun_aaaaaaaaaaaaaaaaaaaaaa", RunNumber: 1,
		Subject:  tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, IdentityID: "ident_aaaaaaaaaaaaaaaaaaaaaa", DeviceID: "vdev_aaaaaaaaaaaaaaaaaaaaaa"},
		SourceIP: "192.0.2.1", VisitorConnectionID: "vc_aaaaaaaaaaaaaaaaaaaaaa", MetadataRevision: 1, Permission: connectorRequestPermissionFixture()}
	data := bytes.Repeat([]byte{0x16}, tunnelv1.MaxInitialBytes+7)
	done := make(chan error, 1)
	go func() {
		writer := NewConnectorOpeningWriter(client, func(initial []byte) error {
			_, err := tunnelv1.WriteConnectorPeerVisitorOpening(client, entry, initial)
			return err
		})
		if n, err := writer.Write(data); err != nil || n != len(data) {
			done <- errors.Join(err, io.ErrShortWrite)
			return
		}
		if err := writer.Renew(connectorRequestPermissionFixture()); err != nil {
			done <- err
			return
		}
		done <- writer.CloseWrite()
	}()
	gotEntry, initial, err := tunnelv1.ReadConnectorPeerVisitorOpening(server)
	if err != nil || gotEntry.VisitorConnectionID != entry.VisitorConnectionID || len(initial) != tunnelv1.MaxInitialBytes {
		t.Fatal("connector opening lost its binding or initial-data bound", err)
	}
	var renewals int
	reader := NewConnectorRequestReader(server, initial, func(tunnelv1.ConnectorVisitorPermission) error { renewals++; return nil })
	got, err := io.ReadAll(reader)
	if err != nil || !bytes.Equal(got, data) || renewals != 1 {
		t.Fatal("connector opening duplicated, changed, or reordered request bytes", err)
	}
	if err := <-done; err != nil {
		t.Fatal("connector request waited for return acceptance", err)
	}
}

func TestConnectorOpeningFailureCannotReplayOnDataRenewalOrClose(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	failed := errors.New("ambiguous opening write")
	var attempts int
	writer := NewConnectorOpeningWriter(client, func([]byte) error { attempts++; return failed })
	if _, err := writer.Write([]byte("initial visitor bytes")); !errors.Is(err, failed) {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("following bytes")); !errors.Is(err, failed) {
		t.Fatal("failed opening resumed request data", err)
	}
	if err := writer.Renew(connectorRequestPermissionFixture()); !errors.Is(err, failed) {
		t.Fatal("failed opening resumed permission renewal", err)
	}
	if err := writer.CloseWrite(); !errors.Is(err, failed) || attempts != 1 {
		t.Fatal("failed opening was replayed during cleanup", attempts, err)
	}
}

func TestConnectorRequestRenewalNeverEntersVisitorTLSBytes(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	writer := NewConnectorRequestWriter(client)
	permission := connectorRequestPermissionFixture()
	renewed := false
	reader := NewConnectorRequestReader(server, []byte("initial TLS record"), func(got tunnelv1.ConnectorVisitorPermission) error {
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
		t.Fatal("connector renewal leaked into, changed, or reordered visitor bytes")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestConnectorHalfCloseKeepsPermissionAndResponseDirections(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	permission := connectorRequestPermissionFixture()
	renewed := make(chan struct{}, 1)
	reader := NewConnectorRequestReader(server, nil, func(got tunnelv1.ConnectorVisitorPermission) error {
		if got != permission {
			return errors.New("half-close changed the renewal proof")
		}
		renewed <- struct{}{}
		return nil
	})
	writer := NewConnectorRequestWriter(client)
	finished := make(chan error, 1)
	go func() {
		if _, err := writer.Write([]byte("request")); err != nil {
			finished <- err
			return
		}
		if err := writer.CloseWrite(); err != nil {
			finished <- err
			return
		}
		finished <- writer.Renew(permission)
	}()
	request, err := io.ReadAll(reader)
	if err != nil || string(request) != "request" {
		t.Fatalf("half-closed application request = %q: %v", request, err)
	}
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	select {
	case <-renewed:
	case <-time.After(time.Second):
		t.Fatal("renewal stopped with the application request direction")
	}
	go func() { _, _ = server.Write([]byte("response")) }()
	var response [8]byte
	if _, err := io.ReadFull(client, response[:]); err != nil || string(response[:]) != "response" {
		t.Fatalf("half-close truncated the response: %q: %v", response, err)
	}
}

func TestConnectorHalfCloseRejectsRevokedRenewal(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	denied := make(chan struct{})
	reader := NewConnectorRequestReader(server, nil, func(tunnelv1.ConnectorVisitorPermission) error {
		close(denied)
		return errors.New("visitor permission revoked")
	})
	writer := NewConnectorRequestWriter(client)
	finished := make(chan error, 1)
	go func() {
		if err := writer.CloseWrite(); err != nil {
			finished <- err
			return
		}
		finished <- writer.Renew(connectorRequestPermissionFixture())
	}()
	if _, err := reader.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatal("half-close did not end application input", err)
	}
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	select {
	case <-denied:
	case <-time.After(time.Second):
		t.Fatal("revoked permission was not checked after the application half-close")
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatal("revoked permission left the response direction open", err)
	}
}

func TestConnectorRequestRejectedRenewalStopsBeforeFollowingData(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	denied := errors.New("permission revoked")
	reader := NewConnectorRequestReader(server, nil, func(tunnelv1.ConnectorVisitorPermission) error { return denied })
	done := make(chan error, 1)
	go func() { done <- NewConnectorRequestWriter(client).Renew(connectorRequestPermissionFixture()) }()
	if n, err := reader.Read(make([]byte, 32)); n != 0 || !errors.Is(err, denied) {
		t.Fatal("rejected renewal became application data", n, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if n, err := reader.Read(make([]byte, 32)); n != 0 || !errors.Is(err, denied) {
		t.Fatal("connector stream resumed after rejected renewal", n, err)
	}
}

func TestConnectorResponseOnlyRequestConsumesRenewalDespiteApplicationDeadline(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	renewed := make(chan struct{}, 1)
	reader := NewConnectorRequestReader(server, []byte("request"), func(tunnelv1.ConnectorVisitorPermission) error { renewed <- struct{}{}; return nil })
	defer reader.Finish()
	var request [7]byte
	if _, err := io.ReadFull(reader, request[:]); err != nil || string(request[:]) != "request" {
		t.Fatal(err)
	}
	if err := reader.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	// a handler can be writing only a response while net/http's background
	// application read is interrupted. neither condition can stop the frame owner.
	done := make(chan error, 1)
	go func() { done <- NewConnectorRequestWriter(client).Renew(connectorRequestPermissionFixture()) }()
	select {
	case <-renewed:
	case <-time.After(time.Second):
		t.Fatal("idle application stopped permission renewal")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Read(request[:]); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("application deadline was reset by renewal", err)
	}
	if err := reader.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	go func() { done <- NewConnectorRequestWriter(client).CloseWrite() }()
	if _, err := reader.Read(request[:]); !errors.Is(err, io.EOF) {
		t.Fatal("cleared deadline poisoned request framing", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestConnectorRequestReadAheadIsBoundedAndFinishJoinsBackpressure(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	reader := NewConnectorRequestReader(server, []byte("initial"), nil)
	defer reader.Finish()
	if _, err := reader.Read(make([]byte, 7)); err != nil {
		t.Fatal(err)
	}
	completed := make(chan error, 3)
	go func() {
		writer := NewConnectorRequestWriter(client)
		for range 3 {
			_, err := writer.Write([]byte("bounded data"))
			completed <- err
			if err != nil {
				return
			}
		}
	}()
	for range 2 {
		select {
		case err := <-completed:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("bounded read-ahead did not accept its two frames")
		}
	}
	select {
	case err := <-completed:
		t.Fatal("reader exceeded its two-frame queue/decode bound", err)
	case <-time.After(20 * time.Millisecond):
	}
	if err := reader.Finish(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-completed:
		if err == nil {
			t.Fatal("closed reader resumed read-ahead")
		}
	case <-time.After(time.Second):
		t.Fatal("finish left the backpressured writer blocked")
	}
}
