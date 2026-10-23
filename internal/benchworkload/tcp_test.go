package benchworkload

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestTCPVisitorFreshAndReusedSockets(t *testing.T) {
	for _, reuse := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh", true: "reused"}[reuse], func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			var accepted atomic.Int64
			done := make(chan error, 1)
			go func() { done <- ServeTCPEcho(ctx, countedTCPListener{Listener: listener, accepted: &accepted}) }()
			t.Cleanup(func() {
				cancel()
				if err := <-done; err != nil {
					t.Error(err)
				}
			})
			visitor := &TCPVisitor{PayloadBytes: 256}
			t.Cleanup(func() { _ = visitor.Close() })
			address := listener.Addr().String()
			if reuse {
				setup, err := visitor.Prepare(ctx, []string{address}, 2)
				if err != nil || setup.Count != 2 {
					t.Fatalf("prepare: %+v, %v", setup, err)
				}
			}
			var rows []RequestResult
			for range 10 {
				row := visitor.request(ctx, address, time.Now())
				if row.Error != "" {
					t.Fatal(row.Error)
				}
				rows = append(rows, row)
			}
			want := int64(10)
			if reuse {
				want = 2
			}
			if accepted.Load() != want {
				t.Fatalf("accepted=%d want=%d", accepted.Load(), want)
			}
			for _, row := range rows {
				if row.Bytes != 260 || row.FirstByte.Before(row.Started) || row.Duration < row.QueueDelay || reuse && row.Connect != 0 {
					t.Fatalf("invalid response timing: %+v", row)
				}
			}
		})
	}
}

type countedTCPListener struct {
	net.Listener
	accepted *atomic.Int64
}

func (l countedTCPListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err == nil {
		l.accepted.Add(1)
	}
	return conn, err
}

func TestTCPVisitorRejectsCorruptionAndCanceledRead(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		t.Run(map[bool]string{false: "canceled", true: "corrupt"}[corrupt], func(t *testing.T) {
			client, server := net.Pipe()
			t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			done := make(chan struct{})
			go func() {
				defer close(done)
				var header [4]byte
				if _, err := io.ReadFull(server, header[:]); err != nil {
					return
				}
				frame := make([]byte, 4+int(binary.BigEndian.Uint32(header[:])))
				copy(frame, header[:])
				if _, err := io.ReadFull(server, frame[4:]); err != nil {
					return
				}
				if corrupt {
					frame[len(frame)-1] ^= 1
					_, _ = server.Write(frame)
				} else {
					cancel()
				}
			}()
			visitor := &TCPVisitor{PayloadBytes: 256}
			_, _, err := visitor.exchange(ctx, client)
			if err == nil {
				t.Fatal("unverified exchange succeeded")
			}
			<-done
		})
	}
}
