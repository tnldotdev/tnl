package stream

import (
	"context"
	"io"
	"net"
	"runtime/trace"
	"testing"
)

type benchTraceAllocationConn struct{ net.Conn }

func (benchTraceAllocationConn) Read([]byte) (int, error)    { return 0, io.EOF }
func (benchTraceAllocationConn) Write(p []byte) (int, error) { return len(p), nil }

func TestConnectorBenchTraceUnarmedUseDoesNotAllocate(t *testing.T) {
	if trace.IsEnabled() {
		t.Fatal("allocation check requires tracing off")
	}
	ctx := context.Background()
	p := &PreparedConnector{ctx: ctx, conn: benchTraceAllocationConn{}}
	use := &preparedConnectorUse{owner: p, ctx: ctx}
	var buffer [1]byte
	allocations := testing.AllocsPerRun(100, func() {
		if n, err := use.Read(buffer[:]); n != 0 || err != io.EOF {
			t.Error("read result changed")
		}
		if n, err := use.Write(buffer[:]); n != 1 || err != nil {
			t.Error("write result changed")
		}
	})
	if allocations != 0 {
		t.Fatalf("unarmed read/write instrumentation allocated: %g", allocations)
	}
}
