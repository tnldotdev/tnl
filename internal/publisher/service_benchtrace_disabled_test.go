//go:build !tnl_benchtrace

package publisher

import (
	"net"
	"testing"
)

type disabledServiceBenchTraceAdmission struct{ ServiceConnectorAdmission }

func (disabledServiceBenchTraceAdmission) DiagnosticVisitorConnectionID() string {
	panic("normal builds must not inspect diagnostic admission metadata")
}

func TestServiceBenchTraceDisabledPreservesIdentityWithoutAllocation(t *testing.T) {
	client, target := net.Pipe()
	defer client.Close()
	defer target.Close()
	admission := disabledServiceBenchTraceAdmission{}
	if allocations := testing.AllocsPerRun(1000, func() {
		left, right := serviceBenchTraceCopy(admission, client, target)
		if left != client || right != target {
			t.Fatal("normal build changed the copy connections")
		}
	}); allocations != 0 {
		t.Fatalf("normal build allocated %g objects per copy", allocations)
	}
}
