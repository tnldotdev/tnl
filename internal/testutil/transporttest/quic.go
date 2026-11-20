package transporttest

import (
	"testing"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
)

// QUICTransport opens one fixture-owned IPv4 loopback socket. a dual-stack
// wildcard can reuse an IPv4 listener's port on macOS and receive no replies.
// borrowed connections close independently; cleanup follows the worker joins.
func QUICTransport(t testing.TB) *muxsession.QUICTransport {
	t.Helper()
	transport, err := muxsession.ListenQUICTransport("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := transport.Close(); err != nil {
			t.Error(err)
		}
	})
	return transport
}
