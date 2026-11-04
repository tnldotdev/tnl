package tunnel

import "testing"

func TestConnectorQUICPreservesApplicationAutotuningWithBoundedControlHeadroom(t *testing.T) {
	config := ConnectorQUICConfig()
	if config.InitialStreamReceiveWindow != 512<<10 || config.MaxStreamReceiveWindow != 6<<20 {
		t.Fatal("connector changed the pinned quic-go application-window defaults")
	}
	if config.MaxIncomingStreams != 65 || config.MaxIncomingUniStreams != -1 {
		t.Fatal("connector did not retain all 64 application streams plus control")
	}
	const unreadPayload = 65 * (6 << 20)
	if config.InitialConnectionReceiveWindow != 2*unreadPayload || config.MaxConnectionReceiveWindow != 2*unreadPayload {
		t.Fatal("connector aggregate headroom lost its explicit bound")
	}
	// pinned quic-go replenishes connection credit after 25% is consumed.
	// all stream maxima must fit even just before that update is generated.
	if config.InitialConnectionReceiveWindow*3/4 <= unreadPayload {
		t.Fatal("batched connection updates can withhold permission-control credit")
	}
}
