package relay

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/pion/stun/v4"
	"golang.org/x/time/rate"
)

type STUNObserver interface{ ObserveSTUNBinding(string) }

// ServeSTUN answers bounded discovery requests on the non-QUIC view of the
// relay's existing UDP socket. mappings are hints, never source authority.
func ServeSTUN(ctx context.Context, packets net.PacketConn, observer STUNObserver) error {
	defer packets.Close()
	stop := context.AfterFunc(ctx, func() { _ = packets.Close() })
	defer stop()
	limiter := rate.NewLimiter(500, 100)
	observe := func(result string) {
		if observer != nil {
			observer.ObserveSTUNBinding(result)
		}
	}
	var buffer [2048]byte
	for {
		n, source, err := packets.ReadFrom(buffer[:])
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("read STUN binding request: %w", err)
		}
		if n > 512 || !stun.IsMessage(buffer[:n]) {
			observe("invalid")
			continue
		}
		request := &stun.Message{Raw: buffer[:n]}
		udp, ok := source.(*net.UDPAddr)
		if !ok || udp == nil || request.Decode() != nil || request.Type != stun.BindingRequest || request.Contains(stun.AttrUsername) || request.Contains(stun.AttrFingerprint) && stun.Fingerprint.Check(request) != nil {
			observe("invalid")
			continue
		}
		if !limiter.Allow() {
			observe("capacity")
			continue
		}
		response, err := stun.Build(stun.NewTransactionIDSetter(request.TransactionID), stun.BindingSuccess, &stun.XORMappedAddress{IP: udp.IP, Port: udp.Port}, stun.Fingerprint)
		if err != nil {
			return fmt.Errorf("encode STUN binding response: %w", err)
		}
		if _, err := packets.WriteTo(response.Raw, source); err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			observe("transport_error")
			continue
		}
		observe("accepted")
	}
}
