package relay

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"net"

	"golang.org/x/time/rate"
)

const (
	stunCookie       = 0x2112a442
	stunFingerprint  = 0x5354554e
	stunRequestLimit = 512
)

type STUNObserver interface{ ObserveSTUNBinding(string) }

// ServeSTUN answers bounded, username-less Binding Requests on the relay's
// existing UDP socket. discovered mappings are hints, never source authority.
// requests must be padded to at least the response size (40/52 bytes for IPv4/6)
// so the unauthenticated responder cannot amplify traffic.
func ServeSTUN(ctx context.Context, packets net.PacketConn, observer STUNObserver) error {
	defer packets.Close()
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = packets.Close()
		close(closed)
	})
	defer func() {
		if !stop() {
			<-closed
		}
	}()
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
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read STUN binding request: %w", err)
		}
		if !limiter.Allow() {
			observe("capacity")
			continue
		}
		address, ok := source.(*net.UDPAddr)
		if !ok {
			if reply, carriesMetadata := source.(interface{ UDPAddr() *net.UDPAddr }); carriesMetadata {
				address = reply.UDPAddr()
			}
		}
		response := stunBindingResponse(buffer[:n], address)
		if response == nil {
			observe("invalid")
			continue
		}
		// pass the original address back unchanged: source-pinned listeners attach
		// the received local-IP/interface metadata to this packet's reply address.
		if _, err := packets.WriteTo(response, source); err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			observe("transport_error")
			continue
		}
		observe("accepted")
	}
}

func stunBindingResponse(request []byte, source *net.UDPAddr) []byte {
	if len(request) < 20 || len(request) > stunRequestLimit || len(request)%4 != 0 ||
		binary.BigEndian.Uint16(request) != 0x0001 || binary.BigEndian.Uint32(request[4:]) != stunCookie ||
		int(binary.BigEndian.Uint16(request[2:])) != len(request)-20 || source == nil || source.Zone != "" || source.Port < 1 || source.Port > 65535 {
		return nil
	}
	ip, family := source.IP.To4(), byte(1)
	if ip == nil {
		ip, family = source.IP.To16(), 2
	}
	if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
		return nil
	}
	for at := 20; at < len(request); {
		if at+4 > len(request) {
			return nil
		}
		kind, length := binary.BigEndian.Uint16(request[at:]), int(binary.BigEndian.Uint16(request[at+2:]))
		next := at + 4 + (length+3)&^3
		if next > len(request) {
			return nil
		}
		switch kind {
		case 0x0026, 0x8022: // padding and software are discovery-only attributes.
		case 0x8028:
			if length != 4 || next != len(request) || binary.BigEndian.Uint32(request[at+4:]) != crc32.ChecksumIEEE(request[:at])^stunFingerprint {
				return nil
			}
		default:
			// no usernames, integrity credentials, ICE checks, or other methods.
			return nil
		}
		at = next
	}
	response := make([]byte, 28+len(ip)+8)
	if len(response) > len(request) {
		return nil
	}
	binary.BigEndian.PutUint16(response, 0x0101)
	binary.BigEndian.PutUint16(response[2:], uint16(len(response)-20))
	copy(response[4:20], request[4:20])
	binary.BigEndian.PutUint16(response[20:], 0x0020) // XOR-MAPPED-ADDRESS.
	binary.BigEndian.PutUint16(response[22:], uint16(4+len(ip)))
	response[25] = family
	binary.BigEndian.PutUint16(response[26:], uint16(source.Port)^uint16(stunCookie>>16))
	for i := range ip {
		response[28+i] = ip[i] ^ request[4+i]
	}
	at := len(response) - 8
	binary.BigEndian.PutUint16(response[at:], 0x8028)
	binary.BigEndian.PutUint16(response[at+2:], 4)
	binary.BigEndian.PutUint32(response[at+4:], crc32.ChecksumIEEE(response[:at])^stunFingerprint)
	return response
}
