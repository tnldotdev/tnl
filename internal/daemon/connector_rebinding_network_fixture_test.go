package daemon

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type rebindingDatagram struct {
	data    []byte
	address net.Addr
	err     error
}

// both sockets carry real UDP packets. changing source models a network switch
// beneath a live QUIC transport; it does not close or relabel that transport.
type rebindingPacketConn struct {
	sockets [2]*net.UDPConn
	source  *atomic.Uint32
	packets chan rebindingDatagram
	done    chan struct{}
	readers sync.WaitGroup
	once    sync.Once
	err     error
}

func newRebindingPacketConn(source *atomic.Uint32) (*rebindingPacketConn, error) {
	p := &rebindingPacketConn{source: source, packets: make(chan rebindingDatagram, 64), done: make(chan struct{})}
	for index := range p.sockets {
		socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, byte(index+1))})
		if err != nil {
			return nil, errors.Join(err, p.Close())
		}
		p.sockets[index] = socket
		p.readers.Go(func() {
			for {
				buffer := make([]byte, 65536)
				n, address, err := socket.ReadFrom(buffer)
				select {
				case p.packets <- rebindingDatagram{data: buffer[:n], address: address, err: err}:
				case <-p.done:
					return
				}
				if err != nil {
					return
				}
			}
		})
	}
	return p, nil
}

func (p *rebindingPacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	select {
	case packet := <-p.packets:
		return copy(buffer, packet.data), packet.address, packet.err
	case <-p.done:
		return 0, nil, net.ErrClosed
	}
}

func (p *rebindingPacketConn) WriteTo(buffer []byte, address net.Addr) (int, error) {
	return p.sockets[p.source.Load()-1].WriteTo(buffer, address)
}

func (p *rebindingPacketConn) LocalAddr() net.Addr { return p.sockets[p.source.Load()-1].LocalAddr() }
func (p *rebindingPacketConn) SetReadDeadline(until time.Time) error {
	return errors.Join(p.sockets[0].SetReadDeadline(until), p.sockets[1].SetReadDeadline(until))
}
func (p *rebindingPacketConn) SetWriteDeadline(until time.Time) error {
	return errors.Join(p.sockets[0].SetWriteDeadline(until), p.sockets[1].SetWriteDeadline(until))
}
func (p *rebindingPacketConn) SetDeadline(until time.Time) error {
	return errors.Join(p.SetReadDeadline(until), p.SetWriteDeadline(until))
}
func (p *rebindingPacketConn) Close() error {
	p.once.Do(func() {
		close(p.done)
		for _, socket := range p.sockets {
			if socket != nil {
				p.err = errors.Join(p.err, socket.Close())
			}
		}
		p.readers.Wait()
	})
	return p.err
}
