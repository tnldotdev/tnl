package tnldruntime

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"

	"github.com/tnldotdev/tnl/internal/naming/tcpport"
)

// bind the entire declared inventory before registering an ingress lease. all
// sockets share admission, drain, and process capacity with the HTTPS listener.
func listenIngress(address string, ports []tcpport.Range, proxied bool) (net.Listener, error) {
	primary, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	if proxied || len(ports) == 0 {
		return primary, nil
	}
	host, primaryPort, err := net.SplitHostPort(primary.Addr().String())
	if err != nil {
		_ = primary.Close()
		return nil, err
	}
	listeners := []net.Listener{primary}
	for _, interval := range ports {
		for port := interval.First; port <= interval.Last; port++ {
			if strconv.Itoa(port) == primaryPort {
				err = errors.New("managed service port overlaps the infrastructure listener")
			} else {
				var listener net.Listener
				listener, err = net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
				if err == nil {
					listeners = append(listeners, listener)
				}
			}
			if err != nil {
				for _, listener := range listeners {
					_ = listener.Close()
				}
				return nil, fmt.Errorf("bind managed service port %d: %w", port, err)
			}
		}
	}
	return combineIngressListeners(listeners), nil
}

func combineIngressListeners(listeners []net.Listener) net.Listener {
	combined := &ingressListeners{listeners: listeners, accepted: make(chan acceptedIngress), closed: make(chan struct{})}
	for _, listener := range listeners {
		combined.workers.Go(func() {
			for {
				connection, err := listener.Accept()
				select {
				case combined.accepted <- acceptedIngress{connection, err}:
				case <-combined.closed:
					if connection != nil {
						_ = connection.Close()
					}
					return
				}
				if err != nil {
					return
				}
			}
		})
	}
	return combined
}

type acceptedIngress struct {
	connection net.Conn
	err        error
}
type ingressListeners struct {
	listeners []net.Listener
	accepted  chan acceptedIngress
	closed    chan struct{}
	once      sync.Once
	workers   sync.WaitGroup
}

func (l *ingressListeners) Accept() (net.Conn, error) {
	select {
	case result := <-l.accepted:
		return result.connection, result.err
	case <-l.closed:
		return nil, net.ErrClosed
	}
}
func (l *ingressListeners) Addr() net.Addr { return l.listeners[0].Addr() }
func (l *ingressListeners) Close() error {
	l.once.Do(func() {
		close(l.closed)
		for _, listener := range l.listeners {
			_ = listener.Close()
		}
		l.workers.Wait()
	})
	return nil
}
