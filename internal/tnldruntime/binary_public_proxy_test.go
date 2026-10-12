package tnldruntime

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/proxyproto"
)

// the fixture's public address carries the original destination port to one
// ingress listener, like a port-preserving external tcp load balancer.
func startIntegrationPublicProxy(t *testing.T, backend string, addresses ...string) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	var listeners []net.Listener
	var mu sync.Mutex
	connections := map[net.Conn]struct{}{}
	var workers sync.WaitGroup
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			cancel()
			for _, listener := range listeners {
				_ = listener.Close()
			}
			mu.Lock()
			active := len(connections)
			for connection := range connections {
				_ = connection.Close()
			}
			mu.Unlock()
			workers.Wait()
			if active != 0 {
				t.Logf("public proxy closed %d active TCP connections", active)
			}
		})
	}
	t.Cleanup(stop)
	track := func(connection net.Conn) func() {
		mu.Lock()
		connections[connection] = struct{}{}
		mu.Unlock()
		return func() {
			mu.Lock()
			delete(connections, connection)
			mu.Unlock()
			_ = connection.Close()
		}
	}
	for _, address := range addresses {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		listeners = append(listeners, listener)
		workers.Add(1)
		go func() {
			defer workers.Done()
			for {
				visitor, err := listener.Accept()
				if err != nil {
					return
				}
				workers.Add(1)
				go func() {
					defer workers.Done()
					closeVisitor := track(visitor)
					defer closeVisitor()
					backendCtx, stop := context.WithTimeout(ctx, 3*time.Second)
					upstream, err := (&net.Dialer{}).DialContext(backendCtx, "tcp", backend)
					stop()
					if err != nil {
						return
					}
					closeUpstream := track(upstream)
					defer closeUpstream()
					source := visitor.RemoteAddr().(*net.TCPAddr)
					destination := visitor.LocalAddr().(*net.TCPAddr)
					sourceIP, _ := netip.AddrFromSlice(source.IP)
					destinationIP, _ := netip.AddrFromSlice(destination.IP)
					header, err := proxyproto.Encode(proxyproto.Header{
						Source: netip.AddrPortFrom(sourceIP.Unmap(), uint16(source.Port)), Destination: netip.AddrPortFrom(destinationIP.Unmap(), uint16(destination.Port)),
					})
					if err != nil {
						return
					}
					if _, err := upstream.Write(header); err != nil {
						return
					}
					var copyBack sync.WaitGroup
					copyBack.Add(1)
					go func() {
						defer copyBack.Done()
						_, _ = io.Copy(visitor, upstream)
						_ = visitor.Close()
					}()
					_, _ = io.Copy(upstream, visitor)
					_ = upstream.Close()
					copyBack.Wait()
				}()
			}
		}()
	}
	return stop
}
