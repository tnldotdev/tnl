package connectionruntime

import (
	"errors"
	"net"
	"sync"
)

// ListenerSwitch keeps the loopback address while replacing only future
// accepts. an accepted connection is never replayed into another session.
type ListenerSwitch struct {
	net.Listener
	mu      sync.Mutex
	current *listenerGeneration
	done    chan struct{}
}

type listenerGeneration struct {
	owner       *ListenerSwitch
	connections chan net.Conn
	done        chan struct{}
	once        sync.Once
}

func NewListenerSwitch(listener net.Listener) *ListenerSwitch {
	s := &ListenerSwitch{Listener: listener, done: make(chan struct{})}
	go func() {
		defer close(s.done)
		for {
			c, err := listener.Accept()
			if err != nil {
				s.mu.Lock()
				if s.current != nil {
					_ = s.current.Close()
				}
				s.mu.Unlock()
				return
			}
			s.mu.Lock()
			g := s.current
			s.mu.Unlock()
			if g == nil {
				_ = c.Close()
				continue
			}
			select {
			case g.connections <- c:
			case <-g.done:
				_ = c.Close()
			}
		}
	}()
	return s
}

func (s *ListenerSwitch) Close() error {
	s.mu.Lock()
	if s.current != nil {
		_ = s.current.Close()
	}
	s.mu.Unlock()
	err := s.Listener.Close()
	<-s.done
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (s *ListenerSwitch) Next() net.Listener {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current != nil {
		_ = s.current.Close()
	}
	g := &listenerGeneration{owner: s, connections: make(chan net.Conn), done: make(chan struct{})}
	s.current = g
	return g
}

func (g *listenerGeneration) Accept() (net.Conn, error) {
	select {
	case c := <-g.connections:
		return c, nil
	case <-g.done:
		return nil, net.ErrClosed
	}
}
func (g *listenerGeneration) Close() error   { g.once.Do(func() { close(g.done) }); return nil }
func (g *listenerGeneration) Addr() net.Addr { return g.owner.Addr() }
