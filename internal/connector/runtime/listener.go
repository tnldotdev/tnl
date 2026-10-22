package runtime

import (
	"errors"
	"net"
	"sync"
)

// ListenerSwitch keeps the loopback address while replacing only future
// accepts. an accepted connection is never replayed into another session.
type ListenerSwitch struct {
	listener  net.Listener
	mu        sync.Mutex
	current   *listenerGeneration
	done      chan struct{}
	closed    bool
	closeOnce sync.Once
	closeErr  error
}

type listenerGeneration struct {
	owner       *ListenerSwitch
	connections chan net.Conn
	done        chan struct{}
	once        sync.Once
}

func NewListenerSwitch(listener net.Listener) *ListenerSwitch {
	s := &ListenerSwitch{listener: listener, done: make(chan struct{})}
	go func() {
		defer close(s.done)
		for {
			c, err := listener.Accept()
			if err != nil {
				s.mu.Lock()
				s.closed = true
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
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		if s.current != nil {
			_ = s.current.Close()
		}
		s.mu.Unlock()
		s.closeErr = s.listener.Close()
		<-s.done
		if errors.Is(s.closeErr, net.ErrClosed) {
			s.closeErr = nil
		}
	})
	return s.closeErr
}

func (s *ListenerSwitch) Addr() net.Addr { return s.listener.Addr() }

func (s *ListenerSwitch) Next() net.Listener {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current != nil {
		_ = s.current.Close()
	}
	g := &listenerGeneration{owner: s, connections: make(chan net.Conn), done: make(chan struct{})}
	if s.closed {
		_ = g.Close()
		return g
	}
	s.current = g
	return g
}

func (g *listenerGeneration) Accept() (net.Conn, error) {
	select {
	case <-g.done:
		return nil, net.ErrClosed
	default:
	}
	select {
	case c := <-g.connections:
		select {
		case <-g.done:
			_ = c.Close()
			return nil, net.ErrClosed
		default:
		}
		return c, nil
	case <-g.done:
		return nil, net.ErrClosed
	}
}
func (g *listenerGeneration) Close() error   { g.once.Do(func() { close(g.done) }); return nil }
func (g *listenerGeneration) Addr() net.Addr { return g.owner.Addr() }
