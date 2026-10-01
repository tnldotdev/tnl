package publisher

import (
	"context"
	"net"
	"sync"

	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// the in-memory transport lets synctest run handshakes, certificate changes,
// acknowledgments, and heartbeats. Close stops and joins every pipe goroutine.
type certificateTestTransport struct {
	done    chan struct{}
	once    sync.Once
	mu      sync.Mutex
	streams []net.Conn
	workers sync.WaitGroup
}

func (s *certificateTestTransport) OpenStream(context.Context) (muxsession.Stream, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.done:
		return nil, muxsession.ErrClosed
	default:
	}
	local, remote := net.Pipe()
	s.streams = append(s.streams, local, remote)
	s.workers.Go(func() {
		defer remote.Close()
		hello, err := tunnelv1.ReadControl(remote)
		if err != nil || hello.Type != tunnelv1.Hello || hello.Role != tunnelv1.Publisher || hello.PublisherConnection == nil || hello.Credential == "" {
			return
		}
		if err := tunnelv1.WriteControl(remote, tunnelv1.Message{Type: tunnelv1.HelloAccepted, ProtocolVersion: tunnelv1.Version}); err != nil {
			return
		}
		request, err := tunnelv1.ReadControl(remote)
		if err != nil || request.Type != tunnelv1.Drain || request.RequestID == "" {
			return
		}
		if err := tunnelv1.WriteControl(remote, tunnelv1.Message{Type: tunnelv1.Draining, ProtocolVersion: tunnelv1.Version, RequestID: request.RequestID}); err != nil {
			return
		}
		if err := tunnelv1.WriteControl(remote, tunnelv1.Message{Type: tunnelv1.Drained, ProtocolVersion: tunnelv1.Version, RequestID: request.RequestID}); err != nil {
			return
		}
		<-s.done
	})
	return certificateTestStream{local}, nil
}

func (s *certificateTestTransport) AcceptStream(ctx context.Context) (muxsession.Stream, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.done:
		return nil, muxsession.ErrClosed
	}
}
func (s *certificateTestTransport) Close() error {
	s.once.Do(func() {
		s.mu.Lock()
		close(s.done)
		for _, stream := range s.streams {
			_ = stream.Close()
		}
		s.mu.Unlock()
		s.workers.Wait()
	})
	return nil
}
func (s *certificateTestTransport) Done() <-chan struct{} { return s.done }
func (s *certificateTestTransport) Err() error {
	select {
	case <-s.done:
		return muxsession.ErrClosed
	default:
		return nil
	}
}

type certificateTestStream struct{ net.Conn }

func (s certificateTestStream) CloseWrite() error  { return s.Close() }
func (s certificateTestStream) Reset(uint32) error { return s.Close() }
