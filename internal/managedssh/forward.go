package managedssh

import (
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

func (s *Server) serveForward(ctx context.Context, conn *ssh.ServerConn, incoming ssh.NewChannel) {
	var target struct {
		Host       string
		Port       uint32
		OriginHost string
		OriginPort uint32
	}
	if len(incoming.ExtraData()) > 4096 || ssh.Unmarshal(incoming.ExtraData(), &target) != nil || target.Host == "" || len(target.Host) > 253 || strings.ContainsAny(target.Host, "\x00\r\n\t /\\") || target.Port == 0 || target.Port > 65535 {
		_ = incoming.Reject(ssh.Prohibited, "invalid forwarding target")
		return
	}
	// the runner drops privileges before resolving or dialing the destination.
	backend, err := s.runner.Dial(ctx, conn.User(), net.JoinHostPort(target.Host, strconv.Itoa(int(target.Port))))
	if err != nil {
		_ = incoming.Reject(ssh.ConnectionFailed, "forwarding target is unavailable")
		return
	}
	defer backend.Close()
	channel, requests, err := incoming.Accept()
	if err != nil {
		return
	}
	defer channel.Close()
	var workers sync.WaitGroup
	workers.Go(func() {
		for request := range requests {
			_ = request.Reply(false, nil)
		}
	})
	copied := make(chan error, 2)
	go func() {
		_, err := io.Copy(backend, channel)
		if half, ok := backend.(interface{ CloseWrite() error }); ok {
			_ = half.CloseWrite()
		}
		copied <- err
	}()
	go func() {
		_, err := io.Copy(channel, backend)
		_ = channel.CloseWrite()
		copied <- err
	}()
	closed := context.AfterFunc(ctx, func() { _ = channel.Close(); _ = backend.Close() })
	defer closed()
	for range 2 {
		if err := <-copied; err != nil {
			_ = channel.Close()
			_ = backend.Close()
		}
	}
	_ = channel.Close()
	_ = backend.Close()
	workers.Wait()
}
