// Package workercontrol carries RouteWorker operations over bearer-authenticated WebSockets.
package workercontrol

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"time"

	yamux "github.com/libp2p/go-yamux/v5"
)

const (
	defaultMaxStreams        = 10_000
	defaultMaxSessions       = 10
	defaultMaxWorkerCapacity = 500
	defaultMaxTotalCapacity  = 5_000
	handshakeTimeout         = 10 * time.Second
	requestTimeout           = 30 * time.Second
)

// SessionRole is the stable endpoint role reported to session observers.
type SessionRole string

const (
	RoleEdge   SessionRole = "edge"
	RoleWorker SessionRole = "worker"
)

// DisconnectReason is the stable reason reported when an established session exits.
type DisconnectReason string

const (
	DisconnectShutdown DisconnectReason = "shutdown"
	DisconnectNetwork  DisconnectReason = "network"
	DisconnectProtocol DisconnectReason = "protocol"
	DisconnectTimeout  DisconnectReason = "timeout"
	DisconnectInternal DisconnectReason = "internal"
)

func disconnectReason(err error) DisconnectReason {
	if isTimeout(err) {
		return DisconnectTimeout
	}
	if isMuxProtocolError(err) {
		return DisconnectProtocol
	}
	if isTransportError(err) {
		return DisconnectNetwork
	}
	if err != nil {
		message := err.Error()
		if strings.HasPrefix(message, "workerv1:") ||
			strings.HasPrefix(message, "json:") ||
			strings.HasPrefix(message, "workercontrol: unexpected ") ||
			message == "workercontrol: response omitted route" {
			return DisconnectProtocol
		}
	}
	return DisconnectInternal
}

func isMuxProtocolError(err error) bool {
	return errors.Is(err, yamux.ErrInvalidVersion) ||
		errors.Is(err, yamux.ErrInvalidMsgType) ||
		errors.Is(err, yamux.ErrDuplicateStream) ||
		errors.Is(err, yamux.ErrRecvWindowExceeded) ||
		errors.Is(err, yamux.ErrUnexpectedFlag)
}

func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var networkError net.Error
	return errors.As(err, &networkError) && networkError.Timeout()
}

func isTransportError(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) ||
		errors.Is(err, yamux.ErrSessionShutdown) || errors.Is(err, yamux.ErrRemoteGoAway) ||
		errors.Is(err, yamux.ErrStreamClosed) || errors.Is(err, yamux.ErrStreamReset) {
		return true
	}
	var networkError net.Error
	return errors.As(err, &networkError)
}

func muxConfig(maxIncoming int) *yamux.Config {
	if maxIncoming <= 0 {
		maxIncoming = defaultMaxStreams
	}
	config := yamux.DefaultConfig()
	config.AcceptBacklog = min(maxIncoming, 256)
	config.MaxIncomingStreams = uint32(maxIncoming)
	config.InitialStreamWindowSize = 256 << 10
	config.MaxStreamWindowSize = 1 << 20
	config.MaxMessageSize = 64 << 10
	config.ConnectionWriteTimeout = 10 * time.Second
	config.KeepAliveInterval = 30 * time.Second
	config.LogOutput = io.Discard
	return config
}
