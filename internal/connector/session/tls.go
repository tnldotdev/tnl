package session

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/targettransport"
)

// StartTLS performs the protocol's visitor TLS negotiation on this exact admitted
// stream. MySQL callers supply their selected 32-byte SSLRequest packet after
// reading the server greeting; no login bytes may precede the verified handshake.
func (s *Conn) StartTLS(ctx context.Context, mysqlRequest []byte) (result error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	if s.closed || s.secure || s.upgrading {
		s.mu.Unlock()
		return errors.New("connector TLS requires an unupgraded stream")
	}
	s.upgrading = true
	raw := s.Conn
	s.mu.Unlock()
	setup, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	deadline, _ := setup.Deadline()
	if err := raw.SetDeadline(deadline); err != nil {
		return err
	}
	stopped := make(chan struct{})
	stop := context.AfterFunc(setup, func() { defer close(stopped); _ = s.raw.Close() })
	defer func() {
		if !stop() {
			<-stopped
		}
		if result != nil {
			_ = s.raw.Close()
		}
	}()
	switch s.owner.metadata.Protocol {
	case "postgres":
		if len(mysqlRequest) != 0 {
			return errors.New("unexpected MySQL SSLRequest")
		}
		if _, err := raw.Write(targettransport.PostgresSSLRequest[:]); err != nil {
			return err
		}
		var response [1]byte
		if _, err := io.ReadFull(raw, response[:]); err != nil {
			return err
		}
		if response[0] != 'S' {
			return errors.New("PostgreSQL visitor refused TLS")
		}
	case "mysql":
		if !s.mysqlRequested {
			if !validMySQLSSLRequest(mysqlRequest) {
				return errors.New("MySQL requires its SSLRequest before startTls")
			}
			if _, err := raw.Write(mysqlRequest); err != nil {
				return err
			}
		} else if len(mysqlRequest) != 0 {
			return errors.New("MySQL SSLRequest was already written")
		}
	case "http", "kubernetes":
		if len(mysqlRequest) != 0 {
			return errors.New("unexpected MySQL SSLRequest")
		}
	default:
		return errors.New("connector protocol has no application TLS upgrade")
	}
	trust := s.owner.trust.Clone()
	trust.MinVersion = max(trust.MinVersion, tls.VersionTLS12)
	if s.owner.metadata.Protocol == "http" || s.owner.metadata.Protocol == "kubernetes" {
		trust.NextProtos = []string{"http/1.1"}
	}
	secured := tls.Client(raw, trust)
	if err := secured.HandshakeContext(setup); err != nil {
		return err
	}
	if err := raw.SetDeadline(time.Time{}); err != nil {
		return err
	}
	if setup.Err() != nil {
		return context.Cause(setup)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return io.ErrClosedPipe
	}
	s.Conn, s.secure, s.upgrading = secured, true, false
	clear(s.mysqlRequest)
	s.mysqlRequest = nil
	return nil
}

func validMySQLSSLRequest(packet []byte) bool {
	if len(packet) != 36 || packet[0] != 32 || packet[1] != 0 || packet[2] != 0 || packet[3] != 1 {
		return false
	}
	flags := binary.LittleEndian.Uint32(packet[4:8])
	if flags&(targettransport.MySQLClientSSL|targettransport.MySQLClientProtocol41) != targettransport.MySQLClientSSL|targettransport.MySQLClientProtocol41 {
		return false
	}
	for _, b := range packet[13:] {
		if b != 0 {
			return false
		}
	}
	return true
}
