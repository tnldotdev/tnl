package ingress

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
)

// service-level proxy checks arrive without a PROXY header. recognize only a
// bounded, bodyless readiness GET from an explicitly trusted proxy peer before
// decoding metadata. a proxied visitor can never enter this health-check path.
func (s *Server) readinessProbe(connection net.Conn) (bool, net.Conn) {
	if !s.config.RequireProxyHeader || s.config.CheckReady == nil || !proxyproto.Trusted(connection.RemoteAddr(), s.config.TrustedProxyPeers) {
		return false, connection
	}
	reader := bufio.NewReader(connection)
	first, err := reader.Peek(1)
	if err != nil || first[0] != 'G' {
		return false, &readerConn{Conn: connection, reader: reader}
	}
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	request, err := http.ReadRequest(bufio.NewReader(io.LimitReader(reader, 4096)))
	if err != nil {
		return true, connection
	}
	defer request.Body.Close()
	if request.Method != http.MethodGet || request.RequestURI != "/ready" || request.ContentLength != 0 || len(request.TransferEncoding) != 0 || request.Header.Get("Upgrade") != "" {
		_, _ = io.WriteString(connection, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return true, connection
	}
	status := "503 Service Unavailable"
	if s.config.CheckReady() {
		status = "204 No Content"
	}
	_, _ = io.WriteString(connection, "HTTP/1.1 "+status+"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
	return true, connection
}
