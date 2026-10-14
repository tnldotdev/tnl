// package remoteprobe checks one public URL from the caller's network path.
package remoteprobe

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/clientruntime"
)

type Selection struct {
	Address, Protocol, Path string
	HTTPTransport           http.RoundTripper
	TLSRoots                *x509.CertPool
}

type Result struct {
	Address     string    `json:"address"`
	Protocol    string    `json:"protocol"`
	CheckedAt   time.Time `json:"checked_at"`
	Reachable   bool      `json:"reachable"`
	TLSVerified bool      `json:"tls_verified,omitempty"`
	HTTPStatus  int       `json:"http_status,omitempty"`
	Reason      string    `json:"reason,omitempty"`
}

func (s Selection) Validate() error {
	if s.Protocol == "" && strings.HasPrefix(s.Address, "https://") {
		s.Protocol = "http"
	}
	if s.Protocol == "http" {
		origin, err := url.Parse(s.Address)
		if err != nil || origin.Scheme != "https" || origin.Hostname() == "" || origin.User != nil ||
			origin.Opaque != "" || origin.RawQuery != "" || origin.ForceQuery || origin.Fragment != "" ||
			origin.Path != "" && origin.Path != "/" || origin.RawPath != "" ||
			(s.Path != "" && (!strings.HasPrefix(s.Path, "/") || strings.HasPrefix(s.Path, "//") || strings.Contains(s.Path, "#"))) {
			return errors.New("pass an HTTPS origin and an optional absolute --path")
		}
		if port := origin.Port(); port != "" {
			value, err := strconv.Atoi(port)
			if err != nil || value < 1 || value > 65535 {
				return errors.New("public HTTPS port must be between 1 and 65535")
			}
		}
		return nil
	}
	if s.Path != "" || s.Protocol != "ssh" && s.Protocol != "postgres" && s.Protocol != "mysql" && s.Protocol != "redis" {
		return errors.New("pass --protocol ssh, postgres, mysql, or redis for a public TCP address")
	}
	host, port, err := net.SplitHostPort(s.Address)
	if err != nil || host == "" {
		return errors.New("pass a public TCP hostname:port")
	}
	value, err := strconv.Atoi(port)
	if err != nil || value < 1 || value > 65535 {
		return errors.New("public TCP port must be between 1 and 65535")
	}
	return nil
}

func Probe(ctx context.Context, selected Selection) (Result, error) {
	if err := selected.Validate(); err != nil {
		return Result{}, err
	}
	if selected.Protocol == "" {
		selected.Protocol = "http"
	}
	result := Result{Address: selected.Address, Protocol: selected.Protocol, CheckedAt: time.Now().UTC()}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if selected.Protocol != "http" {
		err := probeTCP(ctx, selected.Address, selected.Protocol, selected.TLSRoots)
		if ctx.Err() == context.Canceled {
			return Result{}, ctx.Err()
		}
		if err != nil {
			result.Reason = probeFailure(err)
			return result, nil
		}
		result.Reachable = true
		result.TLSVerified = selected.Protocol != "ssh"
		return result, nil
	}
	path := selected.Path
	if path == "" {
		path = "/"
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(selected.Address, "/")+path, nil)
	if err != nil {
		return Result{}, err
	}
	request.Header.Set("User-Agent", "tnl-remote-probe/1")
	transport := selected.HTTPTransport
	if transport == nil {
		// a proxy can have a different source IP and therefore a different visitor policy.
		direct := http.DefaultTransport.(*http.Transport).Clone()
		direct.Proxy = nil
		defer direct.CloseIdleConnections()
		transport = direct
	}
	client := &http.Client{Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		if ctx.Err() == context.Canceled {
			return Result{}, ctx.Err()
		}
		result.Reason = probeFailure(err)
		return result, nil
	}
	defer response.Body.Close()
	result.HTTPStatus = response.StatusCode
	result.TLSVerified = true
	if response.Header.Get(clientruntime.DiagnosticHeader) != "" {
		result.Reason = "remote.denied"
		return result, nil
	}
	result.Reachable = true
	return result, nil
}

func probeFailure(err error) string {
	var certificate *tls.CertificateVerificationError
	var unknownAuthority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalidCertificate x509.CertificateInvalidError
	if errors.As(err, &certificate) || errors.As(err, &unknownAuthority) ||
		errors.As(err, &hostname) || errors.As(err, &invalidCertificate) {
		return "remote.tls_failed"
	}
	return "remote.no_response"
}

var postgresSSLRequest = [8]byte{0, 0, 0, 8, 4, 210, 22, 47}

func probeTCP(ctx context.Context, address, protocol string, roots *x509.CertPool) error {
	host, _, _ := net.SplitHostPort(address)
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return err
	}
	defer connection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		if err := connection.SetDeadline(deadline); err != nil {
			return err
		}
	}
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	verifyTLS := func() error {
		return tls.Client(connection, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host, RootCAs: roots}).HandshakeContext(ctx)
	}
	switch protocol {
	case "postgres":
		if _, err := connection.Write(postgresSSLRequest[:]); err != nil {
			return err
		}
		var answer [1]byte
		if _, err := io.ReadFull(connection, answer[:]); err != nil {
			return err
		}
		if answer[0] != 'S' {
			return errors.New("public PostgreSQL endpoint did not accept TLS")
		}
		return verifyTLS()
	case "mysql":
		var header [4]byte
		if _, err := io.ReadFull(connection, header[:]); err != nil {
			return err
		}
		length := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
		if length < 2 || length > 64<<10 || header[3] != 0 {
			return errors.New("public MySQL endpoint sent an invalid greeting")
		}
		greeting := make([]byte, length)
		if _, err := io.ReadFull(connection, greeting); err != nil {
			return err
		}
		if greeting[0] != 10 {
			return errors.New("public MySQL endpoint sent an invalid protocol version")
		}
		// SSLRequest is the only visitor packet sent. authentication never starts.
		var sslRequest [36]byte
		sslRequest[0], sslRequest[3] = 32, 1
		binary.LittleEndian.PutUint32(sslRequest[4:8], 1<<11|1<<9)
		sslRequest[12] = 45
		if _, err := connection.Write(sslRequest[:]); err != nil {
			return err
		}
		return verifyTLS()
	case "redis":
		return verifyTLS()
	case "ssh":
		reader := bufio.NewReader(io.LimitReader(connection, 4<<10))
		for range 5 {
			line, err := reader.ReadBytes('\n')
			if err != nil {
				return err
			}
			if bytes.HasPrefix(line, []byte("SSH-2.0-")) && len(line) <= 255 && bytes.HasSuffix(line, []byte("\r\n")) {
				return nil
			}
		}
		return errors.New("public SSH endpoint did not send a protocol banner")
	}
	return errors.New("unsupported public TCP protocol")
}
