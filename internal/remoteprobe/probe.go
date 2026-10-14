// package remoteprobe checks one public URL from the caller's network path.
package remoteprobe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
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
}

type Result struct {
	Address    string    `json:"address"`
	Protocol   string    `json:"protocol"`
	CheckedAt  time.Time `json:"checked_at"`
	Reachable  bool      `json:"reachable"`
	HTTPStatus int       `json:"http_status,omitempty"`
	Reason     string    `json:"reason,omitempty"`
}

func (s Selection) Validate() error {
	if s.Protocol == "" && strings.HasPrefix(s.Address, "https://") {
		s.Protocol = "http"
	}
	if s.Protocol == "http" {
		origin, err := url.Parse(s.Address)
		if err != nil || origin.Scheme != "https" || origin.Hostname() == "" || origin.User != nil ||
			origin.RawQuery != "" || origin.Fragment != "" || origin.Path != "" && origin.Path != "/" ||
			(s.Path != "" && (!strings.HasPrefix(s.Path, "/") || strings.HasPrefix(s.Path, "//"))) {
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
	if s.Path != "" || s.Protocol != "ssh" && s.Protocol != "postgres" && s.Protocol != "mysql" && s.Protocol != "redis" && s.Protocol != "mongodb" {
		return errors.New("pass --protocol ssh, postgres, mysql, redis, or mongodb for a public TCP address")
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
		if err := clientruntime.ProbeTCP(ctx, selected.Address, selected.Protocol, nil); err != nil {
			if ctx.Err() == context.Canceled {
				return Result{}, ctx.Err()
			}
			result.Reason = "remote.no_response"
			return result, nil
		}
		result.Reachable = true
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
	client := &http.Client{Timeout: 5 * time.Second, Transport: selected.HTTPTransport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		if ctx.Err() == context.Canceled {
			return Result{}, ctx.Err()
		}
		var certificate *tls.CertificateVerificationError
		var unknownAuthority x509.UnknownAuthorityError
		var hostname x509.HostnameError
		var invalidCertificate x509.CertificateInvalidError
		if errors.As(err, &certificate) || errors.As(err, &unknownAuthority) ||
			errors.As(err, &hostname) || errors.As(err, &invalidCertificate) {
			result.Reason = "remote.tls_failed"
		} else {
			result.Reason = "remote.no_response"
		}
		return result, nil
	}
	defer response.Body.Close()
	result.HTTPStatus = response.StatusCode
	if response.Header.Get(clientruntime.DiagnosticHeader) != "" {
		result.Reason = "remote.denied"
		return result, nil
	}
	result.Reachable = true
	return result, nil
}
