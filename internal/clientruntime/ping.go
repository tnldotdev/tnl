package clientruntime

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// PingResult records only what the invoking machine could verify as a visitor.
type PingResult struct {
	Address   string    `json:"address"`
	Protocol  string    `json:"protocol"`
	CheckedAt time.Time `json:"checked_at"`
	State     string    `json:"state"`
	Status    int       `json:"http_status,omitempty"`
	Code      string    `json:"tnl_error_code,omitempty"`
	Note      string    `json:"note,omitempty"`
}

func Ping(ctx context.Context, address, protocol string) PingResult {
	return pingWithTransport(ctx, address, protocol, nil)
}

// pingWithTransport permits an HTTP transport to be supplied by local tests.
func pingWithTransport(ctx context.Context, address, protocol string, transport http.RoundTripper) PingResult {
	result := PingResult{Address: address, Protocol: protocol, CheckedAt: time.Now().UTC(), State: "unavailable"}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if protocol == "http" || protocol == "https" {
		parsed, err := url.Parse(address)
		if err != nil || parsed.Scheme != protocol || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" || parsed.Opaque != "" {
			result.State = "invalid address"
			return result
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
		if err != nil {
			result.State = "invalid address"
			return result
		}
		request.Header.Set("User-Agent", "tnl-ping/1")
		if transport == nil {
			// a visitor probe measures this machine, not an environment proxy.
			direct := http.DefaultTransport.(*http.Transport).Clone()
			direct.Proxy = nil
			transport = direct
		}
		client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		response, err := client.Do(request)
		if err != nil {
			result.Note = "connection or TLS verification failed"
			return result
		}
		defer response.Body.Close()
		result.Status = response.StatusCode
		result.Code = response.Header.Get(DiagnosticHeader)
		switch {
		case result.Code != "":
			result.State = "tnl denied"
		case response.StatusCode >= 200 && response.StatusCode < 300:
			result.State = "responding"
		case response.StatusCode >= 300 && response.StatusCode < 400:
			result.State = "redirected (not followed)"
		default:
			result.State = "app responded"
		}
		return result
	}
	if protocol != "postgres" && protocol != "mysql" && protocol != "redis" && protocol != "ssh" {
		result.State = "invalid protocol"
		return result
	}
	if _, _, err := net.SplitHostPort(address); err != nil {
		result.State = "invalid address"
		return result
	}
	return pingTCP(ctx, result, nil)
}

func pingTCP(ctx context.Context, result PingResult, trust *tls.Config) PingResult {
	address, protocol := result.Address, result.Protocol
	if protocol == "redis" {
		// a redis visitor probe does not send PING, credentials, or any other command.
		host, _, _ := net.SplitHostPort(address)
		config := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
		if trust != nil {
			config = trust.Clone()
			config.ServerName = host
			config.MinVersion = tls.VersionTLS12
		}
		if config.InsecureSkipVerify {
			result.Note = "verified TLS is required"
			return result
		}
		conn, err := (&tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: config}).DialContext(ctx, "tcp", address)
		if err != nil {
			result.Note = "connection or TLS verification failed"
			return result
		}
		_ = conn.Close()
	} else if err := CheckPublicTCP(ctx, TCPProbeOptions{Address: address, Protocol: protocol}); err != nil {
		result.Note = "connection, protocol, or TLS verification failed"
		return result
	}
	result.State = "responding"
	if protocol == "redis" {
		result.State = "tls verified"
		result.Note = "visitor TLS verified; Redis was not contacted"
	} else if protocol == "ssh" {
		result.Note = "SSH banner received; host key not verified"
	} else {
		result.Note = "TLS verified; no login attempted"
	}
	return result
}

func PingAddress(value, protocol string) (string, string, error) {
	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err != nil || parsed.User != nil || parsed.Fragment != "" || parsed.Hostname() == "" || parsed.Opaque != "" {
			return "", "", errors.New("invalid public URL")
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return "", "", errors.New("use --protocol for TCP host:port")
		}
		if protocol != "" && protocol != parsed.Scheme {
			return "", "", errors.New("protocol does not match URL scheme")
		}
		return value, parsed.Scheme, nil
	}
	if protocol == "" {
		return "", "", errors.New("host:port needs --protocol postgres, mysql, redis, or ssh")
	}
	if protocol != "postgres" && protocol != "mysql" && protocol != "redis" && protocol != "ssh" {
		return "", "", errors.New("host:port needs a TCP protocol")
	}
	if _, _, err := net.SplitHostPort(value); err != nil {
		return "", "", errors.New("expected host:port")
	}
	return value, protocol, nil
}
