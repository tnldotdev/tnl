package app

import (
	"context"
	"errors"
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
	result.State = "invalid protocol"
	return result
}

func PingAddress(value, protocol string) (string, string, error) {
	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err != nil || parsed.User != nil || parsed.Fragment != "" || parsed.Hostname() == "" || parsed.Opaque != "" {
			return "", "", errors.New("invalid public URL")
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return "", "", errors.New("expected an HTTP or HTTPS public URL")
		}
		if protocol != "" && protocol != "http" && protocol != parsed.Scheme {
			return "", "", errors.New("protocol does not match URL scheme")
		}
		return value, parsed.Scheme, nil
	}
	return "", "", errors.New("expected an HTTP or HTTPS public URL; use tnl connect for private services")
}
