package workloadclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/client/project/workloadmanifest"
)

var ErrAssertionSource = errors.New("select exactly one workload assertion, token file, or callback")
var ErrAssertionUnavailable = errors.New("workload assertion is unavailable")

// assertion source is a one-of. files are reread for each new session and
// callbacks acquire request-scoped provider tokens without storing them.
type AssertionSource struct {
	Assertion string
	TokenFile string
	Callback  func(context.Context) (string, error)
}

func (AssertionSource) String() string   { return "private workload assertion source" }
func (AssertionSource) GoString() string { return "private workload assertion source" }
func (s AssertionSource) Acquire(ctx context.Context) (string, error) {
	count := 0
	if s.Assertion != "" {
		count++
	}
	if s.TokenFile != "" {
		count++
	}
	if s.Callback != nil {
		count++
	}
	if count != 1 {
		return "", ErrAssertionSource
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if s.Callback != nil {
		raw, err := s.Callback(ctx)
		if err != nil {
			return "", err
		}
		return boundedAssertion(raw)
	}
	if s.TokenFile != "" {
		f, err := os.Open(s.TokenFile)
		if err != nil {
			return "", errors.Join(ErrAssertionUnavailable, err)
		}
		defer f.Close()
		b, err := io.ReadAll(io.LimitReader(f, (32<<10)+1))
		if err != nil {
			return "", errors.Join(ErrAssertionUnavailable, err)
		}
		return boundedAssertion(string(b))
	}
	return boundedAssertion(s.Assertion)
}
func boundedAssertion(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 32<<10 || strings.ContainsAny(raw, "\r\n\x00\t ") {
		return "", ErrAssertionUnavailable
	}
	return raw, nil
}

// acquire uses nonsecret build hints. control independently selects saved trust.
// Vercel functions should supply @vercel/oidc's request-scoped helper as callback.
func Acquire(ctx context.Context, hints workloadmanifest.Acquisition, callback func(context.Context) (string, error)) (string, error) {
	source := AssertionSource{Callback: callback}
	switch hints.Method {
	case "github-actions", "callback":
		if callback == nil {
			return "", ErrAssertionUnavailable
		}
	case "token-file":
		if callback != nil {
			return "", ErrAssertionSource
		}
		source.TokenFile = hints.TokenFile
	case "vercel-oidc":
		if callback == nil {
			source.TokenFile = os.Getenv("VERCEL_OIDC_TOKEN_FILE")
			if source.TokenFile == "" {
				source.Assertion = os.Getenv("VERCEL_OIDC_TOKEN")
			}
		}
	case "fly-machine-api":
		if callback != nil {
			return "", ErrAssertionSource
		}
		source.Callback = func(ctx context.Context) (string, error) { return flyAssertion(ctx, hints.Audience, "/.fly/api") }
	default:
		return "", ErrAssertionSource
	}
	return source.Acquire(ctx)
}

// Fly's documented endpoint returns a text/plain signed JWT. the fixed local
// socket, not app/org environment variables, acquires the machine identity.
func flyAssertion(ctx context.Context, audience, socket string) (string, error) {
	data, err := json.Marshal(struct {
		Audience string `json:"aud"`
	}{audience})
	if err != nil {
		return "", err
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost/v1/tokens/oidc", bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	r.Header.Set("Content-Type", "application/json")
	response, err := client.Do(r)
	if err != nil {
		return "", errors.Join(ErrAssertionUnavailable, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", ErrAssertionUnavailable
	}
	b, err := io.ReadAll(io.LimitReader(response.Body, (32<<10)+1))
	if err != nil {
		return "", errors.Join(ErrAssertionUnavailable, err)
	}
	return boundedAssertion(string(b))
}
