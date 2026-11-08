package workload

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/tnldotdev/tnl/internal/client/project/workloadmanifest"
	"golang.org/x/sys/unix"
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
		f, err := os.OpenFile(s.TokenFile, os.O_RDONLY|unix.O_NONBLOCK, 0)
		if err != nil {
			return "", errors.Join(ErrAssertionUnavailable, err)
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() > 32<<10 {
			return "", ErrAssertionUnavailable
		}
		b, err := io.ReadAll(io.LimitReader(f, (32<<10)+1))
		if err != nil || len(b) > 32<<10 {
			return "", errors.Join(ErrAssertionUnavailable, err)
		}
		return boundedAssertion(string(b))
	}
	return boundedAssertion(s.Assertion)
}
func boundedAssertion(raw string) (string, error) {
	space := func(r rune) bool { return unicode.IsSpace(r) || r == '\ufeff' }
	raw = strings.TrimFunc(raw, space)
	if raw == "" || len(raw) > 32<<10 || !utf8.ValidString(raw) || strings.ContainsRune(raw, 0) || strings.ContainsFunc(raw, space) {
		return "", ErrAssertionUnavailable
	}
	return raw, nil
}

// acquire uses nonsecret build hints. control independently selects saved trust.
// Vercel functions should supply @vercel/oidc's request-scoped helper as callback.
func Acquire(ctx context.Context, hints workloadmanifest.Acquisition, callback func(context.Context) (string, error), getenv func(string) string) (string, error) {
	source := AssertionSource{Callback: callback}
	switch hints.Method {
	case "github-actions":
		if callback == nil {
			source.Callback = func(ctx context.Context) (string, error) { return githubAssertion(ctx, hints.Audience, nil, getenv) }
		}
	case "callback":
		if callback == nil {
			return "", ErrAssertionUnavailable
		}
	case "token-file":
		if callback != nil {
			return "", ErrAssertionSource
		}
		source.TokenFile = hints.TokenFile
	case "token-env":
		if callback != nil {
			return "", ErrAssertionSource
		}
		source.Assertion = getenv(hints.TokenEnv)
		if source.Assertion == "" {
			return "", ErrAssertionUnavailable
		}
	case "vercel-oidc":
		if callback == nil {
			source.TokenFile = getenv("VERCEL_OIDC_TOKEN_FILE")
			if source.TokenFile == "" {
				source.Assertion = getenv("VERCEL_OIDC_TOKEN")
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

// the audience comes from the generated manifest; the runtime supplies only its
// HTTPS token endpoint and bearer credential. redirects never carry that bearer.
func githubAssertion(ctx context.Context, audience string, transport http.RoundTripper, getenv func(string) string) (string, error) {
	endpoint, bearer, err := githubAssertionSource(getenv)
	if err != nil {
		return "", err
	}
	query := endpoint.Query()
	query.Set("audience", audience)
	endpoint.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return "", ErrAssertionUnavailable
	}
	request.Header.Set("Authorization", "Bearer "+bearer)
	if transport == nil {
		transport = http.DefaultTransport.(*http.Transport).Clone()
	}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	response, err := client.Do(request)
	if err != nil {
		return "", ErrAssertionUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", ErrAssertionUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, (40<<10)+1))
	if err != nil || len(data) > 40<<10 || !utf8.Valid(data) {
		return "", ErrAssertionUnavailable
	}
	var value struct {
		Value string `json:"value"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || decoder.Decode(new(any)) != io.EOF {
		return "", ErrAssertionUnavailable
	}
	return boundedAssertion(value.Value)
}

// ValidateGitHubActionsSource checks a private job-runtime source without
// acquiring a proof. ordinary SDK/request inputs do not gain a background owner.
func ValidateGitHubActionsSource(getenv func(string) string) error {
	_, _, err := githubAssertionSource(getenv)
	return err
}

func githubAssertionSource(getenv func(string) string) (*url.URL, string, error) {
	if getenv("GITHUB_ACTIONS") != "true" {
		return nil, "", ErrAssertionUnavailable
	}
	raw := getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	if len(raw) > 4096 {
		return nil, "", ErrAssertionUnavailable
	}
	endpoint, err := url.Parse(raw)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil || endpoint.Fragment != "" {
		return nil, "", ErrAssertionUnavailable
	}
	bearer, err := boundedAssertion(getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN"))
	if err != nil {
		return nil, "", ErrAssertionUnavailable
	}
	return endpoint, bearer, nil
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
	if err != nil || len(b) > 32<<10 {
		return "", errors.Join(ErrAssertionUnavailable, err)
	}
	return boundedAssertion(string(b))
}
