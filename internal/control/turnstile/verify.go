// package turnstile owns the fixed Siteverify exchange, not attempts, handoffs,
// or visitor authorization. public API handlers own those lifetimes in control
// state; daemon configuration shares only the key validation below.
package turnstile

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

const (
	Action   = "tnl_http_protection"
	endpoint = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
)

var (
	ErrConfiguration = errors.New("configure Turnstile with both a valid site key and secret key")
	ErrRejected      = errors.New("challenge verification was rejected")
	ErrUnavailable   = errors.New("challenge verification is unavailable")
)

func ValidateKeys(site, secret string) error {
	if site == "" && secret == "" {
		return nil
	}
	for _, value := range []string{site, secret} {
		if value == "" || len(value) > 256 || strings.ContainsAny(value, " \t\r\n\x00") {
			return ErrConfiguration
		}
	}
	return nil
}

type Verifier struct {
	SiteKey  string
	secret   string
	hostname string
	client   *http.Client
}

func (*Verifier) String() string   { return "Turnstile verifier" }
func (*Verifier) GoString() string { return "Turnstile verifier" }

// VerifiedAttempt can only be produced by successful Siteverify validation.
// control state still checks the attempt's binding, expiry, and single-use state.
type VerifiedAttempt struct{ id string }

func (v VerifiedAttempt) ID() string { return v.id }

// New returns nil for an unconfigured server. an outage does not change this
// configured-support fact, and no alternate provider or endpoint is selected.
func New(site, secret, hostname string, client *http.Client) (*Verifier, error) {
	if err := ValidateKeys(site, secret); err != nil {
		return nil, err
	}
	if site == "" {
		return nil, nil
	}
	if canonical, err := naming.CanonicalizeHostname(hostname); err != nil || canonical != hostname || strings.Contains(hostname, "*") {
		return nil, ErrConfiguration
	}
	httpClient := http.Client{Timeout: 2 * time.Second}
	if client != nil {
		httpClient = *client
		if httpClient.Timeout <= 0 || httpClient.Timeout > 2*time.Second {
			httpClient.Timeout = 2 * time.Second
		}
	}
	httpClient.Jar = nil
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Verifier{SiteKey: site, secret: secret, hostname: hostname, client: &httpClient}, nil
}

func (v *Verifier) Verify(ctx context.Context, token, attempt string, now time.Time) (VerifiedAttempt, error) {
	if v == nil {
		return VerifiedAttempt{}, ErrUnavailable
	}
	if token == "" || len(token) > 2048 || !opaqueid.Valid(attempt, opaqueid.HTTPChallengePrefix) {
		return VerifiedAttempt{}, ErrRejected
	}
	form := url.Values{"secret": {v.secret}, "response": {token}}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return VerifiedAttempt{}, ErrUnavailable
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := v.client.Do(request)
	if err != nil {
		return VerifiedAttempt{}, ErrUnavailable
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
	if err != nil || len(raw) > 64<<10 || response.StatusCode != http.StatusOK {
		return VerifiedAttempt{}, ErrUnavailable
	}
	var result struct {
		Success     bool      `json:"success"`
		Hostname    string    `json:"hostname"`
		Action      string    `json:"action"`
		Data        string    `json:"cdata"`
		CompletedAt time.Time `json:"challenge_ts"`
		Codes       []string  `json:"error-codes"`
	}
	if json.Unmarshal(raw, &result) != nil {
		return VerifiedAttempt{}, ErrUnavailable
	}
	if !result.Success {
		for _, code := range result.Codes {
			switch code {
			case "missing-input-secret", "invalid-input-secret", "internal-error":
				return VerifiedAttempt{}, ErrUnavailable
			}
		}
		return VerifiedAttempt{}, ErrRejected
	}
	if result.Hostname != v.hostname || result.Action != Action || result.Data != attempt ||
		result.CompletedAt.IsZero() || result.CompletedAt.After(now.Add(5*time.Second)) || result.CompletedAt.Before(now.Add(-5*time.Minute)) {
		return VerifiedAttempt{}, ErrRejected
	}
	return VerifiedAttempt{id: attempt}, nil
}
