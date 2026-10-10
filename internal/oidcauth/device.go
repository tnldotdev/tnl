package oidcauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/tnldotdev/tnl/internal/httpclient"
	"golang.org/x/oauth2"
)

// DeviceChallenge is a private checkpoint. only the approval URL, user code,
// expiry, and interval may be displayed to the person approving login.
type DeviceChallenge struct {
	DeviceCode  string
	Nonce       string
	TokenURL    string
	ApprovalURL string
	UserCode    string
	ExpiresAt   time.Time
	Interval    time.Duration
}

func deviceProvider(ctx context.Context, config Config) (context.Context, *oidc.Provider, error) {
	if strings.TrimSpace(config.Issuer) == "" || strings.TrimSpace(config.ClientID) == "" || !validScopes(config.Scopes) {
		return ctx, nil, errors.New("oidcauth: invalid configuration")
	}
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	ctx = oidc.ClientContext(ctx, httpclient.NoRedirects(client))
	provider, err := oidc.NewProvider(ctx, config.Issuer)
	if err != nil {
		if cause := context.Cause(ctx); cause != nil {
			return ctx, nil, cause
		}
		return ctx, nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	return ctx, provider, nil
}

func StartDevice(ctx context.Context, config Config) (DeviceChallenge, error) {
	ctx, provider, err := deviceProvider(ctx, config)
	if err != nil {
		return DeviceChallenge{}, err
	}
	endpoint := provider.Endpoint()
	endpoint.AuthStyle = oauth2.AuthStyleInParams
	if endpoint.DeviceAuthURL == "" || endpoint.TokenURL == "" {
		return DeviceChallenge{}, errors.New("oidcauth: provider does not support device login")
	}
	nonce, err := randomValue()
	if err != nil {
		return DeviceChallenge{}, err
	}
	oauth := oauth2.Config{ClientID: config.ClientID, Endpoint: endpoint, Scopes: config.Scopes}
	auth, err := oauth.DeviceAuth(ctx, oauth2.SetAuthURLParam("nonce", nonce))
	if err != nil {
		return DeviceChallenge{}, err
	}
	approval := auth.VerificationURIComplete
	if approval == "" {
		approval = auth.VerificationURI
	}
	u, urlErr := url.Parse(approval)
	decodedApproval, _ := url.QueryUnescape(approval)
	if urlErr != nil || u.Scheme != "https" && u.Scheme != "http" || u.Host == "" || u.User != nil ||
		len(approval) > 8192 || auth.DeviceCode == "" || len(auth.DeviceCode) > 16384 || auth.UserCode == "" ||
		len(auth.UserCode) > 256 || strings.Contains(decodedApproval, auth.DeviceCode) || auth.DeviceCode == auth.UserCode ||
		!auth.Expiry.After(time.Now()) || time.Until(auth.Expiry) > 24*time.Hour || auth.Interval > 3600 {
		return DeviceChallenge{}, errors.New("oidcauth: invalid device authorization response")
	}
	interval := time.Duration(auth.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	return DeviceChallenge{DeviceCode: auth.DeviceCode, Nonce: nonce, TokenURL: endpoint.TokenURL,
		ApprovalURL: approval, UserCode: auth.UserCode, ExpiresAt: auth.Expiry, Interval: interval}, nil
}

// PollDevice performs exactly one redemption attempt. the caller checkpoints
// before calling and decides whether a structured response permits another poll.
func PollDevice(ctx context.Context, config Config, challenge DeviceChallenge) (string, error) {
	values := url.Values{"client_id": {config.ClientID}, "grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {challenge.DeviceCode}}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, challenge.TokenURL, strings.NewReader(values.Encode()))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	response, err := httpclient.NoRedirects(client).Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil {
		return "", err
	}
	if len(body) > 65536 {
		return "", errors.New("oidcauth: token response is too large")
	}
	var token struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(body, &token); err != nil {
		return "", fmt.Errorf("oidcauth: decode token response: %w", err)
	}
	if token.Error != "" {
		return "", &oauth2.RetrieveError{Response: response, ErrorCode: token.Error}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 || token.IDToken == "" || len(token.IDToken) > 16384 {
		return "", errors.New("oidcauth: invalid token response")
	}
	return token.IDToken, nil
}

// VerifyDevice verifies a checkpointed assertion before the one-time control exchange.
func VerifyDevice(ctx context.Context, config Config, challenge DeviceChallenge, assertion string) (Result, error) {
	ctx, provider, err := deviceProvider(ctx, config)
	if err != nil {
		return Result{}, err
	}
	return verifiedResult(ctx, provider, config.ClientID, challenge.Nonce, LoginFlowDeviceCode, (&oauth2.Token{}).WithExtra(map[string]any{"id_token": assertion}))
}
