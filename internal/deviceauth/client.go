// Package deviceauth implements the bounded external device login used by tnl.
package deviceauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxResponseBytes = 16 << 10

type Config struct {
	Issuer                      string
	DeviceAuthorizationEndpoint string
	TokenEndpoint               string
	ClientID                    string
	Scope                       string
	HTTPClient                  *http.Client
}

func Login(ctx context.Context, config Config, output io.Writer) (string, error) {
	if output == nil {
		return "", errors.New("deviceauth: output is required")
	}
	issuer, err := parseIssuer(config.Issuer)
	if err != nil {
		return "", fmt.Errorf("deviceauth: issuer: %w", err)
	}
	if err := validateEndpoint(config.DeviceAuthorizationEndpoint, issuer, false); err != nil {
		return "", fmt.Errorf("deviceauth: device endpoint: %w", err)
	}
	if err := validateEndpoint(config.TokenEndpoint, issuer, false); err != nil {
		return "", fmt.Errorf("deviceauth: token endpoint: %w", err)
	}
	if config.ClientID == "" || len(config.ClientID) > 128 || config.Scope == "" || len(config.Scope) > 256 ||
		strings.ContainsAny(config.Scope, " \t\r\n") {
		return "", errors.New("deviceauth: invalid client configuration")
	}
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{
			Timeout:       20 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	var authorization struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		ExpiresIn               int    `json:"expires_in"`
		Interval                int    `json:"interval"`
	}
	if err := postJSON(ctx, client, config.DeviceAuthorizationEndpoint, map[string]string{
		"client_id": config.ClientID, "scope": config.Scope,
	}, &authorization); err != nil {
		return "", fmt.Errorf("deviceauth: request device code: %w", err)
	}
	if authorization.DeviceCode == "" || len(authorization.DeviceCode) > 512 ||
		authorization.UserCode == "" || len(authorization.UserCode) > 64 ||
		authorization.ExpiresIn < 1 || authorization.ExpiresIn > 3600 ||
		authorization.Interval < 1 || authorization.Interval > 60 {
		return "", errors.New("deviceauth: invalid authorization response")
	}
	verificationURL := authorization.VerificationURIComplete
	if verificationURL == "" {
		verificationURL = authorization.VerificationURI
	}
	if err := validateEndpoint(verificationURL, issuer, true); err != nil {
		return "", errors.New("deviceauth: invalid verification URL")
	}
	if _, err := fmt.Fprintf(output, "Open %s\nCode: %s\n", verificationURL, authorization.UserCode); err != nil {
		return "", err
	}

	deadline := time.NewTimer(time.Duration(authorization.ExpiresIn) * time.Second)
	defer deadline.Stop()
	interval := time.Duration(authorization.Interval) * time.Second
	for {
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", ctx.Err()
		case <-deadline.C:
			timer.Stop()
			return "", errors.New("deviceauth: authorization expired")
		case <-timer.C:
		}
		accessToken, code, err := poll(ctx, client, config.TokenEndpoint, config.ClientID, authorization.DeviceCode)
		if err == nil {
			return accessToken, nil
		}
		switch code {
		case "authorization_pending":
			continue
		case "slow_down":
			interval += 5 * time.Second
			continue
		case "access_denied":
			return "", errors.New("deviceauth: authorization denied")
		case "expired_token":
			return "", errors.New("deviceauth: authorization expired")
		default:
			return "", err
		}
	}
}

func poll(
	ctx context.Context,
	client *http.Client,
	endpoint, clientID, deviceCode string,
) (string, string, error) {
	body, err := json.Marshal(map[string]string{
		"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
		"device_code": deviceCode,
		"client_id":   clientID,
	})
	if err != nil {
		return "", "", err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", "", err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return "", "", fmt.Errorf("deviceauth: poll token: %w", err)
	}
	defer response.Body.Close()
	payload, err := readResponse(response.Body)
	if err != nil {
		return "", "", err
	}
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		var result struct {
			AccessToken string `json:"access_token"`
			TokenType   string `json:"token_type"`
			ExpiresIn   int    `json:"expires_in"`
			Scope       string `json:"scope"`
		}
		if err := decode(payload, &result); err != nil || result.AccessToken == "" ||
			len(result.AccessToken) > 4096 || result.TokenType != "Bearer" {
			return "", "", errors.New("deviceauth: invalid token response")
		}
		return result.AccessToken, "", nil
	}
	var problem struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := decode(payload, &problem); err != nil || problem.Error == "" {
		return "", "", fmt.Errorf("deviceauth: token endpoint returned HTTP %d", response.StatusCode)
	}
	return "", problem.Error, fmt.Errorf("deviceauth: token endpoint: %s", problem.Error)
}

func postJSON(ctx context.Context, client *http.Client, endpoint string, body any, result any) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	payload, err := readResponse(response.Body)
	if err != nil {
		return err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", response.StatusCode)
	}
	return decode(payload, result)
}

func readResponse(reader io.Reader) ([]byte, error) {
	payload, err := io.ReadAll(io.LimitReader(reader, maxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(payload) > maxResponseBytes {
		return nil, errors.New("deviceauth: response exceeds limit")
	}
	return payload, nil
}

func decode(payload []byte, result any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(result); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("deviceauth: response contains trailing data")
	}
	return nil
}

func parseIssuer(value string) (*url.URL, error) {
	issuer, err := url.Parse(value)
	if err != nil || issuer.Scheme != "https" || issuer.Host == "" || issuer.User != nil ||
		issuer.Path != "" && issuer.Path != "/" || issuer.RawQuery != "" || issuer.Fragment != "" {
		return nil, errors.New("must be an HTTPS origin")
	}
	issuer.Path = ""
	return issuer, nil
}

func validateEndpoint(value string, issuer *url.URL, allowQuery bool) error {
	endpoint, err := url.Parse(value)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil ||
		endpoint.Fragment != "" || !allowQuery && endpoint.RawQuery != "" {
		return errors.New("must be an HTTPS URL without user information or a fragment")
	}
	if endpoint.Scheme != issuer.Scheme || !strings.EqualFold(endpoint.Host, issuer.Host) {
		return errors.New("must use the external issuer origin")
	}
	return nil
}
