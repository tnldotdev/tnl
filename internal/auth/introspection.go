package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/0xcadams/tnl/internal/credentials"
)

const maxIntrospectionResponseBytes = 16 << 10

type ExternalIdentity struct {
	Issuer    string
	Subject   string
	ExpiresAt time.Time
}

type ExternalVerifier interface {
	Verify(context.Context, string) (ExternalIdentity, error)
}

type IntrospectionConfig struct {
	URL           string
	Issuer        string
	RequiredScope string
	WorkloadToken credentials.WorkloadToken
	HTTPClient    *http.Client
}

type introspectionVerifier struct {
	url           string
	issuer        string
	requiredScope string
	workloadToken credentials.WorkloadToken
	httpClient    *http.Client
}

func NewIntrospectionVerifier(config IntrospectionConfig) (ExternalVerifier, error) {
	endpoint, err := url.Parse(config.URL)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil ||
		endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return nil, errors.New("auth: introspection endpoint must be an HTTPS URL")
	}
	issuer, err := url.Parse(config.Issuer)
	if err != nil || issuer.Scheme != "https" || issuer.Host == "" || issuer.User != nil ||
		issuer.Path != "" && issuer.Path != "/" || issuer.RawQuery != "" || issuer.Fragment != "" {
		return nil, errors.New("auth: external issuer must be an HTTPS origin")
	}
	if endpoint.Scheme != issuer.Scheme || !strings.EqualFold(endpoint.Host, issuer.Host) {
		return nil, errors.New("auth: introspection endpoint must use the external issuer origin")
	}
	if strings.TrimSpace(config.RequiredScope) == "" || strings.ContainsAny(config.RequiredScope, " \t\r\n") {
		return nil, errors.New("auth: one external scope token is required")
	}
	if _, err := credentials.ParseWorkloadToken(config.WorkloadToken); err != nil {
		return nil, fmt.Errorf("auth: introspection credential: %w", err)
	}
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	return &introspectionVerifier{
		url: endpoint.String(), issuer: strings.TrimSuffix(issuer.String(), "/"),
		requiredScope: config.RequiredScope, workloadToken: config.WorkloadToken, httpClient: client,
	}, nil
}

func (v *introspectionVerifier) Verify(ctx context.Context, token string) (ExternalIdentity, error) {
	form := make(url.Values)
	form.Set("token", token)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, v.url, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return ExternalIdentity{}, err
	}
	request.Header.Set("Authorization", "Bearer "+v.workloadToken.String())
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	response, err := v.httpClient.Do(request)
	if err != nil {
		return ExternalIdentity{}, fmt.Errorf("auth: introspect external token: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxIntrospectionResponseBytes))
		return ExternalIdentity{}, fmt.Errorf("auth: introspection returned HTTP %d", response.StatusCode)
	}
	var result struct {
		Active   bool   `json:"active"`
		Issuer   string `json:"iss"`
		Subject  string `json:"sub"`
		Username string `json:"username"`
		Email    string `json:"email"`
		Scope    string `json:"scope"`
		Expires  int64  `json:"exp"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxIntrospectionResponseBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return ExternalIdentity{}, fmt.Errorf("auth: decode introspection response: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ExternalIdentity{}, errors.New("auth: introspection response contains trailing data")
	}
	if !result.Active {
		return ExternalIdentity{}, ErrUnauthenticated
	}
	expiresAt := time.Unix(result.Expires, 0).UTC()
	if result.Issuer != v.issuer || strings.TrimSpace(result.Subject) == "" || len(result.Subject) > 256 ||
		len(result.Username) > 256 || len(result.Email) > 320 || !expiresAt.After(time.Now()) ||
		!slices.Contains(strings.Fields(result.Scope), v.requiredScope) {
		return ExternalIdentity{}, ErrUnauthenticated
	}
	return ExternalIdentity{
		Issuer: result.Issuer, Subject: result.Subject, ExpiresAt: expiresAt,
	}, nil
}
