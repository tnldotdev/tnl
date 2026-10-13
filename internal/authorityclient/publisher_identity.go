package authorityclient

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisheridentity"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

func (c *Client) RedeemPublisherEnrollment(ctx context.Context, enrollmentKey string, public ed25519.PublicKey) (authorityv1.PublisherEnrollmentResult, error) {
	if len(public) != ed25519.PublicKeySize {
		return authorityv1.PublisherEnrollmentResult{}, failure.Wrap("redeem publisher enrollment", failure.ServerResponseInvalid, errors.New("publisher public key is invalid"))
	}
	result, err := requestWithToken[authorityv1.PublisherEnrollmentResult](ctx, c, "", func(ctx context.Context, editors ...authorityv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RedeemPublisherEnrollment(ctx, authorityv1.RedeemPublisherEnrollmentRequest{
			EnrollmentKey: enrollmentKey, PublicKey: base64.RawURLEncoding.EncodeToString(public),
		}, editors...)
	})
	if err != nil {
		return result, err
	}
	if !opaqueid.Valid(result.ClientId, opaqueid.PublisherIdentityPrefix) ||
		!opaqueid.Valid(result.KeyId, opaqueid.PublisherIdentityKeyPrefix) ||
		!opaqueid.Valid(result.GrantId, opaqueid.PublisherGrantPrefix) || result.TeamId == "" ||
		result.Kind != "saved_url" && result.Kind != "namespace" {
		return authorityv1.PublisherEnrollmentResult{}, failure.Wrap("redeem publisher enrollment", failure.ServerResponseInvalid,
			errors.New("control returned an invalid publisher identity"))
	}
	return result, nil
}

func (c *Client) ExchangePublisherAssertion(ctx context.Context, clientID, grantID, keyID string, private ed25519.PrivateKey) (string, time.Time, error) {
	const path = "/v1/publisher/token"
	now := time.Now().UTC()
	origin := strings.TrimSuffix(c.api.Server, "/")
	assertion, err := publisheridentity.Sign(clientID, keyID, origin+path, private, now)
	if err != nil {
		return "", time.Time{}, err
	}
	form := url.Values{
		"grant_type":            {publisheridentity.GrantType},
		"client_id":             {clientID},
		"client_assertion_type": {publisheridentity.AssertionType},
		"client_assertion":      {assertion},
		"scope":                 {grantID},
	}
	response, err := requestWithToken[authorityv1.PublisherTokenResponse](ctx, c, "", func(ctx context.Context, _ ...authorityv1.RequestEditorFn) (*http.Response, error) {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, origin+path, strings.NewReader(form.Encode()))
		if err != nil {
			return nil, err
		}
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("Accept", "application/json, application/problem+json")
		return c.api.Client.Do(request)
	})
	if err != nil {
		return "", time.Time{}, err
	}
	if response.TokenType != "Bearer" || response.Scope != grantID || response.ExpiresIn < 1 || response.ExpiresIn > 300 ||
		!strings.HasPrefix(response.AccessToken, "pta_") || len(response.AccessToken) != 47 {
		return "", time.Time{}, failure.Wrap("exchange publisher assertion", failure.ServerResponseInvalid,
			errors.New("control returned an invalid scoped publisher token"))
	}
	return response.AccessToken, now.Add(time.Duration(response.ExpiresIn) * time.Second), nil
}
