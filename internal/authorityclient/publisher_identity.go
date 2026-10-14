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

	"github.com/tnldotdev/tnl/internal/publisheridentity"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

func (c *Client) RedeemPublisherEnrollment(ctx context.Context, key string, public ed25519.PublicKey) (authorityv1.PublisherEnrollmentResult, error) {
	if len(public) != ed25519.PublicKeySize || key == "" {
		return authorityv1.PublisherEnrollmentResult{}, errors.New("invalid publisher enrollment")
	}
	return requestWithToken[authorityv1.PublisherEnrollmentResult](ctx, c, "", func(ctx context.Context, editors ...authorityv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RedeemPublisherEnrollment(ctx, authorityv1.RedeemPublisherEnrollmentRequest{
			EnrollmentKey: key, PublicKey: base64.RawURLEncoding.EncodeToString(public),
		}, editors...)
	})
}

func (c *Client) ExchangePublisherAssertion(ctx context.Context, clientID, grantID, keyID string, private ed25519.PrivateKey) (string, error) {
	const path = "/v1/publisher/token"
	origin := strings.TrimSuffix(c.api.Server, "/")
	assertion, err := publisheridentity.Sign(clientID, keyID, origin+path, private, time.Now().UTC())
	if err != nil {
		return "", err
	}
	form := url.Values{
		"grant_type": {publisheridentity.GrantType}, "client_id": {clientID},
		"client_assertion_type": {publisheridentity.AssertionType}, "client_assertion": {assertion}, "scope": {grantID},
	}
	response, err := requestWithToken[authorityv1.PublisherTokenResponse](ctx, c, "", func(ctx context.Context, _ ...authorityv1.RequestEditorFn) (*http.Response, error) {
		r, err := http.NewRequestWithContext(ctx, http.MethodPost, origin+path, strings.NewReader(form.Encode()))
		if err != nil {
			return nil, err
		}
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Accept", "application/json, application/problem+json")
		return c.api.Client.Do(r)
	})
	if err != nil {
		return "", err
	}
	if response.TokenType != "Bearer" || response.Scope != grantID || response.ExpiresIn < 1 || response.ExpiresIn > 300 ||
		!strings.HasPrefix(response.AccessToken, "pta_") {
		return "", errors.New("control returned an invalid publisher token")
	}
	return response.AccessToken, nil
}
