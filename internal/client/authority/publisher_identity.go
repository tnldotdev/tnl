package authority

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

func (c *Client) RedeemPublisherEnrollment(ctx context.Context, secret string, public ed25519.PublicKey) (authorityv1.PublisherEnrollmentResult, error) {
	return requestWithToken[authorityv1.PublisherEnrollmentResult](ctx, c, "", func(ctx context.Context, e ...authorityv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RedeemPublisherEnrollment(ctx, authorityv1.RedeemPublisherEnrollmentRequest{EnrollmentKey: secret, PublicKey: base64.RawURLEncoding.EncodeToString(public)}, e...)
	})
}

func (c *Client) ExchangePublisherAssertion(ctx context.Context, client, grant, key string, private ed25519.PrivateKey) (string, error) {
	assertion, err := publisherproof.Sign(client, key, grant, c.api.Server+"v1/publisher-token", private, time.Now())
	if err != nil {
		return "", err
	}
	r, err := requestWithToken[authorityv1.PublisherTokenResponse](ctx, c, "", func(ctx context.Context, e ...authorityv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ExchangePublisherAssertion(ctx, authorityv1.PublisherTokenRequest{ClientId: client, GrantId: grant, GrantType: "client_credentials", ClientAssertionType: publisherproof.AssertionType, ClientAssertion: assertion}, e...)
	})
	if err != nil {
		return "", err
	}
	if r.GrantId != grant || r.AccessToken == "" || r.TokenType != "Bearer" || r.ExpiresIn < 1 || r.ExpiresIn > 300 {
		return "", ErrUnauthenticated
	}
	return r.AccessToken, nil
}

func (c *Client) RotatePublisherKey(ctx context.Context, token, client, grant, currentKey, replacement string, currentPrivate, replacementPrivate ed25519.PrivateKey) error {
	now := time.Now()
	audience := c.api.Server + "v1/publisher-keys/rotate"
	if len(currentPrivate) != ed25519.PrivateKeySize || len(replacementPrivate) != ed25519.PrivateKeySize {
		return publisherproof.ErrProof
	}
	public := replacementPrivate.Public().(ed25519.PublicKey)
	proof, err := publisherproof.Sign(client, replacement, grant, audience, replacementPrivate, now)
	if err != nil {
		return err
	}
	currentProof, err := publisherproof.Sign(client, currentKey, grant, publisherproof.RotationAudience(audience, replacement, public), currentPrivate, now)
	if err != nil {
		return err
	}
	_, err = requestWithToken[struct{}](ctx, c, token, func(ctx context.Context, e ...authorityv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RotatePublisherKey(ctx, authorityv1.RotatePublisherKeyRequest{KeyId: replacement, PublicKey: base64.RawURLEncoding.EncodeToString(public), Proof: proof, CurrentProof: currentProof}, e...)
	})
	return err
}
