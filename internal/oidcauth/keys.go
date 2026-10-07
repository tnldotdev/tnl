package oidcauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"

	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"
)

// the provider verifier formats key-set errors as text. observe the original
// key-set error so classification never depends on that text.
type observedKeySet struct {
	oidc.KeySet
	err error
}

func (k *observedKeySet) VerifySignature(ctx context.Context, raw string) ([]byte, error) {
	payload, err := k.KeySet.VerifySignature(ctx, raw)
	k.err = err
	return payload, err
}

type keyFetchError struct{ cause error }

func (e *keyFetchError) Error() string { return "OIDC signing keys are unavailable" }
func (e *keyFetchError) Unwrap() error { return e.cause }

type keyFetchTransport struct{ base http.RoundTripper }

func (t keyFetchTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := t.base.RoundTrip(request)
	if err != nil {
		return nil, &keyFetchError{err}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, &keyFetchError{errors.New("signing key request did not return HTTP 200")}
	}
	const maximumKeyBytes = 256 << 10
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumKeyBytes+1))
	if err != nil {
		return nil, &keyFetchError{err}
	}
	if len(body) > maximumKeyBytes {
		return nil, &keyFetchError{errors.New("signing key response exceeds its size limit")}
	}
	var payload struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, &keyFetchError{err}
	}
	keys := make([]json.RawMessage, 0, len(payload.Keys))
	for _, raw := range payload.Keys {
		var metadata struct {
			Algorithm string `json:"alg"`
		}
		if err := json.Unmarshal(raw, &metadata); err != nil {
			return nil, &keyFetchError{err}
		}
		// only RS256 can authenticate this server. ignore unrelated algorithms
		// and unsupported key types as required by the JWK set contract.
		if metadata.Algorithm != "" && metadata.Algorithm != "RS256" {
			continue
		}
		var key jose.JSONWebKey
		if err := json.Unmarshal(raw, &key); err != nil {
			if errors.Is(err, jose.ErrUnsupportedKeyType) {
				continue
			}
			return nil, &keyFetchError{err}
		}
		keys = append(keys, raw)
	}
	payload.Keys = keys
	body, err = json.Marshal(payload)
	if err != nil {
		return nil, &keyFetchError{err}
	}
	response.ContentLength = int64(len(body))
	response.Header.Set("Content-Type", "application/json")
	response.Body = io.NopCloser(bytes.NewReader(body))
	return response, nil
}

func providerIssuer(provider *oidc.Provider) string {
	var metadata struct {
		Issuer string `json:"issuer"`
	}
	_ = provider.Claims(&metadata)
	return metadata.Issuer
}

func providerKeySet(ctx context.Context, provider *oidc.Provider) (oidc.KeySet, error) {
	var metadata struct {
		URI string `json:"jwks_uri"`
	}
	if err := provider.Claims(&metadata); err != nil {
		return nil, &keyFetchError{err}
	}
	uri, err := url.Parse(metadata.URI)
	if err != nil || uri.Scheme != "https" || uri.Host == "" || uri.User != nil || uri.Fragment != "" {
		return nil, &keyFetchError{errors.Join(err, errors.New("signing key URL is invalid"))}
	}
	client := *http.DefaultClient
	if configured, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok {
		client = *configured
	}
	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	client.Transport = keyFetchTransport{base: base}
	return oidc.NewRemoteKeySet(oidc.ClientContext(ctx, &client), metadata.URI), nil
}
