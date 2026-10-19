package oidcauth

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Server is the confidential (or public PKCE) client owned by control. provider
// tokens never cross the CLI boundary.
type Server struct {
	verifier *providerVerifier
	secret   string
	scopes   []string
	redirect string
}

type ServerConfig struct {
	Issuer, ClientID, ClientSecret, RedirectURL string
	Scopes                                      []string
	HTTPClient                                  *http.Client
}

func NewServer(c ServerConfig) (*Server, error) {
	v, err := NewVerifier(VerifierConfig{Issuer: c.Issuer, ClientID: c.ClientID, HTTPClient: c.HTTPClient})
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(c.RedirectURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !validScopes(c.Scopes) || len(c.ClientSecret) > 4096 {
		return nil, errors.New("oidcauth: invalid server client configuration")
	}
	return &Server{verifier: v.(*providerVerifier), secret: c.ClientSecret, scopes: append([]string(nil), c.Scopes...), redirect: c.RedirectURL}, nil
}

func (s *Server) oauth(ctx context.Context) (*oauth2.Config, error) {
	p, err := s.verifier.getProvider(ctx)
	if err != nil {
		return nil, err
	}
	e := p.Endpoint()
	for _, raw := range []string{e.AuthURL, e.TokenURL} {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
			return nil, ErrUnavailable
		}
	}
	// select an advertised method explicitly. oauth2's automatic method probing
	// could redeem the same one-use code twice after an uncertain response.
	e.AuthStyle = oauth2.AuthStyleInParams
	if s.secret != "" {
		var metadata struct {
			Methods []string `json:"token_endpoint_auth_methods_supported"`
		}
		if err := p.Claims(&metadata); err != nil {
			return nil, ErrUnavailable
		}
		switch {
		case slices.Contains(metadata.Methods, "client_secret_post"):
		case len(metadata.Methods) == 0 || slices.Contains(metadata.Methods, "client_secret_basic"):
			e.AuthStyle = oauth2.AuthStyleInHeader
		default:
			return nil, ErrUnavailable
		}
	}
	return &oauth2.Config{ClientID: s.verifier.clientID, ClientSecret: s.secret, Endpoint: e, RedirectURL: s.redirect, Scopes: s.scopes}, nil
}

func (s *Server) AuthorizationURL(ctx context.Context, state, nonce, verifier string) (string, error) {
	c, err := s.oauth(ctx)
	if err != nil {
		return "", err
	}
	return c.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("nonce", nonce)), nil
}

func (s *Server) CompanyAuthorizationURL(ctx context.Context, state, nonce, verifier, intent, binding string) (string, error) {
	raw, err := s.AuthorizationURL(ctx, state, nonce, verifier)
	if err != nil {
		return "", err
	}
	u, _ := url.Parse(raw)
	q := u.Query()
	q.Set("tnl_company_intent", intent)
	q.Set("tnl_company_binding", binding)
	q.Set("max_age", "0")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (s *Server) Redeem(ctx context.Context, code, nonce, verifier string) (Identity, error) {
	if !validClaim(code, 4096) || !validClaim(nonce, 256) || len(verifier) < 43 || len(verifier) > 128 {
		return Identity{}, ErrUnauthenticated
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	c, err := s.oauth(ctx)
	if err != nil {
		return Identity{}, err
	}
	token, err := c.Exchange(oidc.ClientContext(ctx, s.verifier.httpClient), code, oauth2.VerifierOption(verifier))
	if err != nil {
		if cause := context.Cause(ctx); cause != nil {
			return Identity{}, cause
		}
		var rejected *oauth2.RetrieveError
		if errors.As(err, &rejected) && (rejected.ErrorCode == "invalid_grant" || rejected.ErrorCode == "access_denied") {
			return Identity{}, ErrUnauthenticated
		}
		return Identity{}, ErrUnavailable
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok {
		return Identity{}, ErrUnauthenticated
	}
	id, err := s.verifier.Verify(ctx, raw)
	if err != nil {
		return Identity{}, err
	}
	if subtle.ConstantTimeCompare([]byte(id.Nonce), []byte(nonce)) != 1 {
		return Identity{}, ErrUnauthenticated
	}
	return id, nil
}
