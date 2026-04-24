// Package oidclogin implements OIDC device login for the CLI.
package oidclogin

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type Config struct {
	Issuer     string
	ClientID   string
	HTTPClient *http.Client
}

func Login(ctx context.Context, config Config, output io.Writer) (string, error) {
	if output == nil || strings.TrimSpace(config.Issuer) == "" || strings.TrimSpace(config.ClientID) == "" {
		return "", errors.New("oidclogin: invalid configuration")
	}
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	ctx = oidc.ClientContext(ctx, client)
	provider, err := oidc.NewProvider(ctx, config.Issuer)
	if err != nil {
		return "", fmt.Errorf("oidclogin: discover provider: %w", err)
	}
	endpoint := provider.Endpoint()
	if endpoint.DeviceAuthURL == "" || endpoint.TokenURL == "" {
		return "", errors.New("oidclogin: provider does not support device login")
	}
	nonce, err := randomNonce()
	if err != nil {
		return "", err
	}
	oauthConfig := oauth2.Config{
		ClientID: config.ClientID,
		Endpoint: endpoint,
		Scopes:   []string{oidc.ScopeOpenID},
	}
	authorization, err := oauthConfig.DeviceAuth(ctx, oauth2.SetAuthURLParam("nonce", nonce))
	if err != nil {
		return "", fmt.Errorf("oidclogin: request login code: %w", err)
	}
	verificationURL := authorization.VerificationURIComplete
	if verificationURL == "" {
		verificationURL = authorization.VerificationURI
	}
	if verificationURL == "" || authorization.UserCode == "" {
		return "", errors.New("oidclogin: invalid device authorization response")
	}
	if _, err := fmt.Fprintf(output, "Open %s\nCode: %s\n", verificationURL, authorization.UserCode); err != nil {
		return "", err
	}
	token, err := oauthConfig.DeviceAccessToken(ctx, authorization)
	if err != nil {
		return "", fmt.Errorf("oidclogin: complete login: %w", err)
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" || len(rawIDToken) > 16384 {
		return "", errors.New("oidclogin: provider did not return an ID token")
	}
	verified, err := provider.Verifier(&oidc.Config{
		ClientID:             config.ClientID,
		SupportedSigningAlgs: []string{"RS256"},
	}).Verify(ctx, rawIDToken)
	if err != nil {
		return "", errors.New("oidclogin: invalid ID token")
	}
	if strings.TrimSpace(verified.Subject) == "" || len(verified.Subject) > 256 {
		return "", errors.New("oidclogin: invalid ID token subject")
	}
	var claims struct {
		Nonce string `json:"nonce"`
	}
	if err := verified.Claims(&claims); err != nil || claims.Nonce != nonce {
		return "", errors.New("oidclogin: invalid ID token nonce")
	}
	return rawIDToken, nil
}

func randomNonce() (string, error) {
	var material [32]byte
	if _, err := rand.Read(material[:]); err != nil {
		return "", fmt.Errorf("oidclogin: generate nonce: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(material[:]), nil
}
