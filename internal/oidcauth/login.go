// Package oidcauth implements OIDC authentication and CLI login flows.
package oidcauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	LoginFlowDeviceCode            = "device_code"
	LoginFlowAuthorizationCodePKCE = "authorization_code_pkce"
)

type Config struct {
	Issuer     string
	ClientID   string
	LoginFlow  string
	Scopes     []string
	HTTPClient *http.Client
	OpenURL    func(string) error
	Prompt     func(Prompt) error
}

// Prompt contains the user action needed to continue authentication.
type Prompt struct {
	URL  string
	Code string
}

type Result struct {
	IDToken  string
	Identity Identity
}

func Login(ctx context.Context, config Config, output io.Writer) (Result, error) {
	if output == nil || strings.TrimSpace(config.Issuer) == "" || strings.TrimSpace(config.ClientID) == "" ||
		config.LoginFlow != LoginFlowDeviceCode && config.LoginFlow != LoginFlowAuthorizationCodePKCE ||
		!validScopes(config.Scopes) {
		return Result{}, errors.New("oidcauth: invalid configuration")
	}
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	ctx = oidc.ClientContext(ctx, client)
	provider, err := oidc.NewProvider(ctx, config.Issuer)
	if err != nil {
		return Result{}, fmt.Errorf("oidcauth: discover provider: %w", err)
	}
	nonce, err := randomValue()
	if err != nil {
		return Result{}, err
	}
	oauthConfig := oauth2.Config{
		ClientID: config.ClientID,
		Endpoint: provider.Endpoint(),
		Scopes:   append([]string(nil), config.Scopes...),
	}
	oauthConfig.Endpoint.AuthStyle = oauth2.AuthStyleInParams
	var token *oauth2.Token
	switch config.LoginFlow {
	case LoginFlowDeviceCode:
		token, err = deviceLogin(ctx, oauthConfig, nonce, output, config.OpenURL, config.Prompt)
	case LoginFlowAuthorizationCodePKCE:
		token, err = authorizationCodeLogin(ctx, oauthConfig, nonce, output, config.OpenURL, config.Prompt)
	}
	if err != nil {
		return Result{}, err
	}
	return verifiedResult(ctx, provider, config.ClientID, nonce, config.LoginFlow, token)
}

func deviceLogin(
	ctx context.Context,
	oauthConfig oauth2.Config,
	nonce string,
	output io.Writer,
	openURL func(string) error,
	prompt func(Prompt) error,
) (*oauth2.Token, error) {
	if oauthConfig.Endpoint.DeviceAuthURL == "" || oauthConfig.Endpoint.TokenURL == "" {
		return nil, errors.New("oidcauth: provider does not support device login")
	}
	authorization, err := oauthConfig.DeviceAuth(ctx, oauth2.SetAuthURLParam("nonce", nonce))
	if err != nil {
		return nil, fmt.Errorf("oidcauth: request login code: %w", err)
	}
	verificationURL := authorization.VerificationURIComplete
	if verificationURL == "" {
		verificationURL = authorization.VerificationURI
	}
	if verificationURL == "" || authorization.UserCode == "" {
		return nil, errors.New("oidcauth: invalid device authorization response")
	}
	if err := writePrompt(output, prompt, Prompt{URL: verificationURL, Code: authorization.UserCode}); err != nil {
		return nil, err
	}
	if openURL != nil {
		_ = openURL(verificationURL)
	}
	token, err := oauthConfig.DeviceAccessToken(ctx, authorization)
	if err != nil {
		return nil, fmt.Errorf("oidcauth: complete login: %w", err)
	}
	return token, nil
}

func authorizationCodeLogin(
	ctx context.Context,
	oauthConfig oauth2.Config,
	nonce string,
	output io.Writer,
	openURL func(string) error,
	prompt func(Prompt) error,
) (*oauth2.Token, error) {
	if oauthConfig.Endpoint.AuthURL == "" || oauthConfig.Endpoint.TokenURL == "" {
		return nil, errors.New("oidcauth: provider does not support authorization-code login")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("oidcauth: listen for authorization response: %w", err)
	}
	defer listener.Close()
	oauthConfig.RedirectURL = "http://" + listener.Addr().String() + "/callback"
	state, err := randomValue()
	if err != nil {
		return nil, err
	}
	verifier := oauth2.GenerateVerifier()
	authorizationURL := oauthConfig.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.S256ChallengeOption(verifier),
	)
	code := make(chan string, 1)
	callbackError := make(chan error, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Query().Get("state") != state {
			http.Error(response, "OIDC login failed", http.StatusBadRequest)
			return
		}
		if request.URL.Query().Get("error") != "" || request.URL.Query().Get("code") == "" {
			http.Error(response, "OIDC login failed", http.StatusBadRequest)
			select {
			case callbackError <- errors.New("oidcauth: invalid authorization response"):
			default:
			}
			return
		}
		_, _ = io.WriteString(response, "OIDC login complete. You can close this window.\n")
		select {
		case code <- request.URL.Query().Get("code"):
		default:
		}
	})
	callbackServer := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	serveError := make(chan error, 1)
	go func() {
		err := callbackServer.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		serveError <- err
	}()
	defer callbackServer.Close()
	if err := writePrompt(output, prompt, Prompt{URL: authorizationURL}); err != nil {
		return nil, err
	}
	if openURL != nil {
		_ = openURL(authorizationURL)
	}
	var authorizationCode string
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case err := <-serveError:
		return nil, fmt.Errorf("oidcauth: serve authorization response: %w", err)
	case err := <-callbackError:
		return nil, err
	case authorizationCode = <-code:
	}
	token, err := oauthConfig.Exchange(ctx, authorizationCode, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, fmt.Errorf("oidcauth: exchange authorization code: %w", err)
	}
	return token, nil
}

func writePrompt(output io.Writer, render func(Prompt) error, prompt Prompt) error {
	if render != nil {
		return render(prompt)
	}
	if prompt.Code == "" {
		_, err := fmt.Fprintf(output, "Open %s\n", prompt.URL)
		return err
	}
	_, err := fmt.Fprintf(output, "Open %s\nCode: %s\n", prompt.URL, prompt.Code)
	return err
}

func verifiedResult(
	ctx context.Context,
	provider *oidc.Provider,
	clientID, nonce, loginFlow string,
	token *oauth2.Token,
) (Result, error) {
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" || len(rawIDToken) > 16384 {
		return Result{}, errors.New("oidcauth: provider did not return an ID token")
	}
	identity, err := verifyToken(ctx, provider, clientID, rawIDToken)
	if err != nil {
		return Result{}, err
	}
	if identity.Nonce != nonce &&
		(loginFlow == LoginFlowAuthorizationCodePKCE || identity.Nonce != "") {
		return Result{}, errors.New("oidcauth: invalid ID token nonce")
	}
	return Result{IDToken: rawIDToken, Identity: identity}, nil
}

func randomValue() (string, error) {
	var material [32]byte
	if _, err := rand.Read(material[:]); err != nil {
		return "", fmt.Errorf("oidcauth: generate random value: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(material[:]), nil
}

func validScopes(scopes []string) bool {
	if len(scopes) == 0 || len(scopes) > 32 {
		return false
	}
	seen := make(map[string]struct{}, len(scopes))
	hasOpenID := false
	for _, scope := range scopes {
		if scope == oidc.ScopeOpenID {
			hasOpenID = true
		}
		if len(scope) == 0 || len(scope) > 128 || strings.TrimSpace(scope) != scope || strings.ContainsAny(scope, " \t\r\n") {
			return false
		}
		if _, exists := seen[scope]; exists {
			return false
		}
		seen[scope] = struct{}{}
	}
	return hasOpenID
}
