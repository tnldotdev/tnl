// Package clientauth owns CLI authentication and serialized control-session refresh.
package clientauth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/authorityclient"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/oidcauth"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/serverclient"
	"github.com/tnldotdev/tnl/pkg/protocol/authorityv1"
	"github.com/tnldotdev/tnl/pkg/protocol/serverv1"
)

const refreshSafetyMargin = 30 * time.Second

type Config struct {
	ServerEndpoint  string
	State           *clientstate.Database
	AccessToken     string
	HTTPClient      *http.Client
	Diagnostics     io.Writer
	OpenURL         func(string) error
	LoginToken      func() (credentials.LoginToken, error)
	ForceLogin      bool
	ForceLoginToken bool
}

type Client struct {
	ServerEndpoint        string
	Kind                  clientstate.ControlSessionKind
	ServerCapabilities    serverv1.Capabilities
	AuthorityCapabilities *authorityv1.Capabilities
	Server                *serverclient.Client
	Authority             *authorityclient.Client
}

type control struct {
	serverEndpoint        string
	kind                  clientstate.ControlSessionKind
	controlEndpoint       string
	serverCapabilities    serverv1.Capabilities
	authorityCapabilities *authorityv1.Capabilities
	rawHTTP               *http.Client
	rawServer             *serverclient.Client
	rawAuthority          *authorityclient.Client
}

func Authenticate(ctx context.Context, config Config) (*Client, error) {
	if config.Diagnostics == nil {
		return nil, errors.New("clientauth: diagnostics output is required")
	}
	resolved, err := resolveControl(ctx, config.ServerEndpoint, config.HTTPClient)
	if err != nil {
		return nil, err
	}
	if config.ForceLoginToken && resolved.kind == clientstate.ControlSessionKindAuthorizationAuthority {
		return nil, errors.New("authorization authority does not support login-token authentication")
	}
	source := &tokenSource{control: resolved, config: config}
	if config.AccessToken != "" {
		if err := validateExplicitToken(resolved.kind, config.AccessToken); err != nil {
			return nil, err
		}
		source.explicit = config.AccessToken
	} else {
		if config.State == nil {
			return nil, errors.New("clientauth: client state is required")
		}
		source.store, err = config.State.Server(ctx, resolved.serverEndpoint)
		if err != nil {
			return nil, err
		}
		if _, err := source.accessToken(ctx, config.ForceLogin, ""); err != nil {
			return nil, err
		}
		if err := config.State.SaveServer(ctx, resolved.serverEndpoint); err != nil {
			return nil, err
		}
	}

	authenticatedHTTP := authenticatedClient(resolved.rawHTTP, source)
	result := &Client{
		ServerEndpoint: resolved.serverEndpoint, Kind: resolved.kind,
		ServerCapabilities: resolved.serverCapabilities, AuthorityCapabilities: resolved.authorityCapabilities,
	}
	if resolved.kind == clientstate.ControlSessionKindServer {
		result.Server, err = serverclient.NewExternallyAuthenticated(resolved.serverEndpoint, authenticatedHTTP)
	} else {
		result.Server = resolved.rawServer
		result.Authority, err = authorityclient.New(resolved.controlEndpoint, authenticatedHTTP)
	}
	if err != nil {
		return nil, err
	}
	return result, nil
}

func Logout(ctx context.Context, config Config) error {
	resolved, err := resolveControl(ctx, config.ServerEndpoint, config.HTTPClient)
	if err != nil {
		return err
	}
	if config.State == nil {
		return errors.New("clientauth: client state is required")
	}
	store, err := config.State.Server(ctx, resolved.serverEndpoint)
	if err != nil {
		return err
	}
	lock, err := clientstate.LockControlSessionContext(ctx, store)
	if err != nil {
		return err
	}
	defer lock.Close()
	stored, found, err := store.ControlSession(ctx)
	if err != nil {
		return err
	}
	if !found {
		return errors.New("no saved login")
	}
	if !sessionMatches(stored, resolved) {
		return errors.New("saved login does not match the selected server authentication authority")
	}
	if err := revokeSession(ctx, resolved, stored, store); err != nil &&
		!errors.Is(err, serverclient.ErrUnauthenticated) && !errors.Is(err, authorityclient.ErrUnauthenticated) {
		return err
	}
	return store.RemoveControlSession(ctx)
}

func resolveControl(ctx context.Context, serverEndpoint string, httpClient *http.Client) (control, error) {
	serverEndpoint, err := clientstate.CanonicalServer(serverEndpoint)
	if err != nil {
		return control{}, err
	}
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	server, err := serverclient.New(serverEndpoint, httpClient, "")
	if err != nil {
		return control{}, err
	}
	capabilities, err := server.Capabilities(ctx)
	if err != nil {
		return control{}, fmt.Errorf("read server capabilities: %w", err)
	}
	resolved := control{
		serverEndpoint: serverEndpoint, kind: clientstate.ControlSessionKindServer, controlEndpoint: serverEndpoint,
		serverCapabilities: capabilities, rawHTTP: httpClient, rawServer: server,
	}
	if capabilities.AuthorizationAuthorityEndpoint == nil {
		if capabilities.Authentication.Required != serverv1.True ||
			authenticationMethodAvailable(capabilities, serverv1.Oidc) != (capabilities.Oidc != nil) ||
			!hasHostnameAuthorization(capabilities, serverv1.LocalHostnames) {
			return control{}, errors.New("clientauth: server returned inconsistent local authentication capabilities")
		}
		return resolved, nil
	}
	authorityEndpoint, err := clientstate.CanonicalServer(*capabilities.AuthorizationAuthorityEndpoint)
	if err != nil || authorityEndpoint != *capabilities.AuthorizationAuthorityEndpoint ||
		!hasHostnameAuthorization(capabilities, serverv1.SignedAuthorization) {
		return control{}, errors.New("clientauth: server returned an invalid authorization authority endpoint")
	}
	authority, err := authorityclient.New(authorityEndpoint, httpClient)
	if err != nil {
		return control{}, err
	}
	authorityCapabilities, err := authority.Capabilities(ctx)
	if err != nil {
		return control{}, fmt.Errorf("read authorization authority capabilities: %w", err)
	}
	if err := validateAuthorityCapabilities(capabilities, authorityCapabilities); err != nil {
		return control{}, err
	}
	resolved.kind = clientstate.ControlSessionKindAuthorizationAuthority
	resolved.controlEndpoint = authorityEndpoint
	resolved.authorityCapabilities = &authorityCapabilities
	resolved.rawAuthority = authority
	return resolved, nil
}

type tokenSource struct {
	mu       sync.Mutex
	control  control
	config   Config
	store    *clientstate.Store
	explicit string
}

func (s *tokenSource) accessToken(ctx context.Context, force bool, usedToken string) (string, error) {
	if s.explicit != "" {
		return s.explicit, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, err := clientstate.LockControlSessionContext(ctx, s.store)
	if err != nil {
		return "", err
	}
	defer lock.Close()
	stored, found, err := s.store.ControlSession(ctx)
	if err != nil {
		return "", err
	}
	if found && !sessionMatches(stored, s.control) {
		return "", errors.New("saved login does not match the selected server authentication authority")
	}
	now := time.Now()
	if found && !s.config.ForceLogin && (!force || usedToken != stored.AccessToken) &&
		stored.AccessExpiresAt.After(now.Add(refreshSafetyMargin)) {
		return stored.AccessToken, nil
	}
	if found && !s.config.ForceLogin && refreshUsable(stored, now) {
		refreshed, refreshErr := refreshSession(ctx, s.control, stored)
		if refreshErr == nil {
			if err := s.store.SaveControlSession(ctx, refreshed); err != nil {
				return "", err
			}
			return refreshed.AccessToken, nil
		}
		if force {
			return "", refreshErr
		}
		if !refreshRejected(refreshErr) {
			return "", refreshErr
		}
	}
	issued, err := s.login(ctx)
	if err != nil {
		return "", err
	}
	if found {
		if err := revokeSession(ctx, s.control, stored, s.store); err != nil &&
			!errors.Is(err, serverclient.ErrUnauthenticated) && !errors.Is(err, authorityclient.ErrUnauthenticated) {
			_ = revokeSession(ctx, s.control, issued, nil)
			return "", fmt.Errorf("revoke previous control session: %w", err)
		}
	}
	if err := s.store.SaveControlSession(ctx, issued); err != nil {
		_ = revokeSession(ctx, s.control, issued, nil)
		return "", err
	}
	s.config.ForceLogin = false
	return issued.AccessToken, nil
}

func (s *tokenSource) login(ctx context.Context) (clientstate.ControlSession, error) {
	if s.control.kind == clientstate.ControlSessionKindAuthorizationAuthority {
		capabilities := s.control.authorityCapabilities.Oidc
		scopes := authorityScopes(capabilities.Scopes)
		result, err := oidcauth.Login(ctx, oidcauth.Config{
			Issuer: capabilities.Issuer, ClientID: string(capabilities.ClientId),
			LoginFlow: oidcauth.LoginFlowDeviceCode, Scopes: scopes,
			HTTPClient: s.control.rawHTTP, OpenURL: s.config.OpenURL,
		}, s.config.Diagnostics)
		if err != nil {
			return clientstate.ControlSession{}, err
		}
		sessionID := result.SessionID
		if sessionID == "" {
			sessionID, err = randomSessionID()
			if err != nil {
				return clientstate.ControlSession{}, err
			}
		}
		return clientstate.ControlSession{
			Kind:            clientstate.ControlSessionKindAuthorizationAuthority,
			ControlEndpoint: s.control.controlEndpoint, SessionID: sessionID,
			Issuer: result.Issuer, ClientID: result.ClientID,
			AccessToken: result.AccessToken, AccessExpiresAt: result.AccessExpiresAt,
			RefreshToken: result.RefreshToken, RefreshExpiresAt: result.RefreshExpiresAt, Scopes: scopes,
		}, nil
	}

	capabilities := s.control.serverCapabilities
	useOIDC := authenticationMethodAvailable(capabilities, serverv1.Oidc) && !s.config.ForceLoginToken
	if useOIDC {
		if capabilities.Oidc == nil {
			return clientstate.ControlSession{}, errors.New("clientauth: server returned inconsistent OIDC capabilities")
		}
		result, err := oidcauth.Login(ctx, oidcauth.Config{
			Issuer: capabilities.Oidc.Issuer, ClientID: capabilities.Oidc.ClientId,
			LoginFlow: string(capabilities.Oidc.LoginFlow), Scopes: []string{"openid"},
			HTTPClient: s.control.rawHTTP, OpenURL: s.config.OpenURL,
		}, s.config.Diagnostics)
		if err != nil {
			return clientstate.ControlSession{}, err
		}
		issued, err := s.control.rawServer.ExchangeOIDC(ctx, result.IDToken)
		if err != nil {
			return clientstate.ControlSession{}, fmt.Errorf("exchange OIDC login: %w", err)
		}
		stored, err := serverSession(issued, "", time.Time{})
		if err != nil {
			return clientstate.ControlSession{}, err
		}
		stored.ControlEndpoint = s.control.serverEndpoint
		stored.Issuer, stored.ClientID = result.Issuer, result.ClientID
		return stored, nil
	}
	if !authenticationMethodAvailable(capabilities, serverv1.LoginToken) {
		return clientstate.ControlSession{}, errors.New("clientauth: server does not support an available interactive authentication method")
	}
	if s.config.LoginToken == nil {
		return clientstate.ControlSession{}, errors.New("login-token authentication requires an interactive terminal")
	}
	loginToken, err := s.config.LoginToken()
	if err != nil {
		return clientstate.ControlSession{}, err
	}
	issued, err := s.control.rawServer.Exchange(ctx, loginToken)
	if err != nil {
		return clientstate.ControlSession{}, fmt.Errorf("exchange login token: %w", err)
	}
	stored, err := serverSession(issued, "", time.Time{})
	if err != nil {
		return clientstate.ControlSession{}, err
	}
	stored.ControlEndpoint, stored.Issuer = s.control.serverEndpoint, s.control.serverEndpoint
	return stored, nil
}

func refreshSession(
	ctx context.Context,
	resolved control,
	stored clientstate.ControlSession,
) (clientstate.ControlSession, error) {
	if resolved.kind == clientstate.ControlSessionKindServer {
		issued, err := resolved.rawServer.Refresh(ctx, credentials.RefreshToken(stored.RefreshToken))
		if err != nil {
			return clientstate.ControlSession{}, err
		}
		refreshed, err := serverSession(issued, stored.SessionID, stored.RefreshExpiresAt)
		if err != nil {
			return clientstate.ControlSession{}, err
		}
		refreshed.ControlEndpoint = stored.ControlEndpoint
		refreshed.Issuer, refreshed.ClientID = stored.Issuer, stored.ClientID
		return refreshed, nil
	}
	issued, err := resolved.rawAuthority.RefreshOAuth(ctx, stored.Issuer, stored.ClientID, stored.RefreshToken)
	if err != nil {
		return clientstate.ControlSession{}, err
	}
	if issued.SessionID != "" && issued.SessionID != stored.SessionID {
		return clientstate.ControlSession{}, errors.New("authorization authority changed the OAuth session ID during refresh")
	}
	refreshExpiry := issued.RefreshExpiresAt
	if refreshExpiry.IsZero() {
		refreshExpiry = stored.RefreshExpiresAt
	}
	return clientstate.ControlSession{
		Kind: stored.Kind, ControlEndpoint: stored.ControlEndpoint, SessionID: stored.SessionID,
		Issuer: stored.Issuer, ClientID: stored.ClientID,
		AccessToken: issued.AccessToken, AccessExpiresAt: issued.AccessExpiresAt,
		RefreshToken: issued.RefreshToken, RefreshExpiresAt: refreshExpiry,
		Scopes: append([]string(nil), stored.Scopes...),
	}, nil
}

func revokeSession(
	ctx context.Context,
	resolved control,
	stored clientstate.ControlSession,
	store *clientstate.Store,
) error {
	if stored.Kind == clientstate.ControlSessionKindAuthorizationAuthority {
		return resolved.rawAuthority.RevokeOAuth(ctx, stored.Issuer, stored.ClientID, stored.RefreshToken)
	}
	err := resolved.rawServer.LogoutWithAccessToken(ctx, credentials.AccessToken(stored.AccessToken))
	if !errors.Is(err, serverclient.ErrUnauthenticated) || !refreshUsable(stored, time.Now()) {
		return err
	}
	refreshed, refreshErr := refreshSession(ctx, resolved, stored)
	if refreshErr != nil {
		return refreshErr
	}
	if store != nil {
		if err := store.SaveControlSession(ctx, refreshed); err != nil {
			return err
		}
	}
	return resolved.rawServer.LogoutWithAccessToken(ctx, credentials.AccessToken(refreshed.AccessToken))
}

func serverSession(
	response serverv1.ControlSessionResponse,
	expectedSessionID string,
	expectedRefreshExpiry time.Time,
) (clientstate.ControlSession, error) {
	stored, err := serverclient.ValidateControlSessionResponse(response, expectedSessionID, expectedRefreshExpiry)
	if err != nil {
		return clientstate.ControlSession{}, err
	}
	stored.Kind = clientstate.ControlSessionKindServer
	return stored, nil
}

func sessionMatches(stored clientstate.ControlSession, resolved control) bool {
	if stored.Kind != resolved.kind || stored.ControlEndpoint != resolved.controlEndpoint {
		return false
	}
	if resolved.kind == clientstate.ControlSessionKindAuthorizationAuthority {
		capabilities := resolved.authorityCapabilities.Oidc
		return stored.Issuer == capabilities.Issuer && stored.ClientID == string(capabilities.ClientId) &&
			equalScopes(stored.Scopes, authorityScopes(capabilities.Scopes))
	}
	return true
}

func refreshUsable(session clientstate.ControlSession, now time.Time) bool {
	return session.RefreshExpiresAt.IsZero() || session.RefreshExpiresAt.After(now)
}

func refreshRejected(err error) bool {
	if errors.Is(err, serverclient.ErrUnauthenticated) || errors.Is(err, authorityclient.ErrUnauthenticated) {
		return true
	}
	var problem *authorityclient.ProblemError
	return errors.As(err, &problem) && (problem.Status == http.StatusBadRequest || problem.Status == http.StatusUnauthorized)
}

type bearerTransport struct {
	base   http.RoundTripper
	source *tokenSource
}

func authenticatedClient(base *http.Client, source *tokenSource) *http.Client {
	copy := *base
	transport := base.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	copy.Transport = &bearerTransport{base: transport, source: source}
	return &copy
}

func (t *bearerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Scheme+"://"+request.URL.Host != t.source.control.controlEndpoint {
		return nil, errors.New("clientauth: refused to send credentials to an unexpected origin")
	}
	if request.Header.Get("Authorization") != "" {
		return t.base.RoundTrip(request)
	}
	token, err := t.source.accessToken(request.Context(), false, "")
	if err != nil {
		return nil, err
	}
	first, err := authenticatedRequest(request, token)
	if err != nil {
		return nil, err
	}
	response, err := t.base.RoundTrip(first)
	if err != nil || t.source.explicit != "" || !qualifyingUnauthorized(response) {
		return response, err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
	_ = response.Body.Close()
	refreshed, err := t.source.accessToken(request.Context(), true, token)
	if err != nil {
		return nil, err
	}
	retry, err := authenticatedRequest(request, refreshed)
	if err != nil {
		return nil, err
	}
	return t.base.RoundTrip(retry)
}

func authenticatedRequest(request *http.Request, token string) (*http.Request, error) {
	copy := request.Clone(request.Context())
	copy.Header = request.Header.Clone()
	if request.Body != nil {
		if request.GetBody == nil {
			return nil, errors.New("clientauth: authenticated request body cannot be replayed")
		}
		body, err := request.GetBody()
		if err != nil {
			return nil, err
		}
		copy.Body = body
	}
	copy.Header.Set("Authorization", "Bearer "+token)
	return copy, nil
}

func qualifyingUnauthorized(response *http.Response) bool {
	if response == nil || response.StatusCode != http.StatusUnauthorized {
		return false
	}
	challenge := strings.TrimSpace(response.Header.Get("WWW-Authenticate"))
	return strings.EqualFold(challenge, "Bearer") || strings.HasPrefix(strings.ToLower(challenge), "bearer ")
}

func validateExplicitToken(kind clientstate.ControlSessionKind, token string) error {
	if kind == clientstate.ControlSessionKindServer {
		if _, _, err := credentials.ParseAccessToken(credentials.AccessToken(token)); err != nil {
			return errors.New("invalid access token")
		}
		return nil
	}
	if len(token) == 0 || len(token) > 16<<10 || strings.TrimSpace(token) != token || strings.ContainsAny(token, " \t\r\n") {
		return errors.New("invalid OAuth access token")
	}
	return nil
}

func validateAuthorityCapabilities(
	server serverv1.Capabilities,
	authority authorityv1.Capabilities,
) error {
	publicKey, keyErr := base64.RawURLEncoding.DecodeString(authority.AuthorizationKey.PublicKey)
	if authority.AuthenticationRequired != authorityv1.CapabilitiesAuthenticationRequiredTrue ||
		authority.Oidc.GrantType != authorityv1.DeviceCode || authority.Oidc.ClientId != authorityv1.TnlCli ||
		authority.Oidc.Issuer == "" || authority.AuthorizationKey.Alg != authorityv1.AuthorizationKeyAlgEdDSA ||
		authority.AuthorizationKey.Kid == "" || len(authority.AuthorizationKey.Kid) > 128 || keyErr != nil ||
		len(publicKey) != 32 || base64.RawURLEncoding.EncodeToString(publicKey) != authority.AuthorizationKey.PublicKey ||
		authority.AuthorizationIssuer == "" || authority.HostnameSuffix != server.HostnameSuffix ||
		int(authority.HostnamePolicy.MaximumSubdomainDepth) != server.MaximumSubdomainDepth ||
		bool(authority.HostnamePolicy.TemporaryNameSupport) != server.TemporaryNameSupport ||
		bool(authority.HostnamePolicy.PersistentBaseSupport) != server.PersistentBaseSupport ||
		bool(authority.HostnamePolicy.CustomDomainSupport) != server.CustomDomainSupport ||
		!validAuthorityScopes(authority.Oidc.Scopes) {
		return errors.New("authorization authority capabilities do not match server")
	}
	return nil
}

func equalScopes(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for _, scope := range left {
		if !slices.Contains(right, scope) {
			return false
		}
	}
	return true
}

func validAuthorityScopes(scopes []authorityv1.OIDCCapabilitiesScopes) bool {
	want := []authorityv1.OIDCCapabilitiesScopes{
		authorityv1.Openid, authorityv1.OfflineAccess, authorityv1.Product, authorityv1.Operations,
	}
	if len(scopes) != len(want) {
		return false
	}
	for _, scope := range want {
		if !slices.Contains(scopes, scope) {
			return false
		}
	}
	return true
}

func hasHostnameAuthorization(capabilities serverv1.Capabilities, value serverv1.CapabilitiesHostnameAuthorization) bool {
	return slices.Contains(capabilities.HostnameAuthorization, value)
}

func authenticationMethodAvailable(
	capabilities serverv1.Capabilities,
	method serverv1.AuthenticationCapabilitiesMethods,
) bool {
	return slices.Contains(capabilities.Authentication.Methods, method)
}

func authorityScopes(values []authorityv1.OIDCCapabilitiesScopes) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = string(value)
	}
	return result
}

func randomSessionID() (string, error) {
	id, err := opaqueid.New("oauth_session_")
	if err != nil {
		return "", fmt.Errorf("clientauth: generate OAuth session ID: %w", err)
	}
	return id, nil
}
