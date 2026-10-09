package clientauth

import (
	"context"
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
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/oidcauth"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"golang.org/x/oauth2"
)

const (
	refreshSafetyMargin            = 30 * time.Second
	defaultInteractiveLoginTimeout = 10 * time.Minute
	issuedSessionCleanupTimeout    = 5 * time.Second
)

var ErrAuthenticationTimeout = errors.New("clientauth: authentication timed out")

type Config struct {
	ServerEndpoint       string
	State                *clientstate.Database
	AccessToken          string
	HTTPClient           *http.Client
	Diagnostics          io.Writer
	OpenURL              func(string) error
	LoginToken           func() (credentials.LoginToken, error)
	AuthenticationPrompt func(oidcauth.Prompt) error
	ObserveLogin         func(clientstate.AuthOperation) error
	ForceLoginToken      bool
	LoginFlow            string
	LoginTimeout         time.Duration
}

type Client struct {
	ServerEndpoint string
	Discovery      controlv1.ControlDiscovery
	Control        *controlclient.Client
	Authority      *authorityclient.Client
}

type control struct {
	serverEndpoint string
	discovery      controlv1.ControlDiscovery
	rawHTTP        *http.Client
	rawAuthority   *authorityclient.Client
}

func Authenticate(ctx context.Context, config Config) (*Client, error) {
	resolved, err := resolveControl(ctx, config.ServerEndpoint, config.HTTPClient)
	if err != nil {
		return nil, err
	}
	source := &tokenSource{control: resolved, config: config}
	if config.AccessToken != "" {
		if err := validateExplicitToken(config.AccessToken); err != nil {
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
		if _, err := source.accessToken(ctx, false, ""); err != nil {
			return nil, err
		}
	}
	return authenticatedResult(resolved, source)
}

func authenticatedResult(resolved control, source *tokenSource) (*Client, error) {
	authenticatedHTTP := authenticatedClient(resolved.rawHTTP, source)
	result := &Client{ServerEndpoint: resolved.serverEndpoint, Discovery: resolved.discovery}
	var err error
	result.Control, err = controlclient.NewExternallyAuthenticated(resolved.serverEndpoint, authenticatedHTTP)
	if err != nil {
		return nil, err
	}
	result.Authority, err = authorityclient.New(resolved.serverEndpoint, authenticatedHTTP, "")
	if err != nil {
		return nil, err
	}
	return result, nil
}

func Logout(ctx context.Context, config Config) error {
	server, err := clientstate.CanonicalServer(config.ServerEndpoint)
	if err != nil {
		return err
	}
	if config.State == nil {
		return errors.New("clientauth: client state is required")
	}
	store, err := config.State.Server(ctx, server)
	if err != nil {
		return err
	}
	lock, err := clientstate.LockControlSessionContext(ctx, store)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := store.FenceAuthOperations(ctx); err != nil {
		return err
	}
	stored, found, err := store.ControlSession(ctx)
	removeErr := store.RemoveControlSession(ctx)
	_ = lock.Close()
	cleanupErr := cleanupCancelledOperations(ctx, config, store)
	if err != nil || removeErr != nil {
		return errors.Join(err, removeErr, cleanupErr)
	}
	if !found {
		return cleanupErr
	}
	resolved, err := resolveControl(ctx, server, config.HTTPClient)
	if err != nil {
		return errors.Join(err, cleanupErr)
	}
	if err := revokeSession(ctx, resolved, stored, nil); err != nil &&
		!errors.Is(err, controlclient.ErrUnauthenticated) && !errors.Is(err, authorityclient.ErrUnauthenticated) {
		return errors.Join(err, cleanupErr)
	}
	return cleanupErr
}

func resolveControl(ctx context.Context, serverEndpoint string, httpClient *http.Client) (control, error) {
	serverEndpoint, err := clientstate.CanonicalServer(serverEndpoint)
	if err != nil {
		return control{}, err
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 20 * time.Second}
	}
	controlClient, err := controlclient.New(serverEndpoint, httpClient, "")
	if err != nil {
		return control{}, err
	}
	discovery, err := controlClient.Discovery(ctx)
	if err != nil {
		return control{}, fmt.Errorf("read control discovery: %w", err)
	}
	authority, err := authorityclient.New(serverEndpoint, httpClient, "")
	if err != nil {
		return control{}, err
	}
	if len(discovery.Authentication.Methods) == 0 ||
		authenticationMethodAvailable(discovery, controlv1.Oidc) != (discovery.Authentication.Oidc != nil) {
		return control{}, errors.New("clientauth: control returned inconsistent authentication facts")
	}
	resolved := control{
		serverEndpoint: serverEndpoint,
		discovery:      discovery, rawHTTP: httpClient, rawAuthority: authority,
	}
	return resolved, nil
}

type tokenSource struct {
	serializeOnce sync.Once
	serialize     chan struct{}
	control       control
	config        Config
	store         *clientstate.Store
	explicit      string
}

func (s *tokenSource) accessToken(ctx context.Context, force bool, usedToken string) (string, error) {
	if s.explicit != "" {
		return s.explicit, nil
	}
	if err := s.lock(ctx); err != nil {
		return "", err
	}
	defer s.unlock()
	lock, err := clientstate.LockControlSessionContext(ctx, s.store)
	if err != nil {
		return "", err
	}
	defer lock.Close()
	stored, found, err := s.store.ControlSession(ctx)
	if err != nil {
		return "", err
	}
	now := time.Now()
	if found && stored.RefreshPending {
		return "", failure.Wrap("recover control session refresh", failure.AuthRecoveryRequired, errors.New("a previous refresh has an uncertain outcome"))
	}
	if found && (!force || usedToken != stored.AccessToken) &&
		stored.AccessExpiresAt.After(now.Add(refreshSafetyMargin)) {
		return stored.AccessToken, nil
	}
	if found && refreshUsable(stored, now) {
		refreshed, refreshErr := protectedRefresh(ctx, s.control, stored, s.store)
		if refreshErr == nil {
			if err := s.store.SaveControlSession(ctx, refreshed); err != nil {
				return "", failure.Wrap("save refreshed control session", failure.AuthRecoveryRequired, err)
			}
			return refreshed.AccessToken, nil
		}
		if !refreshRejected(refreshErr) {
			return "", refreshErr
		}
		return "", failure.Wrap("refresh control session", failure.Authentication, refreshErr)
	}
	return "", failure.Wrap("read control session", failure.Authentication, authorityclient.ErrUnauthenticated)
}

// protectedRefresh checkpoints the single-use refresh credential before sending
// it. a lost response must never cause a later command to replay that credential.
func protectedRefresh(ctx context.Context, resolved control, stored clientstate.ControlSession, store *clientstate.Store) (clientstate.ControlSession, error) {
	if stored.RefreshPending {
		return clientstate.ControlSession{}, failure.Wrap("recover control session refresh", failure.AuthRecoveryRequired, errors.New("refresh outcome is uncertain"))
	}
	if err := store.SetControlSessionRefreshPending(ctx, true); err != nil {
		return clientstate.ControlSession{}, err
	}
	refreshed, err := refreshSession(ctx, resolved, stored)
	if err == nil {
		return refreshed, nil
	}
	if definiteRefreshFailure(err) {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), issuedSessionCleanupTimeout)
		defer cancel()
		return clientstate.ControlSession{}, errors.Join(err, store.SetControlSessionRefreshPending(cleanupCtx, false))
	}
	return clientstate.ControlSession{}, failure.Wrap("refresh control session", failure.AuthRecoveryRequired, err)
}

func definiteRefreshFailure(err error) bool {
	var problem *authorityclient.ProblemError
	var limited *authorityclient.RateLimitError
	return errors.As(err, &problem) || err == authorityclient.ErrUnauthenticated || err == authorityclient.ErrUnavailable || errors.As(err, &limited)
}

func (s *tokenSource) lock(ctx context.Context) error {
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	s.serializeOnce.Do(func() { s.serialize = make(chan struct{}, 1) })
	select {
	case s.serialize <- struct{}{}:
		if cause := context.Cause(ctx); cause != nil {
			s.unlock()
			return cause
		}
		return nil
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

func (s *tokenSource) unlock() {
	<-s.serialize
}

func (s *tokenSource) login(ctx context.Context, beforeRedeem ...func() error) (clientstate.ControlSession, error) {
	var before func() error
	if len(beforeRedeem) != 0 {
		before = beforeRedeem[0]
	}
	discovery := s.control.discovery
	useOIDC := authenticationMethodAvailable(discovery, controlv1.Oidc) && !s.config.ForceLoginToken
	if useOIDC {
		if discovery.Authentication.Oidc == nil {
			return clientstate.ControlSession{}, errors.New("clientauth: control returned inconsistent OIDC authentication facts")
		}
		oidc := discovery.Authentication.Oidc
		flow := string(oidc.LoginFlow)
		if s.config.LoginFlow != "" {
			flow = s.config.LoginFlow
		}
		timeout := s.config.LoginTimeout
		if timeout == 0 {
			timeout = defaultInteractiveLoginTimeout
		}
		loginCtx, cancel := context.WithTimeout(ctx, timeout)
		result, err := oidcauth.Login(loginCtx, oidcauth.Config{
			Issuer: oidc.Issuer, ClientID: oidc.ClientId,
			LoginFlow: flow, Scopes: slices.Clone(oidc.Scopes),
			HTTPClient: s.control.rawHTTP, OpenURL: s.config.OpenURL, Prompt: s.config.AuthenticationPrompt,
			BeforeRedeem: before,
		}, s.config.Diagnostics)
		cancel()
		if err != nil {
			if interactiveAuthenticationTimedOut(ctx, err) {
				return clientstate.ControlSession{}, fmt.Errorf("%w: %w", ErrAuthenticationTimeout, err)
			}
			return clientstate.ControlSession{}, err
		}
		if before != nil {
			if err := before(); err != nil {
				return clientstate.ControlSession{}, err
			}
		}
		issued, err := s.control.rawAuthority.ExchangeOIDC(ctx, result.IDToken)
		if err != nil {
			return clientstate.ControlSession{}, fmt.Errorf("exchange OIDC login: %w", err)
		}
		stored, err := authoritySession(issued, "", time.Time{})
		if err != nil {
			return clientstate.ControlSession{}, err
		}
		return stored, nil
	}
	if !authenticationMethodAvailable(discovery, controlv1.LoginToken) {
		return clientstate.ControlSession{}, errors.New("clientauth: authority does not support an available interactive authentication method")
	}
	if s.config.LoginToken == nil {
		return clientstate.ControlSession{}, failure.Wrap("read login token", failure.LoginTerminalRequired, errors.New("login-token authentication requires an interactive terminal"))
	}
	loginToken, err := s.config.LoginToken()
	if err != nil {
		return clientstate.ControlSession{}, err
	}
	if before != nil {
		if err := before(); err != nil {
			return clientstate.ControlSession{}, err
		}
	}
	issued, err := s.control.rawAuthority.Exchange(ctx, loginToken)
	if err != nil {
		return clientstate.ControlSession{}, fmt.Errorf("exchange login token: %w", err)
	}
	stored, err := authoritySession(issued, "", time.Time{})
	if err != nil {
		return clientstate.ControlSession{}, err
	}
	return stored, nil
}

func interactiveAuthenticationTimedOut(ctx context.Context, err error) bool {
	if ctx.Err() != nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var retrieval *oauth2.RetrieveError
	return errors.As(err, &retrieval) && retrieval.ErrorCode == "expired_token"
}

func refreshSession(
	ctx context.Context,
	resolved control,
	stored clientstate.ControlSession,
) (clientstate.ControlSession, error) {
	issued, err := resolved.rawAuthority.Refresh(ctx, credentials.RefreshToken(stored.RefreshToken))
	if err != nil {
		return clientstate.ControlSession{}, err
	}
	refreshed, err := authoritySession(issued, stored.SessionID, stored.RefreshExpiresAt)
	if err != nil {
		return clientstate.ControlSession{}, err
	}
	return refreshed, nil
}

func revokeSession(
	ctx context.Context,
	resolved control,
	stored clientstate.ControlSession,
	store *clientstate.Store,
) error {
	err := resolved.rawAuthority.LogoutWithAccessToken(ctx, credentials.AccessToken(stored.AccessToken))
	if !errors.Is(err, authorityclient.ErrUnauthenticated) || stored.RefreshPending || !refreshUsable(stored, time.Now()) {
		return err
	}
	var refreshed clientstate.ControlSession
	var refreshErr error
	if store == nil {
		refreshed, refreshErr = refreshSession(ctx, resolved, stored)
	} else {
		refreshed, refreshErr = protectedRefresh(ctx, resolved, stored, store)
	}
	if refreshErr != nil {
		return refreshErr
	}
	if store != nil {
		if err := store.SaveControlSession(ctx, refreshed); err != nil {
			return err
		}
	}
	return resolved.rawAuthority.LogoutWithAccessToken(ctx, credentials.AccessToken(refreshed.AccessToken))
}

func cleanupIssuedSession(ctx context.Context, resolved control, issued clientstate.ControlSession) error {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), issuedSessionCleanupTimeout)
	defer cancel()
	err := revokeSession(cleanupCtx, resolved, issued, nil)
	if err == nil || errors.Is(err, controlclient.ErrUnauthenticated) || errors.Is(err, authorityclient.ErrUnauthenticated) {
		return nil
	}
	return fmt.Errorf("revoke newly issued control session: %w", err)
}

func authoritySession(
	response authorityv1.ControlSessionResponse,
	expectedSessionID string,
	expectedRefreshExpiry time.Time,
) (clientstate.ControlSession, error) {
	stored, err := authorityclient.ValidateControlSessionResponse(response, expectedSessionID, expectedRefreshExpiry)
	if err != nil {
		return clientstate.ControlSession{}, err
	}
	return stored, nil
}

func refreshUsable(session clientstate.ControlSession, now time.Time) bool {
	return session.RefreshExpiresAt.IsZero() || session.RefreshExpiresAt.After(now)
}

func refreshRejected(err error) bool {
	if errors.Is(err, controlclient.ErrUnauthenticated) || errors.Is(err, authorityclient.ErrUnauthenticated) {
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
	origin := request.URL.Scheme + "://" + request.URL.Host
	if origin != t.source.control.serverEndpoint {
		if request.Body != nil {
			_ = request.Body.Close()
		}
		return nil, errors.New("clientauth: refused to send credentials to an unexpected origin")
	}
	if request.Header.Get("Authorization") != "" {
		return t.base.RoundTrip(request)
	}
	if request.Body != nil {
		defer request.Body.Close()
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

func validateExplicitToken(token string) error {
	if _, _, err := credentials.ParseAccessToken(credentials.AccessToken(token)); err != nil {
		return errors.New("invalid access token")
	}
	return nil
}

func authenticationMethodAvailable(
	discovery controlv1.ControlDiscovery,
	method controlv1.AuthenticationFactsMethods,
) bool {
	return slices.Contains(discovery.Authentication.Methods, method)
}
