package clientauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/tnldotdev/tnl/internal/authorityclient"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/oidcauth"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"golang.org/x/oauth2"
)

type loginCheckpoint struct {
	Issuer    string
	ClientID  string
	Scopes    []string
	Challenge oidcauth.DeviceChallenge
	Assertion string
	Session   *clientstate.ControlSession
}

func (p loginCheckpoint) config(httpConfig Config) oidcauth.Config {
	return oidcauth.Config{Issuer: p.Issuer, ClientID: p.ClientID, Scopes: p.Scopes, HTTPClient: httpConfig.HTTPClient}
}

func authStore(ctx context.Context, config Config) (*clientstate.Store, error) {
	if config.State == nil {
		return nil, errors.New("client state is required")
	}
	return config.State.Server(ctx, config.ServerEndpoint)
}

func operationError(op clientstate.AuthOperation) error {
	var reason failure.Reason
	switch op.Phase {
	case clientstate.AuthCancelled:
		reason = failure.AuthCancelled
	case clientstate.AuthDenied:
		reason = failure.AuthDenied
	case clientstate.AuthExpired:
		reason = failure.AuthExpired
	case clientstate.AuthRecoveryRequired:
		reason = failure.AuthRecoveryRequired
	default:
		return nil
	}
	return failure.Wrap("complete login operation", reason, errors.New(string(op.Phase)))
}

func readOperation(ctx context.Context, store *clientstate.Store, id string) (clientstate.AuthOperation, error) {
	op, err := store.AuthOperation(ctx, id)
	if errors.Is(err, clientstate.ErrAuthOperationNotFound) {
		err = failure.Wrap("read login operation", failure.AuthOperationNotFound, err)
	}
	return op, err
}

// StartLogin returns immediately after creating a durable device challenge.
func StartLogin(ctx context.Context, config Config) (clientstate.AuthOperation, error) {
	resolved, err := resolveControl(ctx, config.ServerEndpoint, config.HTTPClient)
	if err != nil {
		return clientstate.AuthOperation{}, err
	}
	facts := resolved.discovery.Authentication.Oidc
	if facts == nil || facts.LoginFlow != controlv1.DeviceCode || config.ForceLoginToken {
		return clientstate.AuthOperation{}, failure.Wrap("start device login", failure.AuthMethodUnavailable, errors.New("device login is unavailable"))
	}
	config.ServerEndpoint = resolved.serverEndpoint
	store, err := authStore(ctx, config)
	if err != nil {
		return clientstate.AuthOperation{}, err
	}
	op, operationLock, created, err := startOperation(ctx, store, "device_code", true)
	if err != nil {
		return op, err
	}
	defer operationLock.Close()
	if !created {
		return op, operationError(op)
	}
	p := loginCheckpoint{Issuer: facts.Issuer, ClientID: facts.ClientId, Scopes: facts.Scopes}
	if err := checkpoint(ctx, store, &op, clientstate.AuthRedeeming, p); err != nil {
		return op, err
	}
	p.Challenge, err = oidcauth.StartDevice(ctx, p.config(config))
	if err != nil {
		return op, finishOperation(ctx, store, &op, clientstate.AuthRecoveryRequired, err)
	}
	op.ApprovalURL, op.UserCode, op.ExpiresAt, op.Interval = p.Challenge.ApprovalURL, p.Challenge.UserCode, p.Challenge.ExpiresAt, p.Challenge.Interval
	op.NextPollAt = time.Now().Add(op.Interval)
	if err := checkpoint(ctx, store, &op, clientstate.AuthPending, p); err != nil {
		return op, err
	}
	return op, nil
}

func beginOperation(ctx context.Context, store *clientstate.Store, method string) (clientstate.AuthOperation, error) {
	op, lock, _, err := startOperation(ctx, store, method, false)
	if lock != nil {
		defer lock.Close()
	}
	return op, err
}

// startOperation locks a new operation before publishing its initial state.
// joining callers release the credential lock before waiting for that operation.
func startOperation(ctx context.Context, store *clientstate.Store, method string, reuse bool) (clientstate.AuthOperation, *clientstate.Lock, bool, error) {
	id, err := clientstate.NewAuthOperationID()
	if err != nil {
		return clientstate.AuthOperation{}, nil, false, err
	}
	op := clientstate.AuthOperation{ID: id, Method: method, Phase: clientstate.AuthPending, ExpiresAt: time.Now().Add(defaultInteractiveLoginTimeout), Revision: 1}
	operationLock, err := clientstate.LockAuthOperationContext(ctx, store, id)
	if err != nil {
		return op, nil, false, err
	}
	lock, err := clientstate.LockControlSessionContext(ctx, store)
	if err != nil {
		_ = operationLock.Close()
		return op, nil, false, err
	}
	defer lock.Close()
	if reuse {
		current, found, err := store.ActiveAuthOperation(ctx)
		if err != nil {
			_ = operationLock.Close()
			return op, nil, false, err
		}
		if found && current.Method == method && (current.Phase != clientstate.AuthPending || current.ExpiresAt.After(time.Now())) {
			_ = operationLock.Close()
			// a published challenge remains readable while a separate waiter polls;
			// start must not wait for that command to finish.
			if current.UserCode != "" {
				return current, nil, false, nil
			}
			if err := lock.Close(); err != nil {
				return current, nil, false, err
			}
			joined, err := clientstate.LockAuthOperationContext(ctx, store, current.ID)
			if err != nil {
				return current, nil, false, err
			}
			current, err = store.AuthOperation(ctx, current.ID)
			if err != nil {
				_ = joined.Close()
				return current, nil, false, err
			}
			return current, joined, false, nil
		}
	}
	if err := store.FenceAuthOperations(ctx); err != nil {
		_ = operationLock.Close()
		return op, nil, false, err
	}
	err = store.CreateAuthOperation(ctx, op)
	if err == nil {
		op, err = store.AuthOperation(ctx, id)
	}
	if err != nil {
		_ = operationLock.Close()
		return op, nil, false, err
	}
	return op, operationLock, true, nil
}

func checkpoint(ctx context.Context, store *clientstate.Store, op *clientstate.AuthOperation, phase clientstate.AuthPhase, p loginCheckpoint) error {
	bytes, err := json.Marshal(p)
	if err != nil {
		return err
	}
	op.Phase, op.Private = phase, bytes
	op.IntervalSeconds = int64(op.Interval / time.Second)
	err = store.UpdateAuthOperation(ctx, op)
	if errors.Is(err, clientstate.ErrAuthOperationChanged) {
		current, readErr := readOperation(ctx, store, op.ID)
		if readErr != nil {
			return readErr
		}
		*op = current
		if terminal := operationError(current); terminal != nil {
			return terminal
		}
	}
	return err
}

func finishOperation(ctx context.Context, store *clientstate.Store, op *clientstate.AuthOperation, phase clientstate.AuthPhase, cause error) error {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), issuedSessionCleanupTimeout)
	defer cancel()
	op.Phase, op.Private = phase, nil
	if err := store.UpdateAuthOperation(cleanupCtx, op); err != nil {
		if errors.Is(err, clientstate.ErrAuthOperationChanged) {
			current, readErr := readOperation(cleanupCtx, store, op.ID)
			if readErr == nil {
				*op = current
				return errors.Join(operationError(current), cause)
			}
		}
		return errors.Join(operationError(*op), cause, err)
	}
	return errors.Join(operationError(*op), cause)
}

func InspectLogin(ctx context.Context, config Config, id string) (clientstate.AuthOperation, error) {
	store, err := authStore(ctx, config)
	if err != nil {
		return clientstate.AuthOperation{}, err
	}
	op, err := readOperation(ctx, store, id)
	if err == nil && op.Phase == clientstate.AuthPending && !op.ExpiresAt.After(time.Now()) {
		// expiration is a fact; avoid changing a checkpoint owned by a waiter.
		op.Phase = clientstate.AuthExpired
	}
	return op, err
}

func CancelLogin(ctx context.Context, config Config, id string) (clientstate.AuthOperation, error) {
	store, err := authStore(ctx, config)
	if err != nil {
		return clientstate.AuthOperation{}, err
	}
	lock, err := clientstate.LockControlSessionContext(ctx, store)
	if err != nil {
		return clientstate.AuthOperation{}, err
	}
	defer lock.Close()
	for {
		op, err := readOperation(ctx, store, id)
		if err != nil {
			return op, err
		}
		if op.Phase == clientstate.AuthCancelled {
			_ = lock.Close()
			return op, cleanupCancelledOperation(ctx, config, store, &op)
		}
		if op.Phase == clientstate.AuthCompleted || operationError(op) != nil {
			return op, nil
		}
		if op.Phase != clientstate.AuthIssued {
			op.Private = nil
		}
		op.Phase = clientstate.AuthCancelled
		err = store.UpdateAuthOperation(ctx, &op)
		if errors.Is(err, clientstate.ErrAuthOperationChanged) {
			continue
		}
		if err != nil {
			return op, err
		}
		_ = lock.Close()
		return op, cleanupCancelledOperation(ctx, config, store, &op)
	}
}

// cancelled issued credentials remain sealed until revocation succeeds, so
// cancelling an idle issued checkpoint does not orphan a control session.
func cleanupCancelledOperation(ctx context.Context, config Config, store *clientstate.Store, op *clientstate.AuthOperation) error {
	if len(op.Private) == 0 {
		return nil
	}
	lock, err := clientstate.LockAuthCleanupContext(ctx, store, op.ID)
	if err != nil {
		return err
	}
	defer lock.Close()
	current, err := store.AuthOperation(ctx, op.ID)
	if err != nil {
		return err
	}
	*op = current
	if len(op.Private) == 0 {
		return nil
	}
	var p loginCheckpoint
	if err := json.Unmarshal(op.Private, &p); err != nil {
		return err
	}
	if p.Session == nil {
		return nil
	}
	authority, err := authorityclient.New(op.Server, config.HTTPClient, "")
	if err != nil {
		return err
	}
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), issuedSessionCleanupTimeout)
	defer cancel()
	resolved := control{rawAuthority: authority}
	err = authority.LogoutWithAccessToken(cleanupCtx, credentials.AccessToken(p.Session.AccessToken))
	if errors.Is(err, authorityclient.ErrUnauthenticated) && refreshUsable(*p.Session, time.Now()) {
		if p.Session.RefreshPending {
			return failure.Wrap("recover cancelled session refresh", failure.AuthRecoveryRequired, err)
		}
		p.Session.RefreshPending = true
		if err := checkpoint(cleanupCtx, store, op, clientstate.AuthCancelled, p); err != nil {
			return err
		}
		refreshed, refreshErr := refreshSession(cleanupCtx, resolved, *p.Session)
		if refreshErr != nil {
			if definiteRefreshFailure(refreshErr) {
				p.Session.RefreshPending = false
				if persistErr := checkpoint(cleanupCtx, store, op, clientstate.AuthCancelled, p); persistErr != nil {
					return errors.Join(refreshErr, persistErr)
				}
			} else {
				return failure.Wrap("refresh cancelled control session", failure.AuthRecoveryRequired, refreshErr)
			}
			err = refreshErr
		} else {
			p.Session = &refreshed
			if err := checkpoint(cleanupCtx, store, op, clientstate.AuthCancelled, p); err != nil {
				return failure.Wrap("save cancelled session refresh", failure.AuthRecoveryRequired, err)
			}
			err = authority.LogoutWithAccessToken(cleanupCtx, credentials.AccessToken(refreshed.AccessToken))
		}
	}
	if err != nil && !errors.Is(err, authorityclient.ErrUnauthenticated) {
		return err
	}
	op.Private = nil
	err = store.UpdateAuthOperation(cleanupCtx, op)
	if errors.Is(err, clientstate.ErrAuthOperationChanged) {
		current, readErr := store.AuthOperation(ctx, op.ID)
		if readErr == nil && current.Phase == clientstate.AuthCancelled && len(current.Private) == 0 {
			*op = current
			return nil
		}
	}
	return err
}

func cleanupCancelledOperations(ctx context.Context, config Config, store *clientstate.Store) error {
	operations, err := store.CancelledAuthCredentials(ctx)
	if err != nil {
		return err
	}
	var failures []error
	for _, op := range operations {
		failures = append(failures, cleanupCancelledOperation(ctx, config, store, &op))
	}
	return errors.Join(failures...)
}

// WaitLogin joins one operation. its file lock is separate from credential
// refresh/install, and cancellation uses revision checks rather than this lock.
func WaitLogin(ctx context.Context, config Config, id string, timeout time.Duration) (result clientstate.AuthOperation, retErr error) {
	if timeout <= 0 {
		timeout = defaultInteractiveLoginTimeout
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	defer func() {
		if errors.Is(retErr, context.DeadlineExceeded) && ctx.Err() == nil {
			if reason, ok := failure.ReasonOf(retErr); !ok || reason != failure.AuthRecoveryRequired {
				retErr = failure.Wrap("wait for login approval", failure.AuthWaitTimeout, retErr)
			}
		}
	}()
	store, err := authStore(waitCtx, config)
	if err != nil {
		return result, err
	}
	lock, err := clientstate.LockAuthOperationContext(waitCtx, store, id)
	if errors.Is(err, clientstate.ErrAuthOperationNotFound) {
		return result, failure.Wrap("wait for login operation", failure.AuthOperationNotFound, err)
	}
	if err != nil {
		return result, err
	}
	defer lock.Close()
	for {
		op, err := readOperation(waitCtx, store, id)
		if err != nil {
			return result, err
		}
		result = op
		if err := operationError(op); err != nil {
			return op, err
		}
		if op.Phase == clientstate.AuthCompleted {
			return op, nil
		}
		if op.Phase == clientstate.AuthRedeeming || op.Phase == clientstate.AuthExchanging {
			return op, finishOperation(waitCtx, store, &op, clientstate.AuthRecoveryRequired, nil)
		}
		var p loginCheckpoint
		if err := json.Unmarshal(op.Private, &p); err != nil {
			return op, finishOperation(waitCtx, store, &op, clientstate.AuthRecoveryRequired, err)
		}
		switch op.Phase {
		case clientstate.AuthPending:
			if !op.ExpiresAt.After(time.Now()) {
				return op, finishOperation(waitCtx, store, &op, clientstate.AuthExpired, nil)
			}
			if delay := time.Until(op.NextPollAt); delay > 0 {
				if delay > 200*time.Millisecond {
					delay = 200 * time.Millisecond
				}
				timer := time.NewTimer(delay)
				select {
				case <-waitCtx.Done():
					timer.Stop()
					return op, context.Cause(waitCtx)
				case <-timer.C:
				}
				continue
			}
			if err := checkpoint(waitCtx, store, &op, clientstate.AuthRedeeming, p); err != nil {
				return op, err
			}
			assertion, pollErr := oidcauth.PollDevice(waitCtx, p.config(config), p.Challenge)
			var provider *oauth2.RetrieveError
			if errors.As(pollErr, &provider) {
				switch provider.ErrorCode {
				case "authorization_pending", "slow_down":
					if provider.ErrorCode == "slow_down" {
						op.Interval += 5 * time.Second
					}
					op.NextPollAt = time.Now().Add(op.Interval)
					persistCtx, stop := context.WithTimeout(context.WithoutCancel(waitCtx), issuedSessionCleanupTimeout)
					err := checkpoint(persistCtx, store, &op, clientstate.AuthPending, p)
					stop()
					if err != nil {
						return op, err
					}
					continue
				case "access_denied":
					return op, finishOperation(waitCtx, store, &op, clientstate.AuthDenied, pollErr)
				case "expired_token":
					return op, finishOperation(waitCtx, store, &op, clientstate.AuthExpired, pollErr)
				}
			}
			if pollErr != nil {
				return op, finishOperation(waitCtx, store, &op, clientstate.AuthRecoveryRequired, pollErr)
			}
			p.Assertion = assertion
			persistCtx, stop := context.WithTimeout(context.WithoutCancel(waitCtx), issuedSessionCleanupTimeout)
			err = checkpoint(persistCtx, store, &op, clientstate.AuthCredentialReceived, p)
			stop()
			if err != nil {
				return op, err
			}
		case clientstate.AuthCredentialReceived:
			if _, err := oidcauth.VerifyDevice(waitCtx, p.config(config), p.Challenge, p.Assertion); err != nil {
				if errors.Is(err, oidcauth.ErrUnavailable) {
					return op, failure.Wrap("verify login assertion", failure.AuthProviderUnavailable, err)
				}
				if errors.Is(err, oidcauth.ErrUnauthenticated) {
					return op, finishOperation(waitCtx, store, &op, clientstate.AuthDenied, err)
				}
				return op, err
			}
			resolved, err := resolveControl(waitCtx, config.ServerEndpoint, config.HTTPClient)
			if err != nil {
				return op, err
			}
			if err := checkpoint(waitCtx, store, &op, clientstate.AuthExchanging, p); err != nil {
				return op, err
			}
			issued, err := resolved.rawAuthority.ExchangeOIDC(waitCtx, p.Assertion)
			if err != nil {
				return op, finishOperation(waitCtx, store, &op, clientstate.AuthRecoveryRequired, err)
			}
			session, err := authoritySession(issued, "", time.Time{})
			if err != nil {
				return op, finishOperation(waitCtx, store, &op, clientstate.AuthRecoveryRequired, err)
			}
			p.Session, p.Assertion = &session, ""
			persistCtx, stop := context.WithTimeout(context.WithoutCancel(waitCtx), issuedSessionCleanupTimeout)
			err = checkpoint(persistCtx, store, &op, clientstate.AuthIssued, p)
			stop()
			if err != nil {
				return op, errors.Join(err, cleanupIssuedSession(waitCtx, resolved, session))
			}
		case clientstate.AuthIssued:
			if p.Session == nil {
				return op, finishOperation(waitCtx, store, &op, clientstate.AuthRecoveryRequired, nil)
			}
			resolved, err := resolveControl(waitCtx, config.ServerEndpoint, config.HTTPClient)
			if err != nil {
				return op, err
			}
			if err := installSession(waitCtx, store, &op, resolved, *p.Session); err != nil {
				return op, err
			}
			return op, nil
		default:
			return op, finishOperation(waitCtx, store, &op, clientstate.AuthRecoveryRequired, nil)
		}
	}
}

func installSession(ctx context.Context, store *clientstate.Store, op *clientstate.AuthOperation, resolved control, session clientstate.ControlSession) error {
	lock, err := clientstate.LockControlSessionContext(ctx, store)
	if err != nil {
		return err
	}
	defer lock.Close()
	current, err := readOperation(ctx, store, op.ID)
	if err != nil {
		return err
	}
	if current.Revision != op.Revision || operationError(current) != nil {
		return errors.Join(operationError(current), clientstate.ErrAuthOperationChanged, cleanupIssuedSession(ctx, resolved, session))
	}
	old, found, err := store.ControlSession(ctx)
	if err != nil {
		return err
	}
	if found {
		err = revokeSession(ctx, resolved, old, store)
		if err != nil && !errors.Is(err, authorityclient.ErrUnauthenticated) {
			return errors.Join(finishOperation(ctx, store, op, clientstate.AuthRecoveryRequired, err), cleanupIssuedSession(ctx, resolved, session))
		}
	}
	if err := store.InstallAuthSession(ctx, op, session); err != nil {
		return errors.Join(finishOperation(ctx, store, op, clientstate.AuthRecoveryRequired, err), cleanupIssuedSession(ctx, resolved, session))
	}
	return nil
}

// Login is explicit convenience authentication. device login uses the same
// durable operation as start/wait; self-host tokens and PKCE remain opt-in.
func Login(ctx context.Context, config Config) (*Client, error) {
	if config.Diagnostics == nil {
		config.Diagnostics = io.Discard
	}
	resolved, err := resolveControl(ctx, config.ServerEndpoint, config.HTTPClient)
	if err != nil {
		return nil, err
	}
	config.ServerEndpoint = resolved.serverEndpoint
	if facts := resolved.discovery.Authentication.Oidc; facts != nil && facts.LoginFlow == controlv1.DeviceCode && !config.ForceLoginToken && config.LoginFlow != oidcauth.LoginFlowAuthorizationCodePKCE {
		op, err := StartLogin(ctx, config)
		if err != nil {
			return nil, err
		}
		if config.ObserveLogin != nil {
			if err := config.ObserveLogin(op); err != nil {
				return nil, err
			}
		} else if op.Phase == clientstate.AuthPending && config.AuthenticationPrompt != nil {
			if err := config.AuthenticationPrompt(oidcauth.Prompt{URL: op.ApprovalURL, Code: op.UserCode}); err != nil {
				return nil, err
			}
		}
		if op.Phase == clientstate.AuthPending && config.OpenURL != nil {
			_ = config.OpenURL(op.ApprovalURL)
		}
		if _, err := WaitLogin(ctx, config, op.ID, config.LoginTimeout); err != nil {
			return nil, err
		}
	} else {
		store, err := authStore(ctx, config)
		if err != nil {
			return nil, err
		}
		method := "login_token"
		if resolved.discovery.Authentication.Oidc != nil && !config.ForceLoginToken {
			method = "authorization_code_pkce"
		}
		if method == "login_token" && !authenticationMethodAvailable(resolved.discovery, controlv1.LoginToken) {
			return nil, failure.Wrap("select login method", failure.AuthMethodUnavailable, errors.New("login token is unavailable"))
		}
		op, lock, _, err := startOperation(ctx, store, method, false)
		if err != nil {
			return nil, err
		}
		defer lock.Close()
		attempted := false
		beforeRedeem := func() error {
			if err := checkpoint(ctx, store, &op, clientstate.AuthRedeeming, loginCheckpoint{}); err != nil {
				return err
			}
			attempted = true
			return nil
		}
		source := tokenSource{control: resolved, config: config, store: store}
		session, err := source.login(ctx, beforeRedeem)
		if err != nil {
			var provider *oauth2.RetrieveError
			if errors.As(err, &provider) {
				switch provider.ErrorCode {
				case "access_denied":
					return nil, finishOperation(ctx, store, &op, clientstate.AuthDenied, err)
				case "expired_token":
					return nil, finishOperation(ctx, store, &op, clientstate.AuthExpired, err)
				}
			}
			if !attempted {
				cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), issuedSessionCleanupTimeout)
				defer cancel()
				op.Phase, op.Private = clientstate.AuthCancelled, nil
				return nil, errors.Join(err, store.UpdateAuthOperation(cleanupCtx, &op))
			}
			return nil, finishOperation(ctx, store, &op, clientstate.AuthRecoveryRequired, err)
		}
		if err := checkpoint(ctx, store, &op, clientstate.AuthIssued, loginCheckpoint{Session: &session}); err != nil {
			return nil, errors.Join(err, cleanupIssuedSession(ctx, resolved, session))
		}
		if err := installSession(ctx, store, &op, resolved, session); err != nil {
			return nil, err
		}
	}
	store, err := authStore(ctx, config)
	if err != nil {
		return nil, err
	}
	return authenticatedResult(resolved, &tokenSource{control: resolved, config: config, store: store})
}
