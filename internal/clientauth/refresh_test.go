package clientauth

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/authorityclient"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

func TestConcurrentRefreshSerializesAndReusesRotatedToken(t *testing.T) {
	for _, independent := range []bool{false, true} {
		name := "one token source"
		if independent {
			name = "independent SQLite handles"
		}
		t.Run(name, func(t *testing.T) {
			old := storedSession(issuedSession(t))
			rotated := issuedSession(t)
			rotated.RefreshExpiresAt = old.RefreshExpiresAt
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			f := newAuthFixture(t, func(request *http.Request) (*http.Response, error) {
				if request.URL.Path != "/v1/auth/refresh" {
					return nil, errors.New("unexpected request")
				}
				once.Do(func() { close(entered) })
				select {
				case <-release:
					return jsonResponse(200, rotated), nil
				case <-request.Context().Done():
					return nil, request.Context().Err()
				}
			})
			f.save(t, old)
			first := f.source(t)
			second := first
			if independent {
				db, err := clientstate.Open(t.Context(), f.root)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := db.Close(); err != nil {
						t.Error(err)
					}
				})
				store, err := db.Server(t.Context(), testControlOrigin)
				if err != nil {
					t.Fatal(err)
				}
				second = &tokenSource{control: first.control, config: f.config, store: store}
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			var workers sync.WaitGroup
			defer func() { cancel(); workers.Wait() }()
			type result struct {
				token string
				err   error
			}
			results := make(chan result, 8)
			started := make(chan struct{}, 8)
			start := func(source *tokenSource) {
				workers.Add(1)
				go func() {
					defer workers.Done()
					started <- struct{}{}
					token, err := source.accessToken(ctx, true, old.AccessToken)
					results <- result{token, err}
				}()
			}
			start(first)
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal("refresh did not start")
			}
			// keep the network call inside the persisted-session lock so a competing
			// process cannot rotate the same refresh token concurrently.
			lock, err := f.store.LockControlSession()
			if lock != nil {
				_ = lock.Close()
			}
			if !errors.Is(err, clientstate.ErrLocked) {
				t.Fatalf("refresh does not own state lock: %v", err)
			}
			for range 7 {
				start(second)
			}
			// every contender has started while the first refresh is gated.
			for range 8 {
				select {
				case <-started:
				case <-ctx.Done():
					t.Fatal("refresh contenders did not start")
				}
			}
			close(release)
			for range 8 {
				select {
				case result := <-results:
					if result.err != nil || result.token != rotated.AccessToken {
						t.Fatalf("refresh failed or returned an old token: %v", result.err)
					}
				case <-ctx.Done():
					t.Fatal("refresh workers did not finish")
				}
			}
			// a delayed 401 for the old token must reuse the persisted rotation too.
			if token, err := second.accessToken(ctx, true, old.AccessToken); err != nil || token != rotated.AccessToken {
				t.Fatalf("delayed refresh: %v", err)
			}
			f.assertSession(t, storedSession(rotated))
			requests := f.transport.snapshot()
			if len(requests) != 2 {
				t.Fatalf("requests=%d, want discovery and exactly one refresh", len(requests))
			}
			assertAuthRequest(t, requests[1], http.MethodPost, testAuthorityOrigin+"/v1/auth/refresh", "", authorityv1.RefreshControlSessionRequest{RefreshToken: old.RefreshToken})
		})
	}
}

func TestRefreshWaitingForPersistedLockCanBeCanceled(t *testing.T) {
	f := newAuthFixture(t, func(*http.Request) (*http.Response, error) { return nil, errors.New("unexpected request") })
	old := storedSession(issuedSession(t))
	f.save(t, old)
	source := f.source(t)
	lock, err := f.store.LockControlSession()
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	token, err := source.accessToken(ctx, true, old.AccessToken)
	if token != "" || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled refresh: token returned=%v error=%v", token != "", err)
	}
	if len(f.transport.snapshot()) != 1 {
		t.Fatal("canceled waiter sent credentials")
	}
	f.assertSession(t, old)
}

func TestRefreshWaitingForTokenSourceCanBeCanceled(t *testing.T) {
	old := storedSession(issuedSession(t))
	rotated := issuedSession(t)
	rotated.RefreshExpiresAt = old.RefreshExpiresAt
	entered, release := make(chan struct{}), make(chan struct{})
	f := newAuthFixture(t, func(request *http.Request) (*http.Response, error) {
		if request.URL.Path != "/v1/auth/refresh" {
			return nil, errors.New("unexpected request")
		}
		close(entered)
		select {
		case <-release:
			return jsonResponse(http.StatusOK, rotated), nil
		case <-request.Context().Done():
			return nil, request.Context().Err()
		}
	})
	f.save(t, old)
	source := f.source(t)
	first := make(chan error, 1)
	go func() {
		_, err := source.accessToken(t.Context(), true, old.AccessToken)
		first <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("first refresh did not start")
	}
	waiterCtx, cancel := context.WithCancel(t.Context())
	waiter := make(chan error, 1)
	go func() {
		_, err := source.accessToken(waiterCtx, true, old.AccessToken)
		waiter <- err
	}()
	cancel()
	select {
	case err := <-waiter:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("contending refresh error = %v", err)
		}
	case <-time.After(time.Second):
		close(release)
		t.Fatal("contending refresh did not honor cancellation")
	}
	if len(f.transport.snapshot()) != 2 {
		close(release)
		t.Fatal("contending refresh sent a request")
	}
	close(release)
	select {
	case err := <-first:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("first refresh did not finish")
	}
}

func TestForcedRefreshFailureNeverPromptsOrChangesSession(t *testing.T) {
	for _, test := range []struct {
		name    string
		status  int
		invalid bool
		want    error
	}{
		{"rejected", 401, false, authorityclient.ErrUnauthenticated},
		{"transient", 503, false, authorityclient.ErrUnavailable},
		{"invalid issued identity", 200, true, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			old := storedSession(issuedSession(t))
			issued := issuedSession(t)
			issued.SessionId = "control_session_abcdef0123456789abcdef0123456789"
			f := newAuthFixture(t, func(*http.Request) (*http.Response, error) {
				if test.invalid {
					return jsonResponse(200, issued), nil
				}
				return problemResponse(test.status, "unauthenticated"), nil
			})
			f.save(t, old)
			prompts := 0
			f.config.LoginToken = func() (credentials.LoginToken, error) { prompts++; return "", errors.New("unexpected login") }
			source := f.source(t)
			token, err := source.accessToken(t.Context(), true, old.AccessToken)
			if token != "" || err == nil || test.want != nil && !errors.Is(err, test.want) || prompts != 0 {
				t.Fatalf("refresh: token returned=%v prompts=%d error=%v", token != "", prompts, err)
			}
			f.assertSession(t, old)
			if len(f.transport.snapshot()) != 2 {
				t.Fatal("unexpected retry or login")
			}
		})
	}
}
