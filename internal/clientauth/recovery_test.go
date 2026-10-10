package clientauth

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/failure"
)

func TestOrdinaryAuthenticationNeverPromptsForMissingOrExpiredCredentials(t *testing.T) {
	for _, saved := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing", true: "expired"}[saved], func(t *testing.T) {
			f := newAuthFixture(t, func(*http.Request) (*http.Response, error) {
				t.Error("ordinary authentication initiated an exchange")
				return nil, errors.New("unexpected exchange")
			})
			if saved {
				old := storedSession(issuedSession(t))
				old.AccessExpiresAt = time.Now().Add(-time.Hour)
				old.RefreshExpiresAt = time.Now().Add(-time.Minute)
				f.save(t, old)
			}
			f.config.LoginToken = func() (credentials.LoginToken, error) { t.Error("ordinary authentication prompted"); return "", nil }
			f.config.OpenURL = func(string) error { t.Error("ordinary authentication opened a browser"); return nil }
			f.config.Diagnostics = nil
			_, err := Authenticate(t.Context(), f.config)
			assertReason(t, err, failure.Authentication)
			if len(f.transport.snapshot()) != 1 {
				t.Fatal("ordinary authentication performed more than discovery")
			}
		})
	}
}

func TestUncertainRefreshIsNeverReplayed(t *testing.T) {
	lost := errors.New("refresh response lost")
	refreshes := 0
	f := newAuthFixture(t, func(r *http.Request) (*http.Response, error) { refreshes++; return nil, lost })
	old := storedSession(issuedSession(t))
	old.AccessExpiresAt = time.Now().Add(-time.Hour)
	f.save(t, old)
	_, err := Authenticate(t.Context(), f.config)
	assertReason(t, err, failure.AuthRecoveryRequired)
	if !errors.Is(err, lost) {
		t.Fatal("refresh cause lost")
	}
	_, err = Authenticate(t.Context(), f.config)
	assertReason(t, err, failure.AuthRecoveryRequired)
	if refreshes != 1 {
		t.Fatal("uncertain refresh was replayed")
	}
	status, err := Status(t.Context(), f.config, false)
	if err != nil || status.Status != "recovery_required" {
		t.Fatalf("status=%s, %v", status.Status, err)
	}
}

func TestIssuedCheckpointCanInstallWithoutAnotherExchange(t *testing.T) {
	f := newAuthFixture(t, func(r *http.Request) (*http.Response, error) {
		t.Error("issued checkpoint attempted a token exchange")
		return nil, errors.New("unexpected request")
	})
	op, err := beginOperation(t.Context(), f.store, "login_token")
	if err != nil {
		t.Fatal(err)
	}
	session := storedSession(issuedSession(t))
	if err := checkpoint(t.Context(), f.store, &op, clientstate.AuthIssued, loginCheckpoint{Session: &session}); err != nil {
		t.Fatal(err)
	}
	completed, err := WaitLogin(t.Context(), f.config, op.ID, time.Second)
	if err != nil || completed.Phase != clientstate.AuthCompleted {
		t.Fatalf("wait=%s, %v", completed.Phase, err)
	}
	f.assertSession(t, session)
	if len(f.transport.snapshot()) != 1 {
		t.Fatal("issued checkpoint was replayed")
	}
}

func TestCancelAndLogoutRevokeIdleIssuedCheckpoint(t *testing.T) {
	for _, logout := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "logout"}[logout], func(t *testing.T) {
			calls := 0
			f := newAuthFixture(t, func(r *http.Request) (*http.Response, error) {
				if r.URL.Path != "/v1/auth/logout" {
					return nil, errors.New("unexpected request")
				}
				calls++
				if calls == 1 {
					return problemResponse(503, "unavailable"), nil
				}
				return &http.Response{StatusCode: 204, Body: http.NoBody}, nil
			})
			op, err := beginOperation(t.Context(), f.store, "login_token")
			if err != nil {
				t.Fatal(err)
			}
			session := storedSession(issuedSession(t))
			if err := checkpoint(t.Context(), f.store, &op, clientstate.AuthIssued, loginCheckpoint{Session: &session}); err != nil {
				t.Fatal(err)
			}
			cancel := func() error {
				if logout {
					return Logout(t.Context(), f.config)
				}
				_, err := CancelLogin(t.Context(), f.config, op.ID)
				return err
			}
			if err := cancel(); err == nil {
				t.Fatal("revocation failure was hidden")
			}
			stored, err := f.store.AuthOperation(t.Context(), op.ID)
			if err != nil || stored.Phase != clientstate.AuthCancelled || len(stored.Private) == 0 {
				t.Fatalf("revocation checkpoint=%s, %v", stored.Phase, err)
			}
			if _, err := WaitLogin(t.Context(), f.config, op.ID, time.Second); err == nil {
				t.Fatal("cancelled issued credential installed")
			}
			if err := cancel(); err != nil {
				t.Fatal(err)
			}
			stored, err = f.store.AuthOperation(t.Context(), op.ID)
			if err != nil || len(stored.Private) != 0 || calls != 2 {
				t.Fatalf("revocation cleanup=%d, %v", calls, err)
			}
		})
	}
}

func TestCancelledCredentialDoesNotReplayUncertainRefresh(t *testing.T) {
	refreshes := 0
	lost := errors.New("cancelled-session refresh response lost")
	f := newAuthFixture(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/v1/auth/logout" {
			return problemResponse(401, "unauthenticated"), nil
		}
		if r.URL.Path == "/v1/auth/refresh" {
			refreshes++
			return nil, lost
		}
		return nil, errors.New("unexpected request")
	})
	op, err := beginOperation(t.Context(), f.store, "login_token")
	if err != nil {
		t.Fatal(err)
	}
	session := storedSession(issuedSession(t))
	session.AccessExpiresAt = time.Now().Add(-time.Minute)
	if err := checkpoint(t.Context(), f.store, &op, clientstate.AuthIssued, loginCheckpoint{Session: &session}); err != nil {
		t.Fatal(err)
	}
	_, err = CancelLogin(t.Context(), f.config, op.ID)
	assertReason(t, err, failure.AuthRecoveryRequired)
	if !errors.Is(err, lost) {
		t.Fatal("refresh cause lost")
	}
	_, err = CancelLogin(t.Context(), f.config, op.ID)
	assertReason(t, err, failure.AuthRecoveryRequired)
	if refreshes != 1 {
		t.Fatal("cancelled session replayed a one-time refresh")
	}
}
