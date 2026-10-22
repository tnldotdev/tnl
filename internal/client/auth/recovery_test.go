package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/failure"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

func TestDeviceIssuedCancellationRevokesSessionAfterPollingCredentialExpires(t *testing.T) {
	issued := issuedSession(t)
	logoutCalls := 0
	f := newAuthFixture(t, func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/v1/auth/device/poll":
			return jsonResponse(200, authorityv1.DeviceLoginResult{Status: authorityv1.DeviceLoginResultStatusApproved, Session: &issued}), nil
		case "/v1/auth/device/cancel":
			return problemResponse(401, "unauthenticated"), nil
		case "/v1/auth/logout":
			logoutCalls++
			if logoutCalls == 1 {
				return problemResponse(503, "unavailable"), nil
			}
			return &http.Response{StatusCode: 204, Body: http.NoBody}, nil
		default:
			return nil, errors.New("unexpected request")
		}
	})
	op, err := StartLogin(t.Context(), f.config)
	if err != nil {
		t.Fatal(err)
	}
	due(t, f, op.ID)
	// stop the real waiter after it persists the issued checkpoint, before install.
	original := f.transport.respond
	discoveries := 0
	f.transport.respond = func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/v1/discovery" {
			discoveries++
			if discoveries == 2 {
				return nil, context.Canceled
			}
		}
		return original(r)
	}
	if _, err := WaitLogin(t.Context(), f.config, op.ID, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	op, err = f.store.AuthOperation(t.Context(), op.ID)
	if err != nil {
		t.Fatal(err)
	}
	var checkpoint loginCheckpoint
	if err := json.Unmarshal(op.Private, &checkpoint); err != nil {
		t.Fatal(err)
	}
	if op.Phase != clientstate.AuthIssued || checkpoint.PollingCredential == "" || checkpoint.Session == nil {
		t.Fatal("fixture did not reach the actual issued checkpoint")
	}
	if _, err := CancelLogin(t.Context(), f.config, op.ID); err == nil {
		t.Fatal("session revocation failure was hidden")
	}
	op, err = f.store.AuthOperation(t.Context(), op.ID)
	if err != nil || len(op.Private) == 0 {
		t.Fatal("issued session was forgotten before revocation", err)
	}
	if _, err := CancelLogin(t.Context(), f.config, op.ID); err != nil {
		t.Fatal(err)
	}
	op, err = f.store.AuthOperation(t.Context(), op.ID)
	if err != nil || len(op.Private) != 0 || logoutCalls != 2 {
		t.Fatalf("cleanup logout calls=%d: %v", logoutCalls, err)
	}
}

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
			f.config.ObserveLogin = func(clientstate.AuthOperation) error { t.Error("ordinary authentication prompted"); return nil }
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
	op, err := beginOperation(t.Context(), f.store, "device_code")
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
			op, err := beginOperation(t.Context(), f.store, "device_code")
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
	op, err := beginOperation(t.Context(), f.store, "device_code")
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
