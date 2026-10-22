package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/failure"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

func assertReason(t *testing.T, err error, want failure.Reason) {
	t.Helper()
	if got, _ := failure.ReasonOf(err); got != want {
		t.Fatalf("reason=%s want=%s: %v", got, want, err)
	}
}

func deviceChallenge() authorityv1.DeviceLoginChallenge {
	return authorityv1.DeviceLoginChallenge{PollingCredential: strings.Repeat("p", 43), ApprovalUrl: testControlOrigin + "/v1/auth/device/approve?code=ABCDEFGHIJKLM", UserCode: "ABCDEFGHIJKLM", ExpiresAt: time.Now().Add(10 * time.Minute), IntervalSeconds: 1}
}

func due(t *testing.T, f *authFixture, id string) {
	t.Helper()
	op, err := f.store.AuthOperation(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	op.NextPollAt = time.Now().Add(-time.Second)
	if err := f.store.UpdateAuthOperation(t.Context(), &op); err != nil {
		t.Fatal(err)
	}
}

func TestDeviceLoginResumeAfterLostPollResponse(t *testing.T) {
	issued := issuedSession(t)
	lost := errors.New("response lost")
	polls := 0
	f := newAuthFixture(t, func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/v1/auth/device":
			return jsonResponse(201, deviceChallenge()), nil
		case "/v1/auth/device/poll":
			polls++
			if polls == 1 {
				return nil, lost
			}
			return jsonResponse(200, authorityv1.DeviceLoginResult{Status: authorityv1.DeviceLoginResultStatusApproved, Session: &issued}), nil
		default:
			return nil, errors.New("unexpected request")
		}
	})
	op, err := StartLogin(t.Context(), f.config)
	if err != nil {
		t.Fatal(err)
	}
	due(t, f, op.ID)
	if _, err := WaitLogin(t.Context(), f.config, op.ID, time.Second); !errors.Is(err, lost) {
		t.Fatal(err)
	}
	db, err := clientstate.Open(t.Context(), f.root)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	config := f.config
	config.State = db
	op, err = WaitLogin(t.Context(), config, op.ID, time.Second)
	if err != nil || op.Phase != clientstate.AuthCompleted || polls != 2 {
		t.Fatalf("resume: %s polls=%d %v", op.Phase, polls, err)
	}
	f.assertSession(t, storedSession(issued))
}

func TestDeviceStartTimeoutInspectAndCancellation(t *testing.T) {
	cancelCalls := 0
	f := newAuthFixture(t, func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/v1/auth/device":
			return jsonResponse(201, deviceChallenge()), nil
		case "/v1/auth/device/cancel":
			cancelCalls++
			return &http.Response{StatusCode: 204, Body: http.NoBody}, nil
		default:
			return nil, errors.New("unexpected request")
		}
	})
	op, err := StartLogin(t.Context(), f.config)
	if err != nil {
		t.Fatal(err)
	}
	joined, err := StartLogin(t.Context(), f.config)
	if err != nil || joined.ID != op.ID {
		t.Fatal("start did not reuse pending challenge", err)
	}
	_, err = WaitLogin(t.Context(), f.config, op.ID, 10*time.Millisecond)
	assertReason(t, err, failure.AuthWaitTimeout)
	op, err = InspectLogin(t.Context(), f.config, op.ID)
	if err != nil || op.Phase != clientstate.AuthPending {
		t.Fatal(err)
	}
	public, err := json.Marshal(op)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(public), strings.Repeat("p", 43)) {
		t.Fatal("poll credential leaked in inspect")
	}
	op, err = CancelLogin(t.Context(), f.config, op.ID)
	if err != nil || op.Phase != clientstate.AuthCancelled || cancelCalls != 1 {
		t.Fatalf("cancel: %s calls=%d %v", op.Phase, cancelCalls, err)
	}
	_, err = WaitLogin(t.Context(), f.config, op.ID, time.Second)
	assertReason(t, err, failure.AuthCancelled)
}

func TestDeviceCancellationRetriesPrivateCleanup(t *testing.T) {
	calls := 0
	unavailable := errors.New("control unavailable")
	f := newAuthFixture(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/v1/auth/device" {
			return jsonResponse(201, deviceChallenge()), nil
		}
		if r.URL.Path == "/v1/auth/device/cancel" {
			calls++
			if calls == 1 {
				return nil, unavailable
			}
			return &http.Response{StatusCode: 204, Body: http.NoBody}, nil
		}
		return nil, errors.New("unexpected request")
	})
	op, err := StartLogin(t.Context(), f.config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CancelLogin(t.Context(), f.config, op.ID); !errors.Is(err, unavailable) {
		t.Fatal(err)
	}
	if _, err := CancelLogin(t.Context(), f.config, op.ID); err != nil || calls != 2 {
		t.Fatalf("cancel cleanup retry: %d %v", calls, err)
	}
	op, err = InspectLogin(t.Context(), f.config, op.ID)
	if err != nil || len(op.Private) != 0 {
		t.Fatal("cancelled credential was not erased", err)
	}
}

func TestRecoveryRequiredDeviceOperationCanBeCancelled(t *testing.T) {
	issued := issuedSession(t)
	issued.RefreshToken = "invalid"
	cancelled := false
	f := newAuthFixture(t, func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/v1/auth/device":
			return jsonResponse(201, deviceChallenge()), nil
		case "/v1/auth/device/poll":
			return jsonResponse(200, authorityv1.DeviceLoginResult{Status: authorityv1.DeviceLoginResultStatusApproved, Session: &issued}), nil
		case "/v1/auth/device/cancel":
			cancelled = true
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
	_, err = WaitLogin(t.Context(), f.config, op.ID, time.Second)
	assertReason(t, err, failure.AuthRecoveryRequired)
	op, err = CancelLogin(t.Context(), f.config, op.ID)
	if err != nil || !cancelled || op.Phase != clientstate.AuthCancelled || len(op.Private) != 0 {
		t.Fatalf("cancel recovery: %s %v", op.Phase, err)
	}
}

func TestDeviceTeamSelectionAndInstallation(t *testing.T) {
	issued := issuedSession(t)
	issued.Identity = authorityv1.IdentityContext{DefaultTeamId: new("tm_selected"), Memberships: []authorityv1.Membership{{TeamId: "tm_selected"}}}
	starts := 0
	f := newAuthFixture(t, func(r *http.Request) (*http.Response, error) {
		switch r.URL.Path {
		case "/v1/auth/device/poll":
			return jsonResponse(200, authorityv1.DeviceLoginResult{Status: authorityv1.DeviceLoginResultStatusApproved, Session: &issued}), nil
		case "/v1/auth/device/cancel":
			return &http.Response{StatusCode: 204, Body: http.NoBody}, nil
		default:
			return nil, errors.New("unexpected request")
		}
	})
	original := f.transport.respond
	f.transport.respond = func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/v1/auth/device" {
			var body authorityv1.StartDeviceLoginRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				return nil, err
			}
			if body.Team == nil || *body.Team != f.config.Team {
				t.Error("team selection not sent to control")
			}
			starts++
			return jsonResponse(201, deviceChallenge()), nil
		}
		return original(r)
	}
	f.config.Team = "first"
	op, err := StartLogin(t.Context(), f.config)
	if err != nil {
		t.Fatal(err)
	}
	f.config.Team = "second"
	next, err := StartLogin(t.Context(), f.config)
	if err != nil || op.ID == next.ID || starts != 2 {
		t.Fatalf("selection reused another team's attempt: %v", err)
	}
	due(t, f, next.ID)
	if _, err := WaitLogin(t.Context(), f.config, next.ID, time.Second); err != nil {
		t.Fatal(err)
	}
	selected, found, err := f.store.SelectedTeam(t.Context())
	if err != nil || !found || selected != "tm_selected" {
		t.Fatalf("selected immutable team: %q %v", selected, err)
	}
}
