package clientauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/testutil/oidctest"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

const deviceIssuer = "https://identity.example"

type deviceFixture struct {
	*authFixture
	signer           *oidctest.Signer
	mu               sync.Mutex
	nonce, assertion string
	polls, exchanges int
	poll             func(*http.Request) (*http.Response, error)
	exchange         func(*http.Request) (*http.Response, error)
}

func newDeviceFixture(t *testing.T) *deviceFixture {
	t.Helper()
	d := &deviceFixture{signer: oidctest.NewSigner(t)}
	issued := issuedSession(t)
	d.authFixture = newAuthFixture(t, func(r *http.Request) (*http.Response, error) { return nil, errors.New("unexpected request") })
	d.transport.respond = func(r *http.Request) (*http.Response, error) {
		switch r.URL.String() {
		case testControlOrigin + "/v1/discovery":
			return jsonResponse(200, controlv1.ControlDiscovery{Authentication: controlv1.AuthenticationFacts{
				Methods: []controlv1.AuthenticationFactsMethods{controlv1.Oidc}, Oidc: &controlv1.OIDCAuthenticationFacts{Issuer: deviceIssuer, ClientId: "cli", LoginFlow: controlv1.DeviceCode, Scopes: []string{"openid"}},
			}}), nil
		case deviceIssuer + "/.well-known/openid-configuration":
			return jsonResponse(200, map[string]any{"issuer": deviceIssuer, "token_endpoint": deviceIssuer + "/token", "device_authorization_endpoint": deviceIssuer + "/device", "jwks_uri": deviceIssuer + "/keys"}), nil
		case deviceIssuer + "/keys":
			return jsonResponse(200, map[string]any{"keys": []any{d.signer.JWK("key")}}), nil
		case deviceIssuer + "/device":
			if err := r.ParseForm(); err != nil {
				return nil, err
			}
			d.mu.Lock()
			d.nonce = r.Form.Get("nonce")
			d.mu.Unlock()
			return jsonResponse(200, map[string]any{"device_code": "private-device-code", "user_code": "HUMAN-CODE", "verification_uri": deviceIssuer + "/approve", "expires_in": 600, "interval": 1}), nil
		case deviceIssuer + "/token":
			d.mu.Lock()
			d.polls++
			assertion, poll := d.assertion, d.poll
			d.mu.Unlock()
			if err := r.ParseForm(); err != nil {
				return nil, err
			}
			if r.Form.Get("device_code") != "private-device-code" || r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" {
				return nil, errors.New("bad device redemption request")
			}
			if poll != nil {
				return poll(r)
			}
			return jsonResponse(200, map[string]any{"id_token": assertion}), nil
		case testControlOrigin + "/v1/auth/oidc":
			d.mu.Lock()
			d.exchanges++
			exchange := d.exchange
			d.mu.Unlock()
			if exchange != nil {
				return exchange(r)
			}
			return jsonResponse(200, issued), nil
		case testControlOrigin + "/v1/auth/logout":
			return &http.Response{StatusCode: 204, Body: http.NoBody}, nil
		default:
			return nil, errors.New("unexpected request: " + r.URL.String())
		}
	}
	return d
}

func (d *deviceFixture) start(t *testing.T) clientstate.AuthOperation {
	t.Helper()
	op, err := StartLogin(t.Context(), d.config)
	if err != nil {
		t.Fatal(err)
	}
	if op.Phase != clientstate.AuthPending || op.IntervalSeconds != 1 || op.UserCode != "HUMAN-CODE" {
		t.Fatalf("start result = %#v", op)
	}
	d.mu.Lock()
	d.assertion = d.signer.Token(t, "key", map[string]any{"iss": deviceIssuer, "sub": "person", "aud": "cli", "nonce": d.nonce, "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix()})
	d.mu.Unlock()
	return op
}

func (d *deviceFixture) due(t *testing.T, id string) {
	t.Helper()
	op, err := d.store.AuthOperation(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	op.NextPollAt = time.Now().Add(-time.Second)
	if err := d.store.UpdateAuthOperation(t.Context(), &op); err != nil {
		t.Fatal(err)
	}
}

func assertReason(t *testing.T, err error, want failure.Reason) {
	t.Helper()
	if got, _ := failure.ReasonOf(err); got != want {
		t.Fatalf("reason = %s, want %s: %v", got, want, err)
	}
}

func TestDeviceStartAndTimeoutAreDurableAndPrivate(t *testing.T) {
	d := newDeviceFixture(t)
	op := d.start(t)
	_, err := WaitLogin(t.Context(), d.config, op.ID, 20*time.Millisecond)
	assertReason(t, err, failure.AuthWaitTimeout)
	if d.polls != 0 || d.exchanges != 0 {
		t.Fatal("timeout sent a redemption")
	}
	// reopen the database, as a later CLI invocation would.
	db, err := clientstate.Open(t.Context(), d.root)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	config := d.config
	config.State = db
	inspected, err := InspectLogin(t.Context(), config, op.ID)
	if err != nil || inspected.Phase != clientstate.AuthPending {
		t.Fatalf("inspect = %s, %v", inspected.Phase, err)
	}
	public, err := json.Marshal(inspected)
	if err != nil {
		t.Fatal(err)
	}
	var values map[string]any
	if err := json.Unmarshal(public, &values); err != nil {
		t.Fatal(err)
	}
	if len(values) != 8 || values["device_code"] != nil || values["nonce"] != nil || values["Private"] != nil {
		t.Fatalf("unexpected public shape: %s", public)
	}
	d.due(t, op.ID)
	completed, err := WaitLogin(t.Context(), config, op.ID, time.Second)
	if err != nil || completed.Phase != clientstate.AuthCompleted {
		t.Fatalf("resume = %s, %v", completed.Phase, err)
	}
	if d.polls != 1 || d.exchanges != 1 {
		t.Fatalf("polls/exchanges = %d/%d", d.polls, d.exchanges)
	}
	if _, found, err := d.store.ControlSession(t.Context()); err != nil || !found {
		t.Fatalf("session installed=%v, %v", found, err)
	}
}

func TestDeviceStartJoinsExistingOperationWithoutCreatingAnotherChallenge(t *testing.T) {
	d := newDeviceFixture(t)
	first := d.start(t)
	second, err := StartLogin(t.Context(), d.config)
	if err != nil {
		t.Fatal(err)
	}
	if second.ID != first.ID || second.UserCode != first.UserCode {
		t.Fatalf("login did not resume pending approval: first=%s second=%s", first.ID, second.ID)
	}
	requests := d.transport.snapshot()
	deviceRequests := 0
	for _, request := range requests {
		if request.url == deviceIssuer+"/device" {
			deviceRequests++
		}
	}
	if deviceRequests != 1 {
		t.Fatalf("device challenges = %d, want one", deviceRequests)
	}
}

func TestDeviceStartDoesNotWaitForAnotherPoller(t *testing.T) {
	d := newDeviceFixture(t)
	op := d.start(t)
	d.due(t, op.ID)
	entered, release := make(chan struct{}), make(chan struct{})
	d.poll = func(r *http.Request) (*http.Response, error) {
		close(entered)
		select {
		case <-release:
			return jsonResponse(200, map[string]any{"id_token": d.assertion}), nil
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
	}
	waitCtx, cancelWait := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancelWait()
	finished := make(chan error, 1)
	go func() { _, err := WaitLogin(waitCtx, d.config, op.ID, 2*time.Second); finished <- err }()
	select {
	case <-entered:
	case <-waitCtx.Done():
		t.Fatal("initial poll never started")
	}
	startCtx, cancelStart := context.WithTimeout(t.Context(), 250*time.Millisecond)
	defer cancelStart()
	joined, err := StartLogin(startCtx, d.config)
	close(release)
	if err != nil || joined.ID != op.ID {
		t.Fatalf("start blocked behind approval wait: %s, %v", joined.ID, err)
	}
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentDeviceWaitersJoinOneRedemption(t *testing.T) {
	d := newDeviceFixture(t)
	op := d.start(t)
	d.due(t, op.ID)
	entered, release := make(chan struct{}), make(chan struct{})
	d.poll = func(r *http.Request) (*http.Response, error) {
		close(entered)
		select {
		case <-release:
			return jsonResponse(200, map[string]any{"id_token": d.assertion}), nil
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
	}
	db, err := clientstate.Open(t.Context(), d.root)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	other := d.config
	other.State = db
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	results := make(chan error, 2)
	go func() { _, err := WaitLogin(ctx, d.config, op.ID, 2*time.Second); results <- err }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("poll did not start")
	}
	// approval does not own the control-session lock.
	lock, err := d.store.LockControlSession()
	if err != nil {
		close(release)
		t.Fatal(err)
	}
	_ = lock.Close()
	go func() { _, err := WaitLogin(ctx, other, op.ID, 2*time.Second); results <- err }()
	close(release)
	for range 2 {
		select {
		case err := <-results:
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal("waiters did not join")
		}
	}
	if d.polls != 1 || d.exchanges != 1 {
		t.Fatalf("polls/exchanges = %d/%d", d.polls, d.exchanges)
	}
}

func TestDeviceProviderStates(t *testing.T) {
	for _, code := range []string{"authorization_pending", "slow_down", "access_denied", "expired_token"} {
		t.Run(code, func(t *testing.T) {
			d := newDeviceFixture(t)
			op := d.start(t)
			d.due(t, op.ID)
			d.poll = func(*http.Request) (*http.Response, error) {
				return jsonResponse(400, map[string]string{"error": code}), nil
			}
			_, err := WaitLogin(t.Context(), d.config, op.ID, 30*time.Millisecond)
			want := failure.AuthWaitTimeout
			if code == "access_denied" {
				want = failure.AuthDenied
			}
			if code == "expired_token" {
				want = failure.AuthExpired
			}
			assertReason(t, err, want)
			stored, err := InspectLogin(t.Context(), d.config, op.ID)
			if err != nil {
				t.Fatal(err)
			}
			if code == "slow_down" && stored.Interval != 6*time.Second {
				t.Fatalf("interval = %v", stored.Interval)
			}
			if d.polls != 1 || d.exchanges != 0 {
				t.Fatalf("polls/exchanges = %d/%d", d.polls, d.exchanges)
			}
			if want == failure.AuthWaitTimeout {
				if stored.Phase != clientstate.AuthPending {
					t.Fatalf("status = %s", stored.Phase)
				}
				d.poll = nil
				d.due(t, op.ID)
				if _, err := WaitLogin(t.Context(), d.config, op.ID, time.Second); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestCancelAndLogoutFenceInFlightExchange(t *testing.T) {
	for _, logout := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "logout"}[logout], func(t *testing.T) {
			d := newDeviceFixture(t)
			op := d.start(t)
			d.due(t, op.ID)
			issued := issuedSession(t)
			entered, release := make(chan struct{}), make(chan struct{})
			d.exchange = func(r *http.Request) (*http.Response, error) {
				close(entered)
				select {
				case <-release:
					return jsonResponse(200, issued), nil
				case <-r.Context().Done():
					return nil, r.Context().Err()
				}
			}
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			result := make(chan error, 1)
			go func() { _, err := WaitLogin(ctx, d.config, op.ID, 2*time.Second); result <- err }()
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal("exchange did not start")
			}
			var err error
			if logout {
				err = Logout(ctx, d.config)
			} else {
				_, err = CancelLogin(ctx, d.config, op.ID)
			}
			close(release)
			if err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-result:
				assertReason(t, err, failure.AuthCancelled)
			case <-ctx.Done():
				t.Fatal("waiter did not finish")
			}
			if _, found, err := d.store.ControlSession(ctx); err != nil || found {
				t.Fatalf("cancelled login installed = %v, %v", found, err)
			}
			if _, err := WaitLogin(ctx, d.config, op.ID, time.Second); err == nil {
				t.Fatal("cancelled operation resumed")
			}
			if d.polls != 1 || d.exchanges != 1 {
				t.Fatal("cancelled operation replayed")
			}
			requests := d.transport.snapshot()
			last := requests[len(requests)-1]
			if last.url != testControlOrigin+"/v1/auth/logout" || last.header.Get("Authorization") != "Bearer "+issued.AccessToken {
				t.Fatal("issued credential was not revoked after fencing")
			}
		})
	}
}

func TestUncertainDeviceRedemptionAndExchangeRequireRecovery(t *testing.T) {
	for _, step := range []string{"redemption", "exchange", "crashed redemption", "crashed exchange"} {
		t.Run(step, func(t *testing.T) {
			d := newDeviceFixture(t)
			op := d.start(t)
			d.due(t, op.ID)
			lost := errors.New("response lost with sensitive provider text")
			switch step {
			case "redemption":
				d.poll = func(*http.Request) (*http.Response, error) { return nil, lost }
			case "exchange":
				d.exchange = func(*http.Request) (*http.Response, error) { return nil, lost }
			default:
				op, err := d.store.AuthOperation(t.Context(), op.ID)
				if err != nil {
					t.Fatal(err)
				}
				op.Phase = clientstate.AuthRedeeming
				if step == "crashed exchange" {
					op.Phase = clientstate.AuthExchanging
				}
				if err := d.store.UpdateAuthOperation(t.Context(), &op); err != nil {
					t.Fatal(err)
				}
			}
			_, err := WaitLogin(t.Context(), d.config, op.ID, time.Second)
			assertReason(t, err, failure.AuthRecoveryRequired)
			if (step == "redemption" || step == "exchange") && !errors.Is(err, lost) {
				t.Fatal("lost original error")
			}
			polls, exchanges := d.polls, d.exchanges
			_, err = WaitLogin(t.Context(), d.config, op.ID, time.Second)
			assertReason(t, err, failure.AuthRecoveryRequired)
			if d.polls != polls || d.exchanges != exchanges {
				t.Fatal("uncertain one-time credential was replayed")
			}
		})
	}
}

func TestCheckpointedAssertionPreservesNonceVerification(t *testing.T) {
	d := newDeviceFixture(t)
	op := d.start(t)
	d.due(t, op.ID)
	d.assertion = d.signer.Token(t, "key", map[string]any{"iss": deviceIssuer, "sub": "person", "aud": "cli", "nonce": "wrong", "exp": time.Now().Add(time.Hour).Unix()})
	if _, err := WaitLogin(t.Context(), d.config, op.ID, time.Second); err == nil {
		t.Fatal("wrong nonce was accepted")
	}
	if d.polls != 1 || d.exchanges != 0 {
		t.Fatal("unverified assertion reached control")
	}
	if _, err := WaitLogin(t.Context(), d.config, op.ID, time.Second); err == nil {
		t.Fatal("wrong nonce was accepted on resume")
	}
	if d.polls != 1 || d.exchanges != 0 {
		t.Fatal("checkpointed assertion caused another device redemption")
	}
}

func TestUnavailableSigningKeysKeepAssertionResumable(t *testing.T) {
	d := newDeviceFixture(t)
	op := d.start(t)
	d.due(t, op.ID)
	respond := d.transport.respond
	d.transport.respond = func(r *http.Request) (*http.Response, error) {
		if r.URL.String() == deviceIssuer+"/keys" {
			return jsonResponse(503, map[string]string{"error": "unavailable"}), nil
		}
		return respond(r)
	}
	_, err := WaitLogin(t.Context(), d.config, op.ID, time.Second)
	assertReason(t, err, failure.AuthProviderUnavailable)
	stored, err := InspectLogin(t.Context(), d.config, op.ID)
	if err != nil || stored.Phase != clientstate.AuthCredentialReceived {
		t.Fatalf("assertion checkpoint=%s, %v", stored.Phase, err)
	}
	d.transport.respond = respond
	if _, err := WaitLogin(t.Context(), d.config, op.ID, time.Second); err != nil {
		t.Fatal(err)
	}
	if d.polls != 1 || d.exchanges != 1 {
		t.Fatal("provider recovery replayed device redemption")
	}
}

func TestStatusIsLocalAndCheckIsSilent(t *testing.T) {
	old := storedSession(issuedSession(t))
	old.AccessExpiresAt = time.Now().Add(-time.Hour)
	rotated := issuedSession(t)
	rotated.RefreshExpiresAt = old.RefreshExpiresAt
	f := newAuthFixture(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/v1/auth/refresh" {
			return jsonResponse(200, rotated), nil
		}
		if r.URL.Path == "/v1/identity" {
			return jsonResponse(200, map[string]any{"identity": map[string]string{"id": "person"}}), nil
		}
		return nil, errors.New("unexpected request")
	})
	f.save(t, old)
	f.config.LoginToken = func() (token credentials.LoginToken, err error) { t.Error("status initiated login"); return }
	status, err := Status(t.Context(), f.config, false)
	if err != nil || status.Status != "refresh_required" || status.Source != "saved_session" || status.Checked || len(f.transport.snapshot()) != 0 {
		t.Fatalf("local status = %#v, %v", status, err)
	}
	status, err = Status(t.Context(), f.config, true)
	if err != nil || status.Status != "authenticated" || !status.Checked || len(f.transport.snapshot()) != 3 {
		t.Fatalf("checked status = %#v, %v", status, err)
	}
	f.assertSession(t, storedSession(rotated))
}
