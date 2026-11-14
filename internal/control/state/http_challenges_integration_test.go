package state

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/control/turnstile"
	"github.com/tnldotdev/tnl/internal/policy/httpprotection"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
)

func TestIntegrationHTTPChallengeSavedServiceOriginAndCurrentRun(t *testing.T) {
	d, now, _, _ := newPublishRunPrerequisites(t)
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{"production": {Public: true}}, Services: map[string]ProjectServiceConfiguration{
		"web": {PublisherGroup: "production", Target: "app:3000", HTTP: &config.HTTPService{Protection: &httpprotection.Settings{WAF: httpprotection.Off, Challenge: httpprotection.Turnstile}}},
	}}
	if _, err := d.ApplyProjectConfiguration(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	enrollment, err := d.IssuePublisherGroupEnrollment(t.Context(), r.TeamID, r.ProjectKey, "production", r.ActorID, 1, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	replica := enrollAppliedGroup(t, d, r, enrollment, now)
	assignment := replica.assignments.Services[0]
	access := groupAssignmentAccess(t, d, replica, assignment, now)
	start := func(retry string) ServiceRunState {
		t.Helper()
		prep, err := d.PrepareServiceRun(t.Context(), assignment.ServiceID, access.PublisherIdentity, retry, now, ServiceMetadata{Protocol: "http", TrustRevision: assignment.TrustRevision})
		if err != nil {
			t.Fatal(err)
		}
		run, err := d.StartServiceRun(t.Context(), assignment.ServiceID, prep.RunID, prep.RunNumber, access.PublisherIdentity, now)
		if err != nil {
			t.Fatal(err)
		}
		return run
	}
	run := start("challenge")
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: run.ServiceID}
	browser := sha256.Sum256([]byte("browser"))
	secret := []byte(strings.Repeat("p", 32))
	binding := base64.RawURLEncoding.EncodeToString(secret)
	publisher := sha256.Sum256(secret)
	attempt, err := d.BeginHTTPChallenge(t.Context(), scope, browser[:], publisher[:], now)
	if err != nil || attempt.Port == 443 || attempt.Port < 1024 {
		t.Fatal("saved service challenge lost its exact endpoint port", attempt.Port, err)
	}
	if err := d.ClaimHTTPChallenge(t.Context(), attempt.ID, browser[:], now); err != nil {
		t.Fatal(err)
	}
	handoff, err := d.CompleteHTTPChallenge(t.Context(), verifiedChallengeAttempt(t, attempt.ID, now), now)
	if err != nil || handoff.Origin != visitortoken.ClearanceOrigin(attempt.Hostname, attempt.Port) {
		t.Fatal("saved service handoff lost its approved origin", err)
	}
	redeem := func(token string, number int64) (visitortoken.ClearanceToken, error) {
		tokenValue, _, err := d.RedeemHTTPChallenge(t.Context(), scope, run.RunID, number, token, handoff.Secret, binding, testVisitorIssuer, now)
		return tokenValue, err
	}
	for _, bad := range []struct {
		token  string
		number int64
	}{{"wrong-token", run.RunNumber}, {run.Token, run.RunNumber + 1}} {
		if _, err := redeem(bad.token, bad.number); err == nil {
			t.Fatal("handoff accepted stale publisher authority")
		}
	}
	if err := d.CloseServiceRun(t.Context(), run.ServiceID, run.RunID, run.Token, now); err != nil {
		t.Fatal(err)
	}
	if _, err := redeem(run.Token, run.RunNumber); err == nil {
		t.Fatal("closed service run redeemed a handoff")
	}
	run = start("replacement")
	if _, err := redeem(run.Token, run.RunNumber); err != nil {
		t.Fatal("same-origin replacement run could not redeem the browser-bound handoff", err)
	}
}

func TestIntegrationHTTPChallengeCapacityAndPruning(t *testing.T) {
	f, auth := finalVisitorRun(t, "http")
	d, now := f.database, f.now
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.publish_runs SET http_protection='{"challenge":"turnstile"}' WHERE id=$1`, auth.PublishRunID); err != nil {
		t.Fatal(err)
	}
	browser, publisher := sha256.Sum256([]byte("browser")), sha256.Sum256([]byte("publisher"))
	scope := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: auth.PublicURLID}
	_, err := d.pool.Exec(t.Context(), `INSERT INTO control.http_challenges
		(id,resource_kind,resource_id,hostname,port,browser_binding_hash,publisher_binding_hash,expires_at)
		SELECT 'cha_' || lpad(n::text,22,'0'),'public_url',$1,'preview.example.test',443,$2,$3,$4
		FROM generate_series(1,256) n`, scope.ID, browser[:], publisher[:], now.Add(5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.BeginHTTPChallenge(t.Context(), scope, browser[:], publisher[:], now); !errors.Is(err, ErrHTTPChallengeCapacity) {
		t.Fatal("attempt quota did not reject new state", err)
	}
	// a separate resource cannot spend another resource's challenge records.
	other := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: "url_" + strings.Repeat("Z", 22)}
	if _, err := d.BeginHTTPChallenge(t.Context(), other, browser[:], publisher[:], now); err == nil {
		t.Fatal("unapproved origin started an attempt")
	}
	if err := d.ExpireVisitorPermissions(t.Context(), now.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.http_challenges`).Scan(&count); err != nil || count != 0 {
		t.Fatal("existing maintenance retained expired challenge state", count, err)
	}
}

type challengeProviderTransport func(*http.Request) (*http.Response, error)

func (f challengeProviderTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func verifiedChallengeAttempt(t *testing.T, id string, now time.Time) turnstile.VerifiedAttempt {
	t.Helper()
	v, err := turnstile.New("site", "secret", "control.example.test", &http.Client{Transport: challengeProviderTransport(func(*http.Request) (*http.Response, error) {
		raw, _ := json.Marshal(map[string]any{"success": true, "hostname": "control.example.test", "action": turnstile.Action, "cdata": id, "challenge_ts": now})
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := v.Verify(t.Context(), "widget-response", id, now)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func TestIntegrationHTTPChallengeAtomicHandoffAndPurposeSeparation(t *testing.T) {
	f, auth := finalVisitorRun(t, "http")
	d, now := f.database, f.now
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.publish_runs SET http_protection='{"challenge":"turnstile"}' WHERE id=$1`, auth.PublishRunID); err != nil {
		t.Fatal(err)
	}
	if err := d.PrepareVisitorSigningKeys(t.Context(), testVisitorIssuer, now); err != nil {
		t.Fatal(err)
	}
	scope := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: auth.PublicURLID}
	browserHash := sha256.Sum256([]byte("control-browser"))
	publisherSecret := strings.Repeat("b", 32)
	binding := base64.RawURLEncoding.EncodeToString([]byte(publisherSecret))
	publisherHash := sha256.Sum256([]byte(publisherSecret))
	attempt, err := d.BeginHTTPChallenge(t.Context(), scope, browserHash[:], publisherHash[:], now)
	if err != nil || !attempt.ExpiresAt.Equal(now.Add(httpprotection.ChallengeAttemptLifetime)) {
		t.Fatal("attempt lost its fixed lifetime", err)
	}
	if _, err := d.ReadHTTPChallenge(t.Context(), attempt.ID, make([]byte, 32), now); !errors.Is(err, ErrHTTPChallenge) {
		t.Fatal("attempt ignored its control browser binding", err)
	}
	if _, err := d.CompleteHTTPChallenge(t.Context(), turnstile.VerifiedAttempt{}, now); !errors.Is(err, ErrHTTPChallenge) {
		t.Fatal("zero verification evidence completed an attempt", err)
	}
	var workers sync.WaitGroup
	claims := make(chan error, 2)
	for range 2 {
		workers.Go(func() { claims <- d.ClaimHTTPChallenge(t.Context(), attempt.ID, browserHash[:], now) })
	}
	workers.Wait()
	if a, b := <-claims, <-claims; (a == nil) == (b == nil) {
		t.Fatal("replicas did not claim the attempt exactly once", a, b)
	}
	proof := verifiedChallengeAttempt(t, attempt.ID, now)
	handoff, err := d.CompleteHTTPChallenge(t.Context(), proof, now)
	if err != nil || handoff.Origin != visitortoken.ClearanceOrigin(attempt.Hostname, attempt.Port) {
		t.Fatal("handoff lost its approved origin", err)
	}
	if _, err := d.CompleteHTTPChallenge(t.Context(), proof, now); !errors.Is(err, ErrHTTPChallenge) {
		t.Fatal("reused provider proof created another handoff", err)
	}
	redeem := func(binding string) (visitortoken.ClearanceToken, time.Time, error) {
		return d.RedeemHTTPChallenge(t.Context(), scope, auth.PublishRunID, int64(auth.PublishRunNumber), auth.PublishRunToken.String(), handoff.Secret, binding, testVisitorIssuer, now)
	}
	if _, _, err := redeem(base64.RawURLEncoding.EncodeToString(make([]byte, 32))); !errors.Is(err, ErrHTTPChallenge) {
		t.Fatal("handoff moved to a different publisher browser", err)
	}
	type redemption struct {
		token   visitortoken.ClearanceToken
		expires time.Time
		err     error
	}
	results := make(chan redemption, 2)
	for range 2 {
		workers.Go(func() { token, expires, err := redeem(binding); results <- redemption{token, expires, err} })
	}
	workers.Wait()
	a, b := <-results, <-results
	if a.err != nil {
		a, b = b, a
	}
	if a.err != nil || !errors.Is(b.err, ErrHTTPChallenge) || !a.expires.Equal(now.Add(visitortoken.ClearanceLifetime)) {
		t.Fatal("handoff was not an atomic fixed-expiry single use", a.err, b.err)
	}
	update, err := d.ReadPublisherVisitorPolicy(t.Context(), scope, auth.PublishRunID, int64(auth.PublishRunNumber), auth.PublishRunToken.String(), 0, now)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := visitorlease.New(scope, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	decoded, err := visitorlease.Decode(update)
	if err != nil || lease.Apply(lease.Begin(), decoded) != nil {
		t.Fatal("policy could not install clearance verification keys", err)
	}
	view, _, _ := lease.Current()
	if expires, err := visitortoken.VerifyClearance(a.token, view, now); err != nil || !expires.Equal(a.expires) {
		t.Fatal("publisher could not verify clearance locally", err)
	}
	if _, err := visitortoken.VerifyBearer(visitortoken.Token(a.token.Reveal()), view, now); !errors.Is(err, visitortoken.ErrToken) {
		t.Fatal("clearance granted visitor permission", err)
	}
	var retained time.Time
	if err := d.pool.QueryRow(t.Context(), `SELECT retain_until FROM control.visitor_token_keys WHERE retired_at IS NULL AND revoked_at IS NULL`).Scan(&retained); err != nil || retained.Before(a.expires) {
		t.Fatal("clearance signing key was not retained through its absolute expiry", err)
	}
}

func TestIntegrationHTTPChallengeFixedAttemptAndHandoffDeadlines(t *testing.T) {
	f, auth := finalVisitorRun(t, "http")
	d, now := f.database, f.now
	scope := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: auth.PublicURLID}
	publisherSecret := []byte(strings.Repeat("p", 32))
	binding := base64.RawURLEncoding.EncodeToString(publisherSecret)
	browser, publisher := sha256.Sum256([]byte("browser")), sha256.Sum256(publisherSecret)
	if _, err := d.BeginHTTPChallenge(t.Context(), scope, browser[:], publisher[:], now); !errors.Is(err, ErrHTTPChallenge) {
		t.Fatal("unconfigured resource started a challenge", err)
	}
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.publish_runs SET http_protection='{"waf":"off","challenge":"turnstile"}' WHERE id=$1`, auth.PublishRunID); err != nil {
		t.Fatal(err)
	}
	attempt, err := d.BeginHTTPChallenge(t.Context(), scope, browser[:], publisher[:], now)
	if err != nil {
		t.Fatal("WAF opt-out silently bypassed the explicit challenge", err)
	}
	if err := d.ClaimHTTPChallenge(t.Context(), attempt.ID, browser[:], attempt.ExpiresAt); !errors.Is(err, ErrHTTPChallenge) {
		t.Fatal("expired attempt was claimed", err)
	}
	if err := d.ClaimHTTPChallenge(t.Context(), attempt.ID, browser[:], now); err != nil {
		t.Fatal(err)
	}
	proof := verifiedChallengeAttempt(t, attempt.ID, now)
	if _, err := d.CompleteHTTPChallenge(t.Context(), proof, attempt.ExpiresAt); !errors.Is(err, ErrHTTPChallenge) {
		t.Fatal("expired attempt was completed", err)
	}
	handoff, err := d.CompleteHTTPChallenge(t.Context(), proof, now)
	if err != nil {
		t.Fatal(err)
	}
	var unused string
	if err := d.pool.QueryRow(t.Context(), `SELECT resource_id FROM control.http_challenges WHERE id=$1 AND handoff_expires_at=$2`, attempt.ID, now.Add(httpprotection.ChallengeHandoffLifetime)).Scan(&unused); err != nil {
		t.Fatal("handoff expiry was not fixed at one minute", err)
	}
	if _, _, err := d.RedeemHTTPChallenge(t.Context(), scope, auth.PublishRunID, int64(auth.PublishRunNumber), auth.PublishRunToken.String(), handoff.Secret, binding, testVisitorIssuer, now.Add(httpprotection.ChallengeHandoffLifetime)); !errors.Is(err, ErrHTTPChallenge) {
		t.Fatal("expired handoff was redeemed", err)
	}
}
