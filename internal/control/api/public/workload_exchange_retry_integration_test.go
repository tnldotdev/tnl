package public

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/connector/workload"
	controlauthority "github.com/tnldotdev/tnl/internal/control/api/authority"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	"github.com/tnldotdev/tnl/internal/testutil/githubtest"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationWorkloadExchangeFreshAssertionRetry(t *testing.T) {
	for _, test := range []struct {
		name          string
		loseFirst     bool
		proofLifetime time.Duration
	}{
		{"same-key", false, 3 * time.Minute},
		{"lost-first-response", true, 45 * time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newWorkloadExchangeRetryFixture(t)
			transport := &workloadExchangeRetryTransport{base: f.server.Client().Transport, loseFirst: test.loseFirst}
			httpClient := *f.server.Client()
			httpClient.Transport = transport
			job, err := workload.New(f.server.URL, &httpClient)
			if err != nil {
				t.Fatal(err)
			}
			issuedAt := time.Now().Truncate(time.Second)
			claims := githubtest.Claims(f.server.URL, issuedAt)
			oldExpiry := issuedAt.Add(test.proofLifetime)
			claims["exp"] = oldExpiry.Unix()
			initial := f.issuer.Sign(t, claims)
			first, err := job.Exchange(t.Context(), f.team, "example", f.sourceFingerprint, "test", initial, nil)
			if len(transport.responses) != 1 {
				t.Fatalf("initial exchange did not return a committed server session: requests=%d successful_responses=%d http_statuses=%v native_error=%v", len(transport.requests), len(transport.responses), transport.statuses, err)
			}
			committed := transport.responses[0]
			if test.loseFirst {
				if !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Fatalf("initial response loss was not delivered to native client: %v", err)
				}
				if _, err := job.Session(); !errors.Is(err, workload.ErrNoSession) {
					t.Fatal("lost initial response installed a local session", err)
				}
			} else if err != nil || !reflect.DeepEqual(first, committed) {
				t.Fatal("initial native exchange failed", err)
			}
			if !committed.IdentityExpiresAt.Equal(oldExpiry) || committed.LeaseExpiresAt.After(oldExpiry) || committed.LeaseExpiresAt.After(time.Now().Add(controlstate.WorkloadLease)) {
				t.Fatal("initial lease escaped proof or renewal bounds")
			}

			// policy additions cannot restore a right removed from this session,
			// including when the client never received its original snapshot.
			p := (*f.body.Configuration.Workloads)["test"]
			p.Services = []string{"api"}
			(*f.body.Configuration.Workloads)["test"] = p
			f.apply(t)
			p.Services = []string{"api", "db"}
			(*f.body.Configuration.Workloads)["test"] = p
			f.apply(t)
			before := f.saved(t, committed.Id)
			claims["jti"] = "fresh-same-execution"
			// a fresh assertion needs fresh issuance times too. retaining the old
			// iat makes exp-iat exceed GitHub's ten-minute cap across a second boundary.
			freshIssuedAt := time.Now().Truncate(time.Second)
			freshExpiry := freshIssuedAt.Add(10 * time.Minute)
			claims["iat"], claims["nbf"], claims["exp"] = freshIssuedAt.Unix(), freshIssuedAt.Unix(), freshExpiry.Unix()
			fresh := f.issuer.Sign(t, claims)
			next, retryErr := job.Exchange(t.Context(), f.team, "example", f.sourceFingerprint, "test", fresh, nil)
			if len(transport.requests) != 2 || len(transport.responses) != 2 {
				t.Fatalf("fresh-token exchange retry failed: requests=%d want=2 successful_responses=%d want=2 http_statuses=%v native_error=%v proof_lifetime=%s lease_remaining=%s identity_remaining=%s", len(transport.requests), len(transport.responses), transport.statuses, retryErr, freshExpiry.Sub(time.Unix(claims["iat"].(int64), 0)), time.Until(committed.LeaseExpiresAt), time.Until(committed.IdentityExpiresAt))
			}
			oldRequest, newRequest := transport.requests[0], transport.requests[1]
			if oldRequest.Nonce != newRequest.Nonce || oldRequest.PublicKey != newRequest.PublicKey || oldRequest.Assertion == newRequest.Assertion || oldRequest.Signature == newRequest.Signature {
				t.Fatal("retry did not retain its key and idempotency nonce with a new signed assertion")
			}
			raw := transport.responses[1]
			if raw.AssertionExpiresAt == nil {
				t.Fatal("exchange retry omitted the supplied assertion's verified expiry")
			}
			t.Logf("real exchange retry: identity_expires_at=%s; assertion_expires_at=%s; lease_expires_at=%s; native error=%v", raw.IdentityExpiresAt.Format(time.RFC3339Nano), raw.AssertionExpiresAt.Format(time.RFC3339Nano), raw.LeaseExpiresAt.Format(time.RFC3339Nano), retryErr)
			// assertion_expires_at reports verification of the supplied token, not
			// attachment to the saved session. exchange recovery must not renew it.
			sameHardExpiry := raw.ExpiresAt == nil && committed.ExpiresAt == nil || raw.ExpiresAt != nil && committed.ExpiresAt != nil && raw.ExpiresAt.Equal(*committed.ExpiresAt)
			if raw.Id != committed.Id || raw.Credential != committed.Credential || raw.Binding != committed.Binding || !reflect.DeepEqual(raw.Subject, committed.Subject) || !reflect.DeepEqual(raw.Github, committed.Github) || !sameHardExpiry || raw.RenewalSequence != committed.RenewalSequence || !raw.IdentityExpiresAt.Equal(committed.IdentityExpiresAt) || !raw.LeaseExpiresAt.Equal(committed.LeaseExpiresAt) || raw.AssertionExpiresAt == nil || !raw.AssertionExpiresAt.Equal(freshExpiry) {
				t.Fatal("exchange retry changed accepted authority or misreported verified proof expiry")
			}
			if len(raw.ServiceIds) != 1 {
				t.Fatal("exchange retry restored removed service rights")
			}
			if !bytes.Equal(before, f.saved(t, committed.Id)) {
				t.Fatal("exchange retry mutated the saved session instead of reporting supplied proof verification")
			}
			if retryErr != nil {
				t.Errorf("same-key fresh-token exchange retry should recover the current proof-capped session: %v", retryErr)
			} else if !reflect.DeepEqual(next, raw) {
				t.Error("native client changed the server's accepted session bounds")
			}
			if retryErr == nil {
				retained, err := job.Session()
				if err != nil || !reflect.DeepEqual(retained, raw) {
					t.Fatal("native client did not retain the recovered proof-capped session", err)
				}
			}
			var sessions int
			if err := f.inspect.QueryRow(t.Context(), `SELECT count(*) FROM control.workload_sessions`).Scan(&sessions); err != nil || sessions != 1 {
				t.Fatal("exchange retry created a replacement session", sessions, err)
			}
			other, err := workload.New(f.server.URL, f.server.Client())
			if err != nil {
				t.Fatal(err)
			}
			_, err = other.Exchange(t.Context(), f.team, "example", f.sourceFingerprint, "test", fresh, nil)
			var problem *clientauthority.ProblemError
			if !errors.As(err, &problem) || problem.Status != http.StatusConflict {
				t.Fatal("fresh token allowed another native key to take over the same execution", err)
			}
		})
	}
}

func TestIntegrationWorkloadExchangeFreshAssertionRetryCannotResurrect(t *testing.T) {
	for _, boundary := range []string{"lease", "identity", "fixed-window", "revoked"} {
		t.Run(boundary, func(t *testing.T) {
			f := newWorkloadExchangeRetryFixture(t)
			job, err := workload.New(f.server.URL, f.server.Client())
			if err != nil {
				t.Fatal(err)
			}
			claims := githubtest.Claims(f.server.URL, time.Now())
			initial, err := job.Exchange(t.Context(), f.team, "example", f.sourceFingerprint, "test", f.issuer.Sign(t, claims), nil)
			if err != nil {
				t.Fatal(err)
			}
			// stage expired accepted authority without waiting for production lease
			// intervals; both provider assertions and all API clocks remain real.
			query := `UPDATE control.workload_sessions SET created_at=$2::timestamptz-interval '2 minutes', renewed_at=$2::timestamptz-interval '2 minutes', lease_expires_at=$2::timestamptz-interval '1 second'`
			want := http.StatusGone
			switch boundary {
			case "identity":
				query += `, identity_expires_at=$2::timestamptz-interval '1 second'`
			case "fixed-window":
				query += `, expires_at=$2::timestamptz-interval '1 second'`
			case "revoked":
				query = `UPDATE control.workload_sessions SET revoked_at=$2`
				want = http.StatusForbidden
			}
			if _, err := f.inspect.Exec(t.Context(), query+` WHERE id=$1`, initial.Id, time.Now()); err != nil {
				t.Fatal(err)
			}
			before := f.saved(t, initial.Id)
			freshIssuedAt := time.Now().Truncate(time.Second)
			claims["jti"] = "fresh-after-authority-ended"
			claims["iat"], claims["nbf"], claims["exp"] = freshIssuedAt.Unix(), freshIssuedAt.Unix(), freshIssuedAt.Add(10*time.Minute).Unix()
			_, err = job.Exchange(t.Context(), f.team, "example", f.sourceFingerprint, "test", f.issuer.Sign(t, claims), nil)
			var problem *clientauthority.ProblemError
			if !errors.As(err, &problem) || problem.Status != want {
				t.Fatalf("fresh verified assertion revived %s authority: %v", boundary, err)
			}
			if !bytes.Equal(before, f.saved(t, initial.Id)) {
				t.Fatal("denied fresh-token retry changed accepted session authority")
			}
			if retained, err := job.Session(); err != nil || !reflect.DeepEqual(retained, initial) {
				t.Fatal("denied fresh-token retry changed the native session", err)
			}
			if _, err := job.CheckService(t.Context(), initial.ServiceIds[0]); err == nil {
				t.Fatal("ended session retained service authority after fresh-token retry")
			}
		})
	}
}

// capture only real successful API responses. dropping one response happens
// after PostgreSQL commits and does not replace provider or server validation.
type workloadExchangeRetryTransport struct {
	base      http.RoundTripper
	loseFirst bool
	requests  []authorityv1.WorkloadExchange
	responses []authorityv1.WorkloadSession
	statuses  []int
}

func (transport *workloadExchangeRetryTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Path != "/v1/workload-sessions/exchange" {
		return transport.base.RoundTrip(r)
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))
	var request authorityv1.WorkloadExchange
	if err := json.Unmarshal(body, &request); err != nil {
		return nil, err
	}
	transport.requests = append(transport.requests, request)
	response, err := transport.base.RoundTrip(r)
	if response != nil {
		transport.statuses = append(transport.statuses, response.StatusCode)
	}
	if err != nil || response.StatusCode != http.StatusOK {
		return response, err
	}
	body, err = io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		return nil, err
	}
	var session authorityv1.WorkloadSession
	if err := json.Unmarshal(body, &session); err != nil {
		return nil, err
	}
	transport.responses = append(transport.responses, session)
	if transport.loseFirst && len(transport.responses) == 1 {
		return nil, io.ErrUnexpectedEOF
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	return response, nil
}

type workloadExchangeRetryFixture struct {
	sourceFingerprint string
	server            *httptest.Server
	issuer            *githubtest.Issuer
	inspect           *pgx.Conn
	owner             *clientcontrol.Client
	team              string
	body              controlv1.ApplyProjectConfigurationRequest
}

func newWorkloadExchangeRetryFixture(t *testing.T) *workloadExchangeRetryFixture {
	t.Helper()
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	ctx := t.Context()
	databaseURL := testutil.NewDisposablePostgresDatabaseURL(t, "workload_exchange_retry")
	if err := controlstate.Migrate(ctx, databaseURL); err != nil {
		t.Fatal(err)
	}
	d, err := controlstate.Open(ctx, databaseURL, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", naming.ManagedURLModeSimple)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	inspect, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inspect.Close(context.Background()) })
	human, err := controltest.Session(ctx, d, "example.test", time.Hour, 24*time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	issuer := githubtest.New(t)
	if _, err := controlauthority.Register(mux, controlauthority.Config{ControlURL: server.URL, HTTPClient: issuer.Client}, d); err != nil {
		t.Fatal(err)
	}
	h, err := NewHandler(Config{ControlURL: server.URL, ManagedURLMode: naming.ManagedURLModeSimple}, DatabaseStores(d), d, nil)
	if err != nil {
		t.Fatal(err)
	}
	mux.Handle("/", h)
	owner, err := clientcontrol.New(server.URL, server.Client(), human.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	team := human.Identity.Memberships[0].TeamID
	deployment := "production"
	policies := map[string]controlv1.ProjectWorkload{"test": {Provider: controlv1.WorkloadGitHub, Github: &controlv1.ProjectWorkloadGitHub{Repository: "example/repository", RepositoryId: "12345", RepositoryOwnerId: "6789", WorkflowRef: "example/repository/.github/workflows/test.yml@refs/heads/main", Ref: "refs/heads/main", Events: []string{"push"}}, Services: []string{"api", "db"}, MaxDurationSeconds: 3600}}
	for name, policy := range policies {
		policy.Deployment = deployment
		policies[name] = policy
	}
	f := &workloadExchangeRetryFixture{server: server, issuer: issuer, inspect: inspect, owner: owner, team: team, body: controlv1.ApplyProjectConfigurationRequest{Deployment: deployment, ServiceDeclarations: controlv1.ProjectServiceDeclarations{"api": "http", "db": "http"}, TeamId: team, Source: &testProjectSource, Configuration: controlv1.ProjectConfiguration{Workloads: &policies, Settings: &controlv1.DeploymentSettings{}, Services: map[string]controlv1.ProjectServiceConfiguration{"api": {Target: "api.internal:3000"}, "db": {Target: "db.internal:5432"}}, Webhooks: map[string]controlv1.ProjectWebhook{}}}}
	f.apply(t)
	return f
}

func (f *workloadExchangeRetryFixture) apply(t *testing.T) {
	t.Helper()
	applied, err := f.owner.ApplyProjectConfiguration(t.Context(), "example", f.body)
	if err != nil {
		t.Fatal(err)
	}
	f.body.ExpectedRevision = applied.Revision
	f.sourceFingerprint = applied.SourceFingerprint
}

func (f *workloadExchangeRetryFixture) saved(t *testing.T, id string) []byte {
	t.Helper()
	var value []byte
	if err := f.inspect.QueryRow(t.Context(), `SELECT to_jsonb(w)::text FROM control.workload_sessions w WHERE id=$1`, id).Scan(&value); err != nil {
		t.Fatal(err)
	}
	return value
}
