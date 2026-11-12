package public

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/connector/workload"
	controlauthority "github.com/tnldotdev/tnl/internal/control/api/authority"
	"github.com/tnldotdev/tnl/internal/control/oidc"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/security/machineproof"
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
	}{{"same-key", false, 3 * time.Minute}, {"lost-first-response", true, 45 * time.Second}} {
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
			claims := f.claims(issuedAt)
			oldExpiry := issuedAt.Add(test.proofLifetime)
			claims["exp"] = oldExpiry.Unix()
			first, err := job.Prepare(t.Context(), f.environment.Ref, f.permission, f.issuer.Sign(t, claims), f.services)
			if len(transport.responses) != 1 {
				t.Fatalf("prepare did not commit: statuses=%v native_error=%v", transport.statuses, err)
			}
			committed := transport.responses[0]
			if test.loseFirst {
				if !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Fatal("response loss not delivered", err)
				}
				if _, err := job.Session(); !errors.Is(err, workload.ErrNoSession) {
					t.Fatal("lost response installed a session", err)
				}
			} else if err != nil || !reflect.DeepEqual(first, committed) {
				t.Fatal("initial native preparation", err)
			}
			if !committed.Session.IdentityExpiresAt.Equal(oldExpiry) || committed.Session.LeaseExpiresAt.After(oldExpiry) || committed.Session.LeaseExpiresAt.After(time.Now().Add(controlstate.WorkloadLease)) {
				t.Fatal("initial lease escaped proof or renewal bounds")
			}
			// changing targets does not change the admitted service IDs. a fresh
			// source token recovers the original accepted session, never renews it.
			targets := controlv1.EnvironmentTargets{"api": {Address: new("replacement.internal:3000")}, "db": {Address: new("db.internal:5432")}}
			f.environment, err = f.owner.ApplyEnvironment(t.Context(), "example", f.environment.Id, controlv1.ApplyEnvironmentRequest{TeamId: f.team, ExpectedRevision: f.environment.MutationRevision, DefinitionRevision: f.environment.AppliedDefinitionRevision, Targets: &targets})
			if err != nil {
				t.Fatal(err)
			}
			before := f.saved(t, committed.Session.Id)
			freshIssuedAt := time.Now().Truncate(time.Second)
			freshExpiry := freshIssuedAt.Add(10 * time.Minute)
			claims["jti"], claims["iat"], claims["nbf"], claims["exp"] = "fresh-same-execution", freshIssuedAt.Unix(), freshIssuedAt.Unix(), freshExpiry.Unix()
			fresh := f.issuer.Sign(t, claims)
			next, retryErr := job.Prepare(t.Context(), f.environment.Ref, f.permission, fresh, f.services)
			if len(transport.requests) != 2 || len(transport.responses) != 2 {
				t.Fatalf("fresh-token retry: statuses=%v error=%v", transport.statuses, retryErr)
			}
			oldRequest, newRequest := transport.requests[0], transport.requests[1]
			if oldRequest.Nonce != newRequest.Nonce || oldRequest.PublicKey != newRequest.PublicKey || oldRequest.Assertion == newRequest.Assertion || oldRequest.Signature == newRequest.Signature || oldRequest.PermissionId != newRequest.PermissionId || !reflect.DeepEqual(oldRequest.Services, newRequest.Services) {
				t.Fatal("retry changed native intent or did not sign the fresh assertion")
			}
			raw := transport.responses[1]
			if !reflect.DeepEqual(raw.Session, committed.Session) || !reflect.DeepEqual(raw.Services, committed.Services) || raw.MutationRevision != f.environment.MutationRevision {
				t.Fatal("retry changed accepted authority or lost current selection")
			}
			if !bytes.Equal(before, f.saved(t, committed.Session.Id)) {
				t.Fatal("retry mutated the saved session")
			}
			if retryErr != nil || !reflect.DeepEqual(next, raw) {
				t.Fatal("native retry changed accepted session bounds", retryErr)
			}
			if retained, err := job.Session(); err != nil || !reflect.DeepEqual(retained, raw.Session) {
				t.Fatal("native client did not retain recovered session", err)
			}
			var sessions int
			if err := f.inspect.QueryRow(t.Context(), `SELECT count(*) FROM control.workload_sessions`).Scan(&sessions); err != nil || sessions != 1 {
				t.Fatal("retry created replacement session", sessions, err)
			}
			other, err := workload.New(f.server.URL, f.server.Client())
			if err != nil {
				t.Fatal(err)
			}
			separate, err := other.Prepare(t.Context(), f.environment.Ref, f.permission, fresh, f.services)
			if err != nil || separate.Session.Id == committed.Session.Id || separate.Session.Credential == committed.Session.Credential {
				t.Fatal("reusable OIDC token took over another ephemeral key's session", err)
			}
			// reusable proof plus a new nonce is independent authority. even a
			// valid new ephemeral signature cannot take over the original nonce.
			takeover := newRequest
			takeover.PublicKey = base64.RawURLEncoding.EncodeToString(other.PublicKey())
			digest := sha256.Sum256([]byte(takeover.Assertion))
			takeover.Signature = base64.RawURLEncoding.EncodeToString(other.Sign(machineproof.EnvironmentVisitorPossession(f.environment.ProjectKey, f.permission, f.environment.Id, "prepare", takeover.PublicKey, takeover.Nonce, f.services, digest)))
			beforeTakeover := f.saved(t, committed.Session.Id)
			denied, err := f.authority.PrepareEnvironmentVisitorWithResponse(t.Context(), f.environment.ProjectKey, f.environment.Id, takeover)
			if err != nil || denied.StatusCode() != http.StatusConflict || bytes.Contains(denied.Body, []byte(committed.Session.Credential)) || bytes.Contains(denied.Body, []byte(separate.Session.Credential)) {
				t.Fatal("same nonce accepted a different correctly signing native key", err)
			}
			if !bytes.Equal(beforeTakeover, f.saved(t, committed.Session.Id)) {
				t.Fatal("denied key takeover changed the original session")
			}
			if retained, err := job.Session(); err != nil || !reflect.DeepEqual(retained, committed.Session) {
				t.Fatal("denied raw key takeover changed the original native session", err)
			}
		})
	}
}

func TestIntegrationWorkloadExchangeFreshAssertionRetryNarrowsOriginalServices(t *testing.T) {
	for _, loseFirst := range []bool{false, true} {
		name := "same-key"
		if loseFirst {
			name = "lost-first-response"
		}
		t.Run(name, func(t *testing.T) {
			f := newWorkloadExchangeRetryFixture(t)
			transport := &workloadExchangeRetryTransport{base: f.server.Client().Transport, loseFirst: loseFirst}
			httpClient := *f.server.Client()
			httpClient.Transport = transport
			_, ephemeral, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			job, err := workload.NewWithKey(f.server.URL, &httpClient, ephemeral)
			if err != nil {
				t.Fatal(err)
			}
			claims := f.claims(time.Now().Truncate(time.Second))
			_, err = job.Prepare(t.Context(), f.environment.Ref, f.permission, f.issuer.Sign(t, claims), f.services)
			if len(transport.responses) != 1 || loseFirst && !errors.Is(err, io.ErrUnexpectedEOF) || !loseFirst && err != nil {
				t.Fatal("initial native preparation did not commit the response-loss fixture", err)
			}
			initial := transport.responses[0]
			originalAPI := initial.Services["api"].ServiceId
			originalDB := initial.Services["db"].ServiceId
			definition, err := f.owner.CreateServiceDefinition(t.Context(), f.environment.ProjectKey, controlv1.CreateServiceDefinitionRequest{TeamId: f.team, SourceFingerprint: strings.Repeat("a", 64), Definition: controlv1.ServiceDefinition{Services: map[string]controlv1.ServiceDefinitionService{"api": {Protocol: "http"}}}})
			if err != nil {
				t.Fatal(err)
			}
			current, err := f.owner.ApplyEnvironment(t.Context(), f.environment.ProjectKey, f.environment.Id, controlv1.ApplyEnvironmentRequest{TeamId: f.team, ExpectedRevision: f.environment.MutationRevision, DefinitionRevision: definition.Revision})
			if err != nil || len(current.Services) != 1 || current.Services[0].ServiceId != originalAPI {
				t.Fatal("narrowing replaced the surviving original service", err)
			}
			if _, err := f.database.CheckWorkloadService(t.Context(), initial.Session.Credential, originalDB, time.Now()); err == nil {
				t.Fatal("removed original service retained visitor authority")
			}
			before := f.saved(t, initial.Session.Id)
			freshAt := time.Now().Truncate(time.Second)
			claims["jti"], claims["iat"], claims["nbf"], claims["exp"] = "fresh-narrowed-recovery", freshAt.Unix(), freshAt.Unix(), freshAt.Add(5*time.Minute).Unix()
			_, retryErr := job.Prepare(t.Context(), f.environment.Ref, f.permission, f.issuer.Sign(t, claims), f.services)
			if len(transport.requests) != 2 {
				t.Fatal("narrowed recovery did not use the real HTTP preparation path")
			}
			firstRequest, retryRequest := transport.requests[0], transport.requests[1]
			if firstRequest.Nonce != retryRequest.Nonce || firstRequest.PublicKey != retryRequest.PublicKey || firstRequest.Signature == retryRequest.Signature || firstRequest.Assertion == retryRequest.Assertion || !reflect.DeepEqual(firstRequest.Services, retryRequest.Services) {
				t.Fatal("narrowed recovery changed its original native admission intent")
			}
			if !bytes.Equal(before, f.saved(t, initial.Session.Id)) {
				t.Fatal("narrowed recovery rewrote the accepted session row")
			}
			if len(transport.responses) != 2 {
				t.Fatalf("narrowed original-ID recovery must return HTTP 200 with the surviving original service, not deny the original request: statuses=%v native_error=%v", transport.statuses, retryErr)
			}
			recovered := transport.responses[1]
			expectedSession := initial.Session
			expectedSession.ServiceIds = []string{originalAPI}
			if !reflect.DeepEqual(recovered.Session, expectedSession) || len(recovered.Services) != 1 || !reflect.DeepEqual(recovered.Services["api"], initial.Services["api"]) || recovered.MutationRevision != current.MutationRevision || recovered.AppliedDefinitionRevision != current.AppliedDefinitionRevision {
				t.Fatal("narrowed recovery changed accepted authority or substituted another service identity")
			}
			if retryErr != nil {
				t.Fatalf("native validator must accept the server's narrowed original-ID recovery: %v", retryErr)
			}
			if retained, err := job.Session(); err != nil || !reflect.DeepEqual(retained, expectedSession) {
				t.Fatal("native client failed to retain the narrowed recovered session", err)
			}
			if _, err := job.CheckService(t.Context(), originalAPI); err != nil {
				t.Fatal("narrowed recovery lost its surviving original service", err)
			}
			if _, err := job.CheckService(t.Context(), originalDB); err == nil {
				t.Fatal("narrowed recovery restored removed visitor authority")
			}
			var sessions int
			if err := f.inspect.QueryRow(t.Context(), `SELECT count(*) FROM control.workload_sessions`).Scan(&sessions); err != nil || sessions != 1 {
				t.Fatal("narrowed recovery created a replacement session", err)
			}
		})
	}
}

func TestIntegrationWorkloadExchangeFreshAssertionRetryCannotResurrect(t *testing.T) {
	for _, boundary := range []string{"lease", "identity", "fixed-window", "revoked", "removed-and-rolled-back"} {
		t.Run(boundary, func(t *testing.T) {
			f := newWorkloadExchangeRetryFixture(t)
			job, err := workload.New(f.server.URL, f.server.Client())
			if err != nil {
				t.Fatal(err)
			}
			claims := f.claims(time.Now())
			prepared, err := job.Prepare(t.Context(), f.environment.Ref, f.permission, f.issuer.Sign(t, claims), f.services)
			if err != nil {
				t.Fatal(err)
			}
			initial := prepared.Session
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
			case "removed-and-rolled-back":
				definition, err := f.owner.CreateServiceDefinition(t.Context(), "example", controlv1.CreateServiceDefinitionRequest{TeamId: f.team, SourceFingerprint: strings.Repeat("a", 64), Definition: controlv1.ServiceDefinition{Services: map[string]controlv1.ServiceDefinitionService{"api": {Protocol: "http"}}}})
				if err != nil {
					t.Fatal(err)
				}
				removed, err := f.owner.ApplyEnvironment(t.Context(), "example", f.environment.Id, controlv1.ApplyEnvironmentRequest{TeamId: f.team, ExpectedRevision: f.environment.MutationRevision, DefinitionRevision: definition.Revision})
				if err != nil {
					t.Fatal(err)
				}
				rolled, err := f.owner.ApplyEnvironment(t.Context(), "example", f.environment.Id, controlv1.ApplyEnvironmentRequest{TeamId: f.team, ExpectedRevision: removed.MutationRevision, DefinitionRevision: f.environment.AppliedDefinitionRevision, Targets: &f.environment.Targets})
				if err != nil {
					t.Fatal(err)
				}
				for _, s := range rolled.Services {
					if s.Service == "db" && s.ServiceId == prepared.Services["db"].ServiceId {
						t.Fatal("rollback reused retired service identity")
					}
				}
				want = http.StatusConflict
			}
			if boundary != "removed-and-rolled-back" {
				if _, err := f.inspect.Exec(t.Context(), query+` WHERE id=$1`, initial.Id, time.Now()); err != nil {
					t.Fatal(err)
				}
			}
			before := f.saved(t, initial.Id)
			fresh := time.Now().Truncate(time.Second)
			claims["jti"], claims["iat"], claims["nbf"], claims["exp"] = "fresh-after-authority-ended", fresh.Unix(), fresh.Unix(), fresh.Add(10*time.Minute).Unix()
			_, err = job.Prepare(t.Context(), f.environment.Ref, f.permission, f.issuer.Sign(t, claims), f.services)
			var problem *clientauthority.ProblemError
			if !errors.As(err, &problem) || problem.Status != want {
				t.Fatalf("fresh assertion revived %s authority: %v", boundary, err)
			}
			if !bytes.Equal(before, f.saved(t, initial.Id)) {
				t.Fatal("denied retry changed saved session")
			}
			if retained, err := job.Session(); err != nil || !reflect.DeepEqual(retained, initial) {
				t.Fatal("denied retry changed native session", err)
			}
			for name, s := range prepared.Services {
				if boundary == "removed-and-rolled-back" && name == "api" {
					continue
				}
				if _, err := job.CheckService(t.Context(), s.ServiceId); err == nil {
					t.Fatal("ended authority retained service access")
				}
			}
		})
	}
}

// the loss happens only after the real HTTP handler commits in PostgreSQL.
type workloadExchangeRetryTransport struct {
	base      http.RoundTripper
	loseFirst bool
	requests  []authorityv1.EnvironmentVisitorPrepareRequest
	responses []authorityv1.EnvironmentVisitorPreparation
	statuses  []int
}

func (transport *workloadExchangeRetryTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if !strings.HasSuffix(r.URL.Path, "/visitors/prepare") {
		return transport.base.RoundTrip(r)
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))
	var request authorityv1.EnvironmentVisitorPrepareRequest
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
	var preparation authorityv1.EnvironmentVisitorPreparation
	if err := json.Unmarshal(body, &preparation); err != nil {
		return nil, err
	}
	transport.responses = append(transport.responses, preparation)
	if transport.loseFirst && len(transport.responses) == 1 {
		return nil, io.ErrUnexpectedEOF
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	return response, nil
}

type workloadExchangeRetryFixture struct {
	server                    *httptest.Server
	issuer                    *githubtest.Issuer
	inspect                   *pgx.Conn
	database                  *controlstate.Database
	databaseURL               string
	owner                     *clientcontrol.Client
	authority                 *authorityv1.ClientWithResponses
	human                     controlstate.ControlSession
	team, permission, machine string
	environment               controlv1.Environment
	services                  map[string]string
	trust                     oidc.WorkloadTrust
}

func retainedVisitorBearer(token string) authorityv1.RequestEditorFn {
	return func(_ context.Context, r *http.Request) error {
		r.Header.Set("Authorization", "Bearer "+token)
		return nil
	}
}

func (f *workloadExchangeRetryFixture) issuePermission(t *testing.T, services []string, maxDuration int) string {
	t.Helper()
	ids := []string{f.environment.Id}
	r, err := f.authority.CreateEnvironmentVisitorPermissionWithResponse(t.Context(), f.team, f.machine, authorityv1.EnvironmentVisitorPermissionRequest{ProjectKey: f.environment.ProjectKey, Scope: authorityv1.EnvironmentPermissionScope{EnvironmentIds: &ids}, Services: services, MaxDurationSeconds: maxDuration, ExpiresAt: time.Now().Add(time.Hour)}, retainedVisitorBearer(f.human.AccessToken.String()))
	if err != nil || r.JSON201 == nil {
		t.Fatal("create exact visitor permission", r, err)
	}
	return r.JSON201.Id
}

func newRetainedVisitorHTTPFixture(t *testing.T, trust oidc.WorkloadTrust, services map[string]controlv1.ServiceDefinitionService, targets controlv1.EnvironmentTargets) *workloadExchangeRetryFixture {
	t.Helper()
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	ctx := t.Context()
	databaseURL := testutil.NewDisposablePostgresDatabaseURL(t, "environment_visitor_http")
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
	if trust.Audience == "" {
		trust.Audience = server.URL
	}
	issuer := githubtest.NewKeySet(t, trust.JWKSURL)
	if _, err = controlauthority.Register(mux, controlauthority.Config{ControlURL: server.URL, HTTPClient: issuer.Client, Machines: d, Publications: d}, d); err != nil {
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
	authority, err := authorityv1.NewClientWithResponses(server.URL, authorityv1.WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatal(err)
	}
	f := &workloadExchangeRetryFixture{server: server, issuer: issuer, inspect: inspect, database: d, databaseURL: databaseURL, owner: owner, authority: authority, human: human, team: human.Identity.Memberships[0].TeamID, trust: trust, services: map[string]string{}}
	f.environment = retainedHTTPEnvironment(t, owner, f.team, "example", "production", services, targets)
	wireTrust := &authorityv1.MachineTrust{Provider: authorityv1.MachineTrustProvider(trust.Provider), Issuer: trust.Issuer, JwksUrl: trust.JWKSURL, Audience: trust.Audience, Claims: trust.Claims}
	if trust.Events != nil {
		wireTrust.Events = &trust.Events
	}
	r, err := authority.RegisterMachineIdentityWithResponse(ctx, f.team, authorityv1.RegisterMachineRequest{Name: "visitor", ProofKind: "oidc", Trust: wireTrust}, retainedVisitorBearer(human.AccessToken.String()))
	if err != nil || r.JSON201 == nil {
		t.Fatal("register OIDC machine", r, err)
	}
	f.machine = r.JSON201.Id
	names := make([]string, 0, len(services))
	for name, service := range services {
		names = append(names, name)
		f.services[name] = string(service.Protocol)
	}
	f.permission = f.issuePermission(t, names, 3600)
	return f
}

func newWorkloadExchangeRetryFixture(t *testing.T) *workloadExchangeRetryFixture {
	t.Helper()
	return newRetainedVisitorHTTPFixture(t, oidc.WorkloadTrust{Provider: "github", Issuer: oidc.GitHubIssuer, JWKSURL: oidc.GitHubIssuer + "/.well-known/jwks", Claims: map[string]string{"repository": "example/repository", "repository_id": "12345", "repository_owner_id": "6789", "workflow_ref": "example/repository/.github/workflows/test.yml@refs/heads/main", "ref": "refs/heads/main"}, Events: []string{"push"}}, map[string]controlv1.ServiceDefinitionService{"api": {Protocol: "http"}, "db": {Protocol: "http"}}, controlv1.EnvironmentTargets{"api": {Address: new("api.internal:3000")}, "db": {Address: new("db.internal:5432")}})
}

func (f *workloadExchangeRetryFixture) claims(now time.Time) map[string]any {
	claims := map[string]any{"iss": f.trust.Issuer, "aud": f.trust.Audience, "iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(10 * time.Minute).Unix()}
	if f.trust.Provider == "github" {
		claims = githubtest.Claims(f.trust.Audience, now)
	}
	for name, value := range f.trust.Claims {
		claims[name] = value
	}
	return claims
}

func (f *workloadExchangeRetryFixture) saved(t *testing.T, id string) []byte {
	t.Helper()
	var value []byte
	if err := f.inspect.QueryRow(t.Context(), `SELECT to_jsonb(w)::text FROM control.workload_sessions w WHERE id=$1`, id).Scan(&value); err != nil {
		t.Fatal(err)
	}
	return value
}
