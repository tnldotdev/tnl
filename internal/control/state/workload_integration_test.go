package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/oidc"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/security/machineproof"
	"github.com/tnldotdev/tnl/internal/security/workloadproof"
)

type retainedVisitorFixture struct {
	project     environmentPublisherTestProject
	environment Environment
	machine     MachineIdentity
	permission  EnvironmentVisitorPermission
}

func retainedGitHubTrust() oidc.WorkloadTrust {
	return oidc.WorkloadTrust{Provider: "github", Issuer: oidc.GitHubIssuer, JWKSURL: "https://token.actions.githubusercontent.com/.well-known/jwks", Audience: machineTestServer, Claims: map[string]string{"repository": "example/repository", "repository_id": "12345", "repository_owner_id": "6789", "workflow_ref": "example/repository/.github/workflows/test.yml@refs/heads/main", "ref": "refs/heads/main"}, Events: []string{"push"}}
}

func newRetainedVisitorFixture(t *testing.T, d *Database, now time.Time, trust oidc.WorkloadTrust, duration int, public bool) retainedVisitorFixture {
	t.Helper()
	r := retainedEnvironmentProject(t, d, now)
	definition := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"api": {Protocol: "http"}, "db": {Protocol: "postgres"}})
	environment, err := d.CreateEnvironment(t.Context(), CreateEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint, ActorID: r.ActorID, Name: "production", DefinitionRevision: definition.Revision, Targets: EnvironmentTargets{"api": {Address: "api.internal:3000"}, "db": {Address: "db.internal:5432"}}, Public: public, IdempotencyKey: "visitor-environment", Now: now})
	if err != nil {
		t.Fatal(err)
	}
	machine, err := d.RegisterMachineIdentity(t.Context(), RegisterMachineRequest{TeamID: r.TeamID, ActorID: r.ActorID, Name: "test", ProofKind: "oidc", Trust: trust}, now)
	if err != nil {
		t.Fatal(err)
	}
	permission, err := d.CreateEnvironmentVisitorPermission(t.Context(), EnvironmentVisitorPermission{MachineID: machine.ID, TeamID: r.TeamID, ProjectKey: r.ProjectKey, Scope: EnvironmentPermissionScope{EnvironmentIDs: []string{environment.ID}}, Services: []string{"api", "db"}, MaxDurationSeconds: duration, ExpiresAt: now.Add(48 * time.Hour)}, r.ActorID, now)
	if err != nil {
		t.Fatal(err)
	}
	return retainedVisitorFixture{project: r, environment: environment, machine: machine, permission: permission}
}

func retainedVisitorPreparation(t *testing.T, f retainedVisitorFixture, now time.Time) (PrepareEnvironmentVisitorRequest, ed25519.PrivateKey) {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := oidc.GitHubExecution{Subject: "repo:example/repository:ref:refs/heads/main", JTI: "assertion", Repository: "example/repository", RepositoryID: "12345", RepositoryOwnerID: "6789", WorkflowRef: "example/repository/.github/workflows/test.yml@refs/heads/main", Ref: "refs/heads/main", Event: "push", RunID: "111", RunAttempt: "1", CheckRunID: "222", IssuedAt: now.Unix(), NotBefore: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix()}
	request := PrepareEnvironmentVisitorRequest{ProjectKey: f.project.ProjectKey, EnvironmentID: f.environment.ID, PermissionID: f.permission.ID, Audience: machineTestServer + "/v1/environment-visitor-sessions/prepare", Nonce: rand.Text(), PublicKey: public, Services: map[string]string{"api": "http", "db": "postgres"}, Proof: MachineProof{Execution: oidc.WorkloadExecution{Provider: "github", Issuer: oidc.GitHubIssuer, Audience: machineTestServer, TrustDigest: f.machine.Trust.Digest(), Subject: c.Subject, GitHub: &c, IssuedAt: c.IssuedAt, NotBefore: c.NotBefore, ExpiresAt: c.ExpiresAt}}}
	signRetainedVisitorPreparation(&request, key)
	return request, key
}
func retainedVisitorProof(execution oidc.WorkloadExecution) MachineProof {
	execution.AssertionDigest = [32]byte{}
	data, _ := json.Marshal(execution)
	execution.AssertionDigest = sha256.Sum256(data)
	return MachineProof{Assertion: string(data), Execution: execution}
}

func signRetainedVisitorPreparation(r *PrepareEnvironmentVisitorRequest, key ed25519.PrivateKey) {
	r.Proof = retainedVisitorProof(r.Proof.Execution)
	digest := sha256.Sum256([]byte(r.Proof.Assertion))
	r.Signature = ed25519.Sign(key, machineproof.EnvironmentVisitorPossession(r.ProjectKey, r.PermissionID, r.EnvironmentID, "prepare", base64.RawURLEncoding.EncodeToString(r.PublicKey), r.Nonce, r.Services, digest))
}

func retainedVisitorAssertion(t *testing.T, d *Database, session WorkloadSession, key ed25519.PrivateKey, execution oidc.WorkloadExecution) (MachineProof, []byte, string) {
	t.Helper()
	var permission, environment string
	var encoded, public []byte
	if err := d.pool.QueryRow(t.Context(), `SELECT binding.permission_id,binding.environment_id,binding.expected_protocols,session.public_key FROM control.workload_session_machines binding JOIN control.workload_sessions session ON session.id=binding.session_id WHERE binding.session_id=$1`, session.ID).Scan(&permission, &environment, &encoded, &public); err != nil {
		t.Fatal(err)
	}
	var services map[string]string
	if err := json.Unmarshal(encoded, &services); err != nil {
		t.Fatal(err)
	}
	return retainedVisitorAssertionForPreparation(PrepareEnvironmentVisitorRequest{ProjectKey: session.ProjectKey, PermissionID: permission, EnvironmentID: environment, PublicKey: public, Services: services}, session, key, execution)
}

func retainedVisitorAttachmentMessage(request PrepareEnvironmentVisitorRequest, session WorkloadSession, proof MachineProof) []byte {
	digest := sha256.Sum256([]byte(proof.Assertion))
	return machineproof.EnvironmentVisitorPossession(request.ProjectKey, request.PermissionID, request.EnvironmentID, "attach", base64.RawURLEncoding.EncodeToString(request.PublicKey), session.ID, request.Services, digest)
}

func retainedVisitorAssertionForPreparation(request PrepareEnvironmentVisitorRequest, session WorkloadSession, key ed25519.PrivateKey, execution oidc.WorkloadExecution) (MachineProof, []byte, string) {
	proof := retainedVisitorProof(execution)
	signature := ed25519.Sign(key, retainedVisitorAttachmentMessage(request, session, proof))
	return proof, signature, machineTestServer + "/v1/environment-visitor-sessions/" + session.ID + "/assertions"
}

func signWorkloadRenewal(session WorkloadSession, key ed25519.PrivateKey) WorkloadRenewal {
	sequence := session.RenewalSequence + 1
	return WorkloadRenewal{Sequence: sequence, Signature: ed25519.Sign(key, workloadproof.Renew(session.ID, sequence))}
}

func TestIntegrationWorkloadReusableProviderFixedWindow(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "workload_reusable")
	trust := oidc.WorkloadTrust{Provider: "vercel", Issuer: "https://oidc.vercel.com/acme", JWKSURL: "https://oidc.vercel.com/acme/.well-known/jwks", Audience: "https://vercel.com/acme", Claims: map[string]string{"owner": "acme", "owner_id": "team_one", "project_id": "prj_store", "environment": "production"}}
	f := newRetainedVisitorFixture(t, d, now, trust, 3600, false)
	request, key := retainedVisitorPreparation(t, f, now)
	request.Services = map[string]string{"api": "http"}
	request.Proof.Execution = oidc.WorkloadExecution{Provider: "vercel", Issuer: trust.Issuer, Audience: trust.Audience, TrustDigest: trust.Digest(), Subject: "owner:acme:project:store:environment:production", IssuedAt: now.Unix(), NotBefore: now.Unix(), ExpiresAt: now.Add(2 * time.Hour).Unix(), Vercel: &oidc.VercelExecution{Owner: "acme", OwnerID: "team_one", Project: "store", ProjectID: "prj_store", Environment: "production"}}
	signRetainedVisitorPreparation(&request, key)
	prepared, err := d.PrepareEnvironmentVisitor(t.Context(), request, now)
	if err != nil {
		t.Fatal(err)
	}
	session := prepared.Session
	for at := now.Add(30 * time.Second); at.Before(*session.ExpiresAt); at = at.Add(30 * time.Second) {
		renewed, e := d.RenewEnvironmentVisitorSession(t.Context(), session.ID, session.Credential, signWorkloadRenewal(session, key), at)
		if e != nil || !renewed.ExpiresAt.Equal(*session.ExpiresAt) {
			t.Fatal("renew changed fixed window", e)
		}
		session = renewed
	}
	if _, err = d.PrepareEnvironmentVisitor(t.Context(), request, session.ExpiresAt.Add(time.Second)); !errors.Is(err, ErrWorkloadDenied) {
		t.Fatal("nonce retry resurrected expired window", err)
	}
	_, otherKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other := request
	other.PublicKey = otherKey.Public().(ed25519.PublicKey)
	signRetainedVisitorPreparation(&other, otherKey)
	if _, err = d.PrepareEnvironmentVisitor(t.Context(), other, now); !errors.Is(err, ErrWorkloadConflict) {
		t.Fatal("new key took over original nonce", err)
	}
	other.Nonce = rand.Text()
	signRetainedVisitorPreparation(&other, otherKey)
	next, err := d.PrepareEnvironmentVisitor(t.Context(), other, session.ExpiresAt.Add(time.Second))
	if err != nil || next.Session.ID == session.ID || !next.Session.ExpiresAt.Equal(session.ExpiresAt.Add(time.Hour+time.Second)) {
		t.Fatal("valid reusable token did not start a new fixed session", err)
	}
}

func TestIntegrationWorkloadHandleCapacityAndExpiredCleanup(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "workload_handles")
	ctx := t.Context()
	f := newRetainedVisitorFixture(t, d, now, retainedGitHubTrust(), 3600, false)
	applied := f.environment
	exchange, firstKey := retainedVisitorPreparation(t, f, now)
	prepared, err := d.PrepareEnvironmentVisitor(ctx, exchange, now)
	if err != nil {
		t.Fatal(err)
	}
	first := prepared.Session
	service := applied.Services[0].ServiceID
	renewed, err := d.RenewEnvironmentVisitorSession(ctx, first.ID, first.Credential, signWorkloadRenewal(first, firstKey), now.Add(31*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if authorization, err := d.CheckWorkloadService(ctx, first.Credential, service, now.Add(32*time.Second)); err != nil || authorization.Subject != first.Subject || authorization.ValidUntil.After(*first.ExpiresAt) {
		t.Fatal("renewal changed subject or fixed lifetime", err)
	}
	expired := renewed.LeaseExpiresAt.Add(time.Second)
	if _, err := d.CheckWorkloadService(ctx, first.Credential, service, expired); !errors.Is(err, ErrWorkloadDenied) {
		t.Fatal("service permission revived expired lease", err)
	}
	secondRequest, secondKey := retainedVisitorPreparation(t, f, expired)
	secondRequest.Proof.Execution.GitHub.CheckRunID, secondRequest.Proof.Execution.GitHub.JTI = "333", "second"
	signRetainedVisitorPreparation(&secondRequest, secondKey)
	second, err := d.PrepareEnvironmentVisitor(ctx, secondRequest, expired)
	if err != nil {
		t.Fatal(err)
	}
	if authorization, err := d.CheckWorkloadService(ctx, second.Session.Credential, service, expired); err != nil || authorization.Subject != second.Session.Subject {
		t.Fatal("independent workload was blocked by expired sibling", err)
	}
	maximumPermission, err := d.CreateEnvironmentVisitorPermission(ctx, EnvironmentVisitorPermission{MachineID: f.machine.ID, TeamID: f.project.TeamID, ProjectKey: f.project.ProjectKey, Scope: EnvironmentPermissionScope{EnvironmentIDs: []string{f.environment.ID}}, Services: []string{"api", "db"}, MaxDurationSeconds: 6 * 60 * 60, ExpiresAt: now.Add(48 * time.Hour)}, f.project.ActorID, expired)
	if err != nil {
		t.Fatal(err)
	}
	maximumFixture := f
	maximumFixture.permission = maximumPermission
	maximumRequest, key := retainedVisitorPreparation(t, maximumFixture, expired)
	maximumRequest.Proof.Execution.GitHub.CheckRunID, maximumRequest.Proof.Execution.GitHub.JTI = "444", "maximum"
	signRetainedVisitorPreparation(&maximumRequest, key)
	maximumPreparation, err := d.PrepareEnvironmentVisitor(ctx, maximumRequest, expired)
	if err != nil {
		t.Fatal(err)
	}
	maximum := maximumPreparation.Session
	if maximumPermission.ID == f.permission.ID || maximum.ID == first.ID || maximum.ID == second.Session.ID || !maximum.ExpiresAt.Equal(expired.Add(6*time.Hour)) {
		t.Fatal("six-hour fixed window changed")
	}
	for _, original := range []struct {
		request PrepareEnvironmentVisitorRequest
		key     ed25519.PrivateKey
	}{{exchange, firstKey}, {secondRequest, secondKey}} {
		rebound := original.request
		rebound.PermissionID = maximumPermission.ID
		signRetainedVisitorPreparation(&rebound, original.key)
		if _, err := d.PrepareEnvironmentVisitor(ctx, rebound, expired); !errors.Is(err, ErrWorkloadConflict) {
			t.Fatal("original nonce rebound to the six-hour permission", err)
		}
	}
	if recovered, err := d.PrepareEnvironmentVisitor(ctx, secondRequest, expired); err != nil || !reflect.DeepEqual(recovered.Session, second.Session) {
		t.Fatal("same-permission retry adopted the six-hour window", err)
	}
	at := expired.Add(30 * time.Second)
	fresh := secondRequest.Proof.Execution
	fresh.GitHub = new(*fresh.GitHub)
	fresh.IssuedAt, fresh.NotBefore, fresh.ExpiresAt = at.Unix(), at.Unix(), at.Add(5*time.Minute).Unix()
	fresh.GitHub.IssuedAt, fresh.GitHub.NotBefore, fresh.GitHub.ExpiresAt = fresh.IssuedAt, fresh.NotBefore, fresh.ExpiresAt
	fresh.GitHub.JTI = "second-refreshed"
	proof, signature, audience := retainedVisitorAssertion(t, d, second.Session, secondKey, fresh)
	rebound := secondRequest
	rebound.PermissionID = maximumPermission.ID
	reboundSignature := ed25519.Sign(secondKey, retainedVisitorAttachmentMessage(rebound, second.Session, proof))
	if _, err := d.AttachEnvironmentVisitorAssertion(ctx, second.Session.ID, second.Session.Credential, proof, reboundSignature, audience, at); !errors.Is(err, ErrMachineDenied) {
		t.Fatal("attachment rebound the original session to the six-hour permission", err)
	}
	attached, err := d.AttachEnvironmentVisitorAssertion(ctx, second.Session.ID, second.Session.Credential, proof, signature, audience, at)
	if err != nil || !attached.ExpiresAt.Equal(*second.Session.ExpiresAt) || attached.Binding != second.Session.Binding {
		t.Fatal("fresh proof adopted the six-hour window", err)
	}
	if renewed, err := d.RenewEnvironmentVisitorSession(ctx, second.Session.ID, second.Session.Credential, signWorkloadRenewal(attached, secondKey), at); err != nil || !renewed.ExpiresAt.Equal(expired.Add(time.Hour)) || renewed.Binding != second.Session.Binding {
		t.Fatal("renewal adopted the six-hour window", err)
	}
	var boundPermission string
	var originalDuration int
	if err := d.pool.QueryRow(ctx, `SELECT binding.permission_id,permission.max_duration_seconds FROM control.workload_session_machines binding JOIN control.machine_workload_permissions permission ON permission.id=binding.permission_id WHERE binding.session_id=$1`, second.Session.ID).Scan(&boundPermission, &originalDuration); err != nil || boundPermission != f.permission.ID || originalDuration != 3600 {
		t.Fatal("attachment or renewal changed the original duration permission", err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	// native certificates retain the fixed workload window; HTTP permissions
	// have their own short-lived certificate and local policy lease coverage.
	nativeService := ""
	for _, candidate := range applied.Services {
		if candidate.Service == "db" {
			nativeService = candidate.ServiceID
		}
	}
	certificate, err := d.IssueWorkloadServiceClientCertificate(ctx, maximum.Credential, nativeService, csr, expired)
	if err != nil {
		t.Fatal(err)
	}
	if !certificate.ExpiresAt.Equal(maximum.ExpiresAt.Truncate(time.Second)) {
		t.Fatal("maximum certificate clipped to renewable lease")
	}
}

func TestIntegrationWorkloadReplayNarrowingAndFixedWindow(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "workload_replay")
	ctx := t.Context()
	f := newRetainedVisitorFixture(t, d, now, retainedGitHubTrust(), 3600, false)
	r := f.project
	exchange, key := retainedVisitorPreparation(t, f, now)
	var wg sync.WaitGroup
	results := make(chan WorkloadSession, 8)
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() { v, err := d.PrepareEnvironmentVisitor(ctx, exchange, now); results <- v.Session; errs <- err })
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var original WorkloadSession
	for v := range results {
		if original.ID != "" && !reflect.DeepEqual(original, v) {
			t.Fatal("lost reply changed workload session")
		}
		original = v
	}
	if !original.ExpiresAt.Equal(now.Add(time.Hour)) || !original.LeaseExpiresAt.Equal(now.Add(90*time.Second)) || len(original.ServiceIDs) != 2 {
		t.Fatal("incorrect execution window", original)
	}
	_, newKey, _ := ed25519.GenerateKey(rand.Reader)
	replacement := exchange
	replacement.PublicKey = newKey.Public().(ed25519.PublicKey)
	signRetainedVisitorPreparation(&replacement, newKey)
	if _, err := d.PrepareEnvironmentVisitor(ctx, replacement, now); !errors.Is(err, ErrWorkloadConflict) {
		t.Fatal("new key stole session", err)
	}
	for name, edit := range map[string]func(*PrepareEnvironmentVisitorRequest){"repository-id": func(r *PrepareEnvironmentVisitorRequest) { r.Proof.Execution.GitHub.RepositoryID = "999" }, "owner-id": func(r *PrepareEnvironmentVisitorRequest) { r.Proof.Execution.GitHub.RepositoryOwnerID = "999" }, "workflow": func(r *PrepareEnvironmentVisitorRequest) {
		r.Proof.Execution.GitHub.WorkflowRef = "example/repository/.github/workflows/evil.yml@refs/heads/main"
	}, "ref": func(r *PrepareEnvironmentVisitorRequest) { r.Proof.Execution.GitHub.Ref = "refs/heads/other" }, "event": func(r *PrepareEnvironmentVisitorRequest) { r.Proof.Execution.GitHub.Event = "pull_request" }} {
		t.Run(name, func(t *testing.T) {
			bad := exchange
			bad.Proof.Execution.GitHub = new(*exchange.Proof.Execution.GitHub)
			edit(&bad)
			signRetainedVisitorPreparation(&bad, key)
			if _, err := d.PrepareEnvironmentVisitor(ctx, bad, now); !errors.Is(err, ErrMachineDenied) {
				t.Fatal("wrong claims accepted", err)
			}
		})
	}
	replay := exchange
	replay.Proof.Execution.GitHub = new(*exchange.Proof.Execution.GitHub)
	replay.Proof.Execution.GitHub.CheckRunID = "333"
	signRetainedVisitorPreparation(&replay, key)
	if _, err := d.PrepareEnvironmentVisitor(ctx, replay, now); !errors.Is(err, ErrWorkloadConflict) {
		t.Fatal("jti moved to another execution", err)
	}
	renewed, err := d.RenewEnvironmentVisitorSession(ctx, original.ID, original.Credential, signWorkloadRenewal(original, key), now.Add(30*time.Second))
	if err != nil || !renewed.ExpiresAt.Equal(*original.ExpiresAt) || !renewed.LeaseExpiresAt.Equal(now.Add(120*time.Second)) {
		t.Fatalf("renew changed absolute window: lease=%s want=%s fixed=%s want=%s err=%v", renewed.LeaseExpiresAt, now.Add(120*time.Second), renewed.ExpiresAt, original.ExpiresAt, err)
	}
	for _, id := range original.ServiceIDs {
		if _, err := d.CheckWorkloadService(ctx, original.Credential, id, now.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	// removal retires the exact accepted database ID; re-adding its logical name
	// cannot restore the issued right, even with the original permission intact.
	definition := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"api": {Protocol: "http"}})
	applied, err := d.ApplyEnvironment(ctx, ApplyEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, EnvironmentApplication: EnvironmentApplication{EnvironmentID: f.environment.ID, ExpectedRevision: f.environment.MutationRevision, DefinitionRevision: definition.Revision, Targets: EnvironmentTargets{"api": {Address: "api.internal:3000"}}}, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	services, err := d.ListWorkloadServices(ctx, original.Credential, now.Add(time.Minute))
	if err != nil || len(services) != 1 || services[0].Service != "api" {
		t.Fatal("narrowing failed", services, err)
	}
	definition = environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"api": {Protocol: "http"}, "db": {Protocol: "postgres"}})
	_, err = d.ApplyEnvironment(ctx, ApplyEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, EnvironmentApplication: EnvironmentApplication{EnvironmentID: applied.ID, ExpectedRevision: applied.MutationRevision, DefinitionRevision: definition.Revision, Targets: f.environment.Targets}, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	services, err = d.ListWorkloadServices(ctx, original.Credential, now.Add(time.Minute))
	if err != nil || len(services) != 1 {
		t.Fatal("re-added service expanded issued session", services, err)
	}
	if _, err = d.PrepareEnvironmentVisitor(ctx, exchange, now.Add(time.Minute)); !errors.Is(err, ErrWorkloadConflict) {
		t.Fatal("same nonce accepted a replacement immutable service ID", err)
	}
	for at := now.Add(90 * time.Second); at.Before(*original.ExpiresAt); at = at.Add(30 * time.Second) {
		if !renewed.IdentityExpiresAt.After(at.Add(WorkloadLease)) {
			fresh := exchange.Proof.Execution
			fresh.GitHub = new(*fresh.GitHub)
			fresh.IssuedAt, fresh.NotBefore, fresh.ExpiresAt = at.Unix(), at.Unix(), at.Add(5*time.Minute).Unix()
			fresh.GitHub.IssuedAt, fresh.GitHub.NotBefore, fresh.GitHub.ExpiresAt = fresh.IssuedAt, fresh.NotBefore, fresh.ExpiresAt
			fresh.GitHub.JTI = fmt.Sprint("refresh-", at.Unix())
			proof, signature, audience := retainedVisitorAssertion(t, d, original, key, fresh)
			var err error
			renewed, err = d.AttachEnvironmentVisitorAssertion(ctx, original.ID, original.Credential, proof, signature, audience, at)
			if err != nil {
				t.Fatal("fresh same-identity proof could not renew the fixed session", err)
			}
		}
		if renewed, err = d.RenewEnvironmentVisitorSession(ctx, original.ID, original.Credential, signWorkloadRenewal(renewed, key), at); err != nil {
			t.Fatal(err)
		}
		if len(renewed.ServiceIDs) != 1 || renewed.ServiceIDs[0] != services[0].ID {
			t.Fatal("renewal restored narrowed rights")
		}
	}
	if _, err = d.RenewEnvironmentVisitorSession(ctx, original.ID, original.Credential, signWorkloadRenewal(renewed, key), *original.ExpiresAt); !errors.Is(err, ErrWorkloadDenied) {
		t.Fatal("renew crossed absolute deadline", err)
	}
	if _, err = d.CheckWorkloadService(ctx, original.Credential, services[0].ID, *original.ExpiresAt); !errors.Is(err, ErrWorkloadDenied) {
		t.Fatal("expired session still authorized", err)
	}
}

func TestIntegrationWorkloadPrivateAndPublicAdmission(t *testing.T) {
	d, now, _, leases := newConnectorPairPrerequisites(t)
	ctx := t.Context()
	f := newRetainedVisitorFixture(t, d, now, retainedGitHubTrust(), 10, true)
	r, applied := f.project, f.environment
	replica := enrollTestEnvironment(t, d, r, applied)
	var a EnvironmentPublisherAssignment
	for _, candidate := range replica.assignments.Services {
		if candidate.Configuration.Protocol == "postgres" {
			a = candidate
		}
	}
	access := environmentAssignmentAccess(t, d, replica, a, now)
	service, err := d.GetServiceForPublisher(ctx, a.ServiceID, access.PublisherIdentity, now)
	if err != nil {
		t.Fatal(err)
	}
	run := readyAppliedServiceRun(t, d, access, replica.private, service, leases, now, &replica.assignments.Environment)
	exchange, key := retainedVisitorPreparation(t, f, now)
	prepared, err := d.PrepareEnvironmentVisitor(ctx, exchange, now)
	if err != nil {
		t.Fatal(err)
	}
	session := prepared.Session
	port := 0
	for _, s := range applied.Services {
		if s.ServiceID == service.ID {
			port = s.Port
		}
	}
	var ingresses []IngressLease
	for _, name := range []string{"workload-a", "workload-b"} {
		lease, err := d.RegisterIngress(ctx, IngressRegistration{IngressID: name, IngressRunID: mustOpaqueID(t, opaqueid.IngressRunPrefix), ProtocolVersion: 1, ConnectionCapacity: 64, IngressPoolID: PrimaryIngressPoolID, ServicePorts: []int32{int32(port)}}, now, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		ingresses = append(ingresses, lease)
	}
	source := netip.MustParseAddr("192.0.2.44")
	lease := ingresses[0]
	request := ConnectorPeerPairRequest{ServiceID: service.ID, ServiceRunID: run.RunID, RunNumber: run.RunNumber, PublisherIdentityID: access.PublisherIdentity.ID, Subject: session.Subject, Source: WorkloadTokenSource{Credential: session.Credential}, IdempotencyKey: "connect", Action: "create", RequestedAt: now, ExpectedRelays: testConnectorPairRelays(run, leases)}
	message, err := request.proof().Message()
	if err != nil {
		t.Fatal(err)
	}
	request.Signature = ed25519.Sign(key, message)
	pair, err := d.PrepareConnectorPeerPair(ctx, request, now)
	if err != nil || pair.Subject != session.Subject || pair.Subject.IdentityID != "" || pair.Subject.DeviceID != "" || !pair.ExpiresAt.Equal(*session.ExpiresAt) {
		t.Fatal("native workload subject/fixed expiry changed", err)
	}
	retry, err := d.PrepareConnectorPeerPair(ctx, request, now)
	if err != nil || retry.ID != pair.ID || retry.Key != pair.Key || retry.DeliveryID != pair.DeliveryID || retry.DeliveryGeneration != pair.DeliveryGeneration || !retry.ExpiresAt.Equal(pair.ExpiresAt) {
		t.Fatal("native lost-reply instability", err)
	}
	for slot, relay := range pair.Relays {
		if _, err := testClaimConnectorPeerPairLeg(t, d, ctx, relay.RelayLease, source, testConnectorLegProof(t, pair, slot, now, key), now); err != nil {
			t.Fatal(err)
		}
	}
	visitor := mustOpaqueID(t, opaqueid.VisitorConnectionPrefix)
	delivered, err := d.DeliverConnectorPeerPair(ctx, service.ID, run.RunID, pair.ID, pair.DeliveryGeneration, run.Token, now.Add(time.Second))
	if err != nil || !delivered.ExpiresAt.Equal(*session.ExpiresAt) {
		t.Fatal("native workload recheck deadline", err)
	}
	if _, err := d.DeliverConnectorPeerPair(ctx, service.ID, run.RunID, pair.ID, pair.DeliveryGeneration, session.Credential, now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("workload credential authenticated as publisher run", err)
	}
	if err := d.ConfirmConnectorPeerPairPrepared(ctx, service.ID, run.RunID, pair.ID, run.Token, ConnectorPeerPairPrepared{Phase: "installed", DeliveryID: pair.DeliveryID, DeliveryGeneration: pair.DeliveryGeneration, BindingExpiresAt: delivered.ExpiresAt}, now); err != nil {
		t.Fatal(err)
	}
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	certificate, err := d.IssueWorkloadServiceClientCertificate(ctx, session.Credential, service.ID, csr, now)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(certificate.CertificatePEM))
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := d.ServiceClientIssuer(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if subject, err := issuer.Subject(leaf, service.ID, now); err != nil || subject != session.Subject {
		t.Fatal("certificate used a human subject", subject, err)
	}
	direct := mustOpaqueID(t, opaqueid.VisitorConnectionPrefix)
	if _, err = d.AdmitPublicServiceVisitor(ctx, lease.IngressLeaseIdentity, PrimaryIngressPoolID, direct, port, source, now); err != nil {
		t.Fatal(err)
	}
	decision, err := d.AuthorizeServiceClientCertificate(ctx, service.ID, run.RunID, run.Token, direct, run.RunNumber, source, block.Bytes, now)
	if err != nil || !decision.Allowed || decision.Admitted || !decision.ValidUntil.Equal(*session.ExpiresAt) {
		t.Fatal("public workload certificate authorization", decision, err)
	}
	if err = d.PromotePublicServiceVisitor(ctx, lease.IngressLeaseIdentity, direct, now); err != nil {
		t.Fatal(err)
	}
	status, err := d.PublicServiceVisitorStatus(ctx, lease.IngressLeaseIdentity, direct, now.Add(time.Second))
	if err != nil || status.State != PublicServiceVisitorAllowed {
		t.Fatal("public active recheck", status, err)
	}
	for _, connector := range []bool{false, true} {
		observation := serviceaudit.Observation{EventID: serviceaudit.NewID(), ServiceID: service.ID, ServiceKind: "service", EventType: "connection.open", OccurredAt: now, RunID: run.RunID, RunNumber: run.RunNumber, VisitorConnectionID: direct, SourceIP: source.String(), Outcome: "allowed"}
		if connector {
			observation.VisitorConnectionID, observation.PairID, observation.DeliveryGeneration = visitor, pair.ID, pair.DeliveryGeneration
			if _, err := d.IngestServiceRunObservations(ctx, service.ID, run.RunID, run.Token, run.RunNumber, serviceaudit.Batch{Events: []serviceaudit.Observation{observation}}, now); err != nil {
				t.Fatal("native audit scanned workload as human", err)
			}
			continue
		}
		if _, err := d.IngestIngressServiceObservations(ctx, lease.IngressLeaseIdentity, serviceaudit.Batch{Events: []serviceaudit.Observation{observation}}, now); err != nil {
			t.Fatal("audit scanned workload as a human", err)
		}
	}
	if _, err := d.DeliverConnectorPeerPair(ctx, service.ID, run.RunID, pair.ID, pair.DeliveryGeneration, run.Token, *session.ExpiresAt); err == nil {
		t.Fatal("native authority outlived job")
	}
	if _, err = d.AuthorizeServiceClientCertificate(ctx, service.ID, run.RunID, run.Token, direct, run.RunNumber, source, block.Bytes, *session.ExpiresAt); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("public stream outlived job", err)
	}
	// policy removal denies still-live admissions before their earlier deadline.
	if err = d.RevokeEnvironmentVisitorPermission(ctx, r.TeamID, f.permission.ID, r.ActorID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.DeliverConnectorPeerPair(ctx, service.ID, run.RunID, pair.ID, pair.DeliveryGeneration, run.Token, now.Add(2*time.Second)); err == nil {
		t.Fatal("native authority survived policy removal")
	}
	if decision, err := d.AuthorizeServiceClientCertificate(ctx, service.ID, run.RunID, run.Token, direct, run.RunNumber, source, block.Bytes, now.Add(2*time.Second)); !errors.Is(err, ErrServiceAccess) || decision.Allowed {
		t.Fatal("public stream survived policy removal", decision, err)
	}
}

func TestIntegrationWorkloadApplyRaceAndExplicitScope(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "workload_policy_race")
	ctx := t.Context()
	f := newRetainedVisitorFixture(t, d, now, retainedGitHubTrust(), 3600, false)
	r := f.project
	exchange, key := retainedVisitorPreparation(t, f, now)
	exchange.Services = map[string]string{"api": "http"}
	signRetainedVisitorPreparation(&exchange, key)
	prepared, err := d.PrepareEnvironmentVisitor(ctx, exchange, now)
	if err != nil {
		t.Fatal(err)
	}
	first := prepared.Session
	if len(first.ServiceIDs) != 1 {
		t.Fatal("subset was not preserved")
	}
	broader := exchange
	broader.Services = map[string]string{"api": "http", "db": "postgres"}
	signRetainedVisitorPreparation(&broader, key)
	if _, err = d.PrepareEnvironmentVisitor(ctx, broader, now); !errors.Is(err, ErrWorkloadConflict) {
		t.Fatal("execution unioned service grants", err)
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make(chan error, 9)
	for i := range 8 {
		wg.Go(func() {
			<-start
			request := exchange
			request.Proof.Execution.GitHub = new(*exchange.Proof.Execution.GitHub)
			request.Nonce = rand.Text()
			request.Proof.Execution.GitHub.CheckRunID = fmt.Sprint(1000 + i)
			request.Proof.Execution.GitHub.JTI = fmt.Sprint(1000 + i)
			signRetainedVisitorPreparation(&request, key)
			_, err := d.PrepareEnvironmentVisitor(ctx, request, now)
			if err != nil && !errors.Is(err, ErrMachineDenied) {
				errs <- err
			} else {
				errs <- nil
			}
		})
	}
	wg.Go(func() {
		<-start
		err := d.RevokeEnvironmentVisitorPermission(ctx, r.TeamID, f.permission.ID, r.ActorID, now)
		errs <- err
	})
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err = d.CheckWorkloadService(ctx, first.Credential, first.ServiceIDs[0], now); !errors.Is(err, ErrWorkloadDenied) {
		t.Fatal("apply race left a usable workload", err)
	}
	var active int
	if err = d.pool.QueryRow(ctx, `SELECT count(*) FROM control.workload_sessions session JOIN control.workload_session_machines binding ON binding.session_id=session.id JOIN control.machine_workload_permissions permission ON permission.id=binding.permission_id WHERE session.team_id=$1 AND session.revoked_at IS NULL AND permission.revoked_at IS NULL`, r.TeamID).Scan(&active); err != nil || active != 0 {
		t.Fatal("apply failed to fence concurrent starts", active, err)
	}
	var people, devices int
	if err = d.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM control.identities WHERE id IN(SELECT subject_id FROM control.connector_peer_pairs WHERE subject_kind='workload_session')),(SELECT count(*) FROM control.visitor_devices WHERE id IN(SELECT subject_id FROM control.connector_peer_pairs WHERE subject_kind='workload_session'))`).Scan(&people, &devices); err != nil || people != 0 || devices != 0 {
		t.Fatal("workload created a person or enrolled device", people, devices, err)
	}
}
