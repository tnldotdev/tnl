package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
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
	"github.com/tnldotdev/tnl/internal/security/workloadproof"
)

func workloadConfiguration() ProjectConfiguration {
	return ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{"production": {}}, Services: map[string]ProjectServiceConfiguration{"api": {PublisherGroup: "production", Target: "api.internal:3000"}, "db": {PublisherGroup: "production", Protocol: "postgres", Target: "db.internal:5432"}}, Workloads: map[string]ProjectWorkload{"test": {Provider: "github", GitHub: &ProjectWorkloadGitHub{Repository: "example/repository", RepositoryID: "12345", RepositoryOwnerID: "6789", WorkflowRef: "example/repository/.github/workflows/test.yml@refs/heads/main", Ref: "refs/heads/main", Events: []string{"push"}}, Services: []string{"api", "db"}, MaxDurationSeconds: 3600}}}
}

func workloadExchange(t *testing.T, r ApplyProjectConfigurationRequest, now time.Time) (ExchangeWorkloadRequest, ed25519.PrivateKey) {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := oidc.GitHubExecution{Subject: "repo:example/repository:ref:refs/heads/main", JTI: "assertion", Repository: "example/repository", RepositoryID: "12345", RepositoryOwnerID: "6789", WorkflowRef: "example/repository/.github/workflows/test.yml@refs/heads/main", Ref: "refs/heads/main", Event: "push", RunID: "111", RunAttempt: "1", CheckRunID: "222", IssuedAt: now.Unix(), NotBefore: now.Unix(), ExpiresAt: now.Add(5 * time.Minute).Unix()}
	request := ExchangeWorkloadRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint, Nonce: rand.Text(), Workload: "test", Execution: oidc.WorkloadExecution{Provider: "github", Issuer: oidc.GitHubIssuer, Subject: c.Subject, GitHub: &c, IssuedAt: c.IssuedAt, NotBefore: c.NotBefore, ExpiresAt: c.ExpiresAt}, PublicKey: public}
	signWorkloadRequest(&request, key)
	return request, key
}
func signWorkloadRequest(r *ExchangeWorkloadRequest, key ed25519.PrivateKey) {
	data, _ := json.Marshal(r.Execution)
	r.Execution.AssertionDigest = sha256.Sum256(data)
	r.Signature = ed25519.Sign(key, workloadproof.Exchange(r.TeamID, r.ProjectKey, r.Workload, r.SourceFingerprint, r.Nonce, r.Execution.AssertionDigest, r.Services))
}

func TestIntegrationWorkloadReusableProviderFixedWindow(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "workload_reusable")
	r := appliedProjectRequest(t, d, now)
	r.Configuration = workloadConfiguration()
	trust := oidc.WorkloadTrust{Provider: "vercel", Issuer: "https://oidc.vercel.com/acme", JWKSURL: "https://oidc.vercel.com/acme/.well-known/jwks", Audience: "https://vercel.com/acme", Claims: map[string]string{"owner": "acme", "owner_id": "team_one", "project_id": "prj_store", "environment": "production"}}
	r.Configuration.Workloads = map[string]ProjectWorkload{"storefront": {Provider: "vercel", Trust: trust, Services: []string{"api"}, MaxDurationSeconds: 3600}}
	if _, err := d.ApplyProjectConfiguration(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	request, key := workloadExchange(t, r, now)
	request.Workload = "storefront"
	request.Execution = oidc.WorkloadExecution{Provider: "vercel", Issuer: trust.Issuer, Audience: trust.Audience, TrustDigest: trust.Digest(), Subject: "owner:acme:project:store:environment:production", IssuedAt: now.Unix(), NotBefore: now.Unix(), ExpiresAt: now.Add(2 * time.Hour).Unix(), Vercel: &oidc.VercelExecution{Owner: "acme", OwnerID: "team_one", Project: "store", ProjectID: "prj_store", Environment: "production"}}
	signWorkloadRequest(&request, key)
	session, err := d.ExchangeWorkload(t.Context(), request, now)
	if err != nil {
		t.Fatal(err)
	}
	for at := now.Add(30 * time.Second); at.Before(session.ExpiresAt); at = at.Add(30 * time.Second) {
		renewed, e := d.RenewWorkloadSession(t.Context(), session.ID, session.Credential, at)
		if e != nil || !renewed.ExpiresAt.Equal(session.ExpiresAt) {
			t.Fatal("renew changed fixed window", e)
		}
	}
	if _, err = d.ExchangeWorkload(t.Context(), request, session.ExpiresAt.Add(time.Second)); !errors.Is(err, ErrWorkloadDenied) {
		t.Fatal("nonce retry resurrected expired window", err)
	}
	_, otherKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other := request
	other.PublicKey = otherKey.Public().(ed25519.PublicKey)
	signWorkloadRequest(&other, otherKey)
	if _, err = d.ExchangeWorkload(t.Context(), other, now); !errors.Is(err, ErrWorkloadConflict) {
		t.Fatal("new key took over original nonce", err)
	}
	other.Nonce = rand.Text()
	signWorkloadRequest(&other, otherKey)
	next, err := d.ExchangeWorkload(t.Context(), other, session.ExpiresAt.Add(time.Second))
	if err != nil || next.ID == session.ID || !next.ExpiresAt.Equal(session.ExpiresAt.Add(time.Hour+time.Second)) {
		t.Fatal("valid reusable token did not start a new fixed session", err)
	}
}

func TestIntegrationWorkloadHandleCapacityAndExpiredCleanup(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "workload_handles")
	ctx := t.Context()
	r := appliedProjectRequest(t, d, now)
	r.Configuration = workloadConfiguration()
	applied, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	exchange, _ := workloadExchange(t, r, now)
	first, err := d.ExchangeWorkload(ctx, exchange, now)
	if err != nil {
		t.Fatal(err)
	}
	service := applied.Services[0].ServiceID
	renewed, err := d.RenewWorkloadSession(ctx, first.ID, first.Credential, now.Add(31*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if authorization, err := d.CheckWorkloadService(ctx, first.Credential, service, now.Add(32*time.Second)); err != nil || authorization.Subject != first.Subject || authorization.ValidUntil.After(first.ExpiresAt) {
		t.Fatal("renewal changed subject or fixed lifetime", err)
	}
	expired := renewed.LeaseExpiresAt.Add(time.Second)
	if _, err := d.CheckWorkloadService(ctx, first.Credential, service, expired); !errors.Is(err, ErrWorkloadDenied) {
		t.Fatal("service permission revived expired lease", err)
	}
	secondRequest, key := workloadExchange(t, r, expired)
	secondRequest.Execution.GitHub.CheckRunID, secondRequest.Execution.GitHub.JTI = "333", "second"
	signWorkloadRequest(&secondRequest, key)
	second, err := d.ExchangeWorkload(ctx, secondRequest, expired)
	if err != nil {
		t.Fatal(err)
	}
	if authorization, err := d.CheckWorkloadService(ctx, second.Credential, service, expired); err != nil || authorization.Subject != second.Subject {
		t.Fatal("independent workload was blocked by expired sibling", err)
	}
	r.ExpectedRevision = applied.Revision
	policy := r.Configuration.Workloads["test"]
	policy.MaxDurationSeconds = 6 * 60 * 60
	r.Configuration.Workloads["test"] = policy
	if _, err := d.ApplyProjectConfiguration(ctx, r); err != nil {
		t.Fatal(err)
	}
	maximumRequest, key := workloadExchange(t, r, expired)
	maximumRequest.Execution.GitHub.CheckRunID, maximumRequest.Execution.GitHub.JTI = "444", "maximum"
	signWorkloadRequest(&maximumRequest, key)
	maximum, err := d.ExchangeWorkload(ctx, maximumRequest, expired)
	if err != nil {
		t.Fatal(err)
	}
	if !maximum.ExpiresAt.Equal(expired.Add(6 * time.Hour)) {
		t.Fatal("six-hour fixed window changed")
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
	r := appliedProjectRequest(t, d, now)
	r.Configuration = workloadConfiguration()
	applied, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	r.ExpectedRevision = applied.Revision
	exchange, key := workloadExchange(t, r, now)
	var wg sync.WaitGroup
	results := make(chan WorkloadSession, 8)
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() { v, err := d.ExchangeWorkload(ctx, exchange, now); results <- v; errs <- err })
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
	signWorkloadRequest(&replacement, newKey)
	if _, err = d.ExchangeWorkload(ctx, replacement, now); !errors.Is(err, ErrWorkloadConflict) {
		t.Fatal("new key stole session", err)
	}
	for name, edit := range map[string]func(*ExchangeWorkloadRequest){"repository-id": func(r *ExchangeWorkloadRequest) { r.Execution.GitHub.RepositoryID = "999" }, "owner-id": func(r *ExchangeWorkloadRequest) { r.Execution.GitHub.RepositoryOwnerID = "999" }, "workflow": func(r *ExchangeWorkloadRequest) {
		r.Execution.GitHub.WorkflowRef = "example/repository/.github/workflows/evil.yml@refs/heads/main"
	}, "ref": func(r *ExchangeWorkloadRequest) { r.Execution.GitHub.Ref = "refs/heads/other" }, "event": func(r *ExchangeWorkloadRequest) { r.Execution.GitHub.Event = "pull_request" }} {
		t.Run(name, func(t *testing.T) {
			bad := exchange
			bad.Execution.GitHub = new(*exchange.Execution.GitHub)
			edit(&bad)
			signWorkloadRequest(&bad, key)
			if _, err := d.ExchangeWorkload(ctx, bad, now); !errors.Is(err, ErrWorkloadDenied) {
				t.Fatal("wrong claims accepted", err)
			}
		})
	}
	replay := exchange
	replay.Execution.GitHub = new(*exchange.Execution.GitHub)
	replay.Execution.GitHub.CheckRunID = "333"
	signWorkloadRequest(&replay, key)
	if _, err = d.ExchangeWorkload(ctx, replay, now); !errors.Is(err, ErrWorkloadConflict) {
		t.Fatal("jti moved to another execution", err)
	}
	renewed, err := d.RenewWorkloadSession(ctx, original.ID, original.Credential, now.Add(30*time.Second))
	if err != nil || !renewed.ExpiresAt.Equal(original.ExpiresAt) || !renewed.LeaseExpiresAt.Equal(now.Add(120*time.Second)) {
		t.Fatal("renew changed absolute window", err)
	}
	for _, id := range original.ServiceIDs {
		if _, err = d.CheckWorkloadService(ctx, original.Credential, id, now.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	p := r.Configuration.Workloads["test"]
	p.Services = []string{"api"}
	r.Configuration.Workloads["test"] = p
	applied, err = d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	r.ExpectedRevision = applied.Revision
	services, err := d.ListWorkloadServices(ctx, original.Credential, now.Add(time.Minute))
	if err != nil || len(services) != 1 || services[0].Service != "api" {
		t.Fatal("narrowing failed", services, err)
	}
	p.Services = []string{"api", "db"}
	r.Configuration.Workloads["test"] = p
	applied, err = d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	r.ExpectedRevision = applied.Revision
	services, err = d.ListWorkloadServices(ctx, original.Credential, now.Add(time.Minute))
	if err != nil || len(services) != 1 {
		t.Fatal("re-added service expanded issued session", services, err)
	}
	if _, err = d.ExchangeWorkload(ctx, exchange, now.Add(time.Minute)); err != nil {
		t.Fatal("same JWT/key could not resume after policy addition", err)
	}
	for at := now.Add(90 * time.Second); at.Before(original.ExpiresAt); at = at.Add(30 * time.Second) {
		if _, err = d.RenewWorkloadSession(ctx, original.ID, original.Credential, at); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = d.RenewWorkloadSession(ctx, original.ID, original.Credential, original.ExpiresAt); !errors.Is(err, ErrWorkloadDenied) {
		t.Fatal("renew crossed absolute deadline", err)
	}
	if _, err = d.CheckWorkloadService(ctx, original.Credential, services[0].ID, original.ExpiresAt); !errors.Is(err, ErrWorkloadDenied) {
		t.Fatal("expired session still authorized", err)
	}
}

func TestIntegrationWorkloadPrivateAndPublicAdmission(t *testing.T) {
	d, now, _, leases := newConnectorPairPrerequisites(t)
	ctx := t.Context()
	r := appliedProjectRequest(t, d, now)
	r.Configuration = workloadConfiguration()
	p := r.Configuration.Workloads["test"]
	p.MaxDurationSeconds = 10
	r.Configuration.Workloads["test"] = p
	group := r.Configuration.PublisherGroups["production"]
	group.Public = true
	r.Configuration.PublisherGroups["production"] = group
	applied, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	e, err := d.IssuePublisherGroupEnrollment(ctx, r.TeamID, r.ProjectKey, "production", r.ActorID, 1, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	replica := enrollAppliedGroup(t, d, r, e, now)
	var a PublisherGroupServiceAssignment
	for _, candidate := range replica.assignments.Services {
		if candidate.Configuration.Protocol == "postgres" {
			a = candidate
		}
	}
	access := groupAssignmentAccess(t, d, replica, a, now)
	service, err := d.GetServiceForPublisher(ctx, a.ServiceID, access.PublisherIdentity, now)
	if err != nil {
		t.Fatal(err)
	}
	run := readyAppliedServiceRun(t, d, access, replica.private, service, leases, now)
	exchange, key := workloadExchange(t, r, now)
	session, err := d.ExchangeWorkload(ctx, exchange, now)
	if err != nil {
		t.Fatal(err)
	}
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
	if err != nil || pair.Subject != session.Subject || pair.Subject.IdentityID != "" || pair.Subject.DeviceID != "" || !pair.ExpiresAt.Equal(session.ExpiresAt) {
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
	if err != nil || !delivered.ExpiresAt.Equal(session.ExpiresAt) {
		t.Fatal("native workload recheck deadline", err)
	}
	if _, err := d.DeliverConnectorPeerPair(ctx, service.ID, run.RunID, pair.ID, pair.DeliveryGeneration, session.Credential, now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("workload credential authenticated as publisher run", err)
	}
	if err := d.ConfirmConnectorPeerPairPrepared(ctx, service.ID, run.RunID, pair.ID, run.Token, ConnectorPeerPairPrepared{DeliveryID: pair.DeliveryID, DeliveryGeneration: pair.DeliveryGeneration, BindingExpiresAt: delivered.ExpiresAt}, now); err != nil {
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
	if err != nil || !decision.Allowed || decision.Admitted || !decision.ValidUntil.Equal(session.ExpiresAt) {
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
			observation.VisitorConnectionID, observation.PairID = visitor, pair.ID
			if _, err := d.IngestServiceRunObservations(ctx, service.ID, run.RunID, run.Token, run.RunNumber, serviceaudit.Batch{Events: []serviceaudit.Observation{observation}}, now); err != nil {
				t.Fatal("native audit scanned workload as human", err)
			}
			continue
		}
		if _, err := d.IngestIngressServiceObservations(ctx, lease.IngressLeaseIdentity, serviceaudit.Batch{Events: []serviceaudit.Observation{observation}}, now); err != nil {
			t.Fatal("audit scanned workload as a human", err)
		}
	}
	if _, err := d.DeliverConnectorPeerPair(ctx, service.ID, run.RunID, pair.ID, pair.DeliveryGeneration, run.Token, session.ExpiresAt); err == nil {
		t.Fatal("native authority outlived job")
	}
	if _, err = d.AuthorizeServiceClientCertificate(ctx, service.ID, run.RunID, run.Token, direct, run.RunNumber, source, block.Bytes, session.ExpiresAt); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("public stream outlived job", err)
	}
	// policy removal denies still-live admissions before their earlier deadline.
	r.ExpectedRevision = applied.Revision
	r.Configuration.Workloads = nil
	if _, err = d.ApplyProjectConfiguration(ctx, r); err != nil {
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
	r := appliedProjectRequest(t, d, now)
	r.Configuration = workloadConfiguration()
	applied, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	r.ExpectedRevision = applied.Revision
	exchange, key := workloadExchange(t, r, now)
	exchange.Services = []string{"api"}
	signWorkloadRequest(&exchange, key)
	first, err := d.ExchangeWorkload(ctx, exchange, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.ServiceIDs) != 1 {
		t.Fatal("subset was not preserved")
	}
	broader := exchange
	broader.Services = []string{"api", "db"}
	signWorkloadRequest(&broader, key)
	if _, err = d.ExchangeWorkload(ctx, broader, now); !errors.Is(err, ErrWorkloadConflict) {
		t.Fatal("execution unioned service grants", err)
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make(chan error, 9)
	for i := range 8 {
		wg.Go(func() {
			<-start
			request := exchange
			request.Execution.GitHub = new(*exchange.Execution.GitHub)
			request.Nonce = rand.Text()
			request.Execution.GitHub.CheckRunID = fmt.Sprint(1000 + i)
			request.Execution.GitHub.JTI = fmt.Sprint(1000 + i)
			signWorkloadRequest(&request, key)
			_, err := d.ExchangeWorkload(ctx, request, now)
			if err != nil && !errors.Is(err, ErrWorkloadDenied) {
				errs <- err
			} else {
				errs <- nil
			}
		})
	}
	r.Configuration.Workloads = nil
	wg.Go(func() { <-start; _, err := d.ApplyProjectConfiguration(ctx, r); errs <- err })
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
	if err = d.pool.QueryRow(ctx, `SELECT count(*) FROM control.workload_sessions WHERE team_id=$1 AND revoked_at IS NULL`, r.TeamID).Scan(&active); err != nil || active != 0 {
		t.Fatal("apply failed to fence concurrent starts", active, err)
	}
	var people, devices int
	if err = d.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM control.identities WHERE id IN(SELECT subject_id FROM control.connector_peer_pairs WHERE subject_kind='workload_session')),(SELECT count(*) FROM control.visitor_devices WHERE id IN(SELECT subject_id FROM control.connector_peer_pairs WHERE subject_kind='workload_session'))`).Scan(&people, &devices); err != nil || people != 0 || devices != 0 {
		t.Fatal("workload created a person or enrolled device", people, devices, err)
	}
}
