package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
)

type applicationSessionFixture struct {
	database        *Database
	now             time.Time
	application     ApplicationRegistration
	persistentKey   ed25519.PrivateKey
	session         WorkloadSession
	sessionKey      ed25519.PrivateKey
	request         RegisterApplicationRequest
	exchangeRequest ExchangeWorkloadRequest
}

// setup seeds the approved application binding directly. this suite qualifies
// source authority, not the unfinished declarative apply or SDK acquisition path.
func newApplicationSessionFixture(t *testing.T, lifetime ...time.Duration) applicationSessionFixture {
	t.Helper()
	d, now, _, _ := newPublishRunPrerequisites(t)
	r, persistentKey := applicationRequest(t, d, now)
	if len(lifetime) != 0 {
		for index := range r.Grants {
			r.Grants[index].ExpiresAt = new(now.Add(lifetime[0]))
		}
	}
	application, err := d.RegisterApplication(t.Context(), r, now)
	if err != nil {
		t.Fatal(err)
	}
	project := ApplyProjectConfigurationRequest{TeamID: r.TeamID, ActorID: r.ActingIdentityID, ProjectKey: "application-session", SourceFingerprint: strings.Repeat("a", 64), Configuration: workloadConfiguration(), Now: now}
	if _, err := d.ApplyProjectConfiguration(t.Context(), project); err != nil {
		t.Fatal(err)
	}
	if _, err := d.pool.Exec(t.Context(), `INSERT INTO control.workload_applications(id,team_id,project_key,workload_name,publisher_identity_id,created_at) VALUES('binding',$1,$2,'test',$3,$4)`, r.TeamID, project.ProjectKey, application.ID, now); err != nil {
		t.Fatal(err)
	}
	exchange, sessionKey := workloadExchange(t, project, now)
	session, err := d.ExchangeWorkload(t.Context(), exchange, now)
	if err != nil {
		t.Fatal(err)
	}
	var sessionKeyID string
	if err := d.pool.QueryRow(t.Context(), `SELECT id FROM control.publisher_identity_keys WHERE publisher_identity_id=$1 AND workload_session_id=$2`, application.ID, session.ID).Scan(&sessionKeyID); err != nil {
		t.Fatal(err)
	}
	application.KeyID = sessionKeyID
	return applicationSessionFixture{database: d, now: now, application: application, persistentKey: persistentKey, session: session, sessionKey: sessionKey, request: r, exchangeRequest: exchange}
}

func (f applicationSessionFixture) exchange(t *testing.T, grant ApplicationGrant, at time.Time) (PublisherAccess, error) {
	t.Helper()
	assertion, err := publisherproof.Sign(f.application.ID, f.application.KeyID, grant.ID, publisherTestAudience, f.sessionKey, at)
	if err != nil {
		t.Fatal(err)
	}
	return f.database.ExchangePublisherAssertion(t.Context(), f.application.ID, grant.ID, publisherTestAudience, assertion, "", at)
}

func (f applicationSessionFixture) persistentApplication(t *testing.T) ApplicationRegistration {
	t.Helper()
	registered := f.application
	if err := f.database.pool.QueryRow(t.Context(), `SELECT id FROM control.publisher_identity_keys WHERE publisher_identity_id=$1 AND workload_session_id IS NULL AND retired_at IS NULL`, registered.ID).Scan(&registered.KeyID); err != nil {
		t.Fatal(err)
	}
	return registered
}

func TestIntegrationApplicationSessionUsesOneIdentityAndCapturedGrants(t *testing.T) {
	f := newApplicationSessionFixture(t)
	for _, grant := range f.application.Grants {
		access, err := f.exchange(t, grant, f.now)
		if err != nil || access.ID != f.application.ID || access.KeyID != f.application.KeyID || access.Operation != grant.Operation || !access.Until.Equal(f.session.LeaseExpiresAt) {
			t.Fatal("session changed identity, operation or deadline", err)
		}
	}
	q := controlstatedb.New(f.database.pool)
	keys, err := q.GetPublisherKey(t.Context(), controlstatedb.GetPublisherKeyParams{ID: f.application.KeyID, PublisherIdentityID: f.application.ID})
	if err != nil || keys.WorkloadSessionID.String != f.session.ID || keys.WorkloadBindingID.String != "binding" {
		t.Fatal("source key lost its binding", err)
	}
	grant := f.application.Grants[1]
	access, err := f.exchange(t, grant, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.pool.Exec(t.Context(), `DELETE FROM control.workload_session_application_grants WHERE workload_session_id=$1 AND grant_id=$2`, f.session.ID, grant.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.AuthenticatePublisherAccess(t.Context(), access.Token, "", f.now.Add(time.Second)); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatal("captured grant removal did not revoke existing access", err)
	}
	if _, err := f.exchange(t, grant, f.now.Add(time.Second)); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatal("exchange restored a removed delegation", err)
	}
	if _, err := f.exchange(t, f.application.Grants[4], f.now.Add(time.Second)); err != nil {
		t.Fatal("unrelated grant was revoked", err)
	}
}

func TestIntegrationApplicationSessionCannotAcquireLaterGrantsOrPermanentKeys(t *testing.T) {
	f := newApplicationSessionFixture(t)
	d := f.database
	service, err := d.CreateServiceAt(t.Context(), f.request.TeamID, f.request.ActingIdentityID, "late-service", "late-service", ServicePlacement{}, f.now, ServiceMetadata{Protocol: "postgres"})
	if err != nil {
		t.Fatal(err)
	}
	member, err := controlstatedb.New(d.pool).GetActivePublishRunMembership(t.Context(), controlstatedb.GetActivePublishRunMembershipParams{TeamID: f.request.TeamID, IdentityID: f.request.ActingIdentityID})
	if err != nil {
		t.Fatal(err)
	}
	grantID, err := d.CreatePublisherGrant(t.Context(), CreatePublisherGrantRequest{PublisherIdentityID: f.application.ID, Scope: PublisherScope{TeamID: f.request.TeamID, Kind: "service", ServiceID: service.ID}, EditorID: f.request.ActingIdentityID, EditorMembershipID: member.ID, PolicyRevision: uint64(member.PolicyRevision), Now: f.now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.exchange(t, ApplicationGrant{ID: grantID}, f.now); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatal("old session gained a later grant", err)
	}
	if retried, err := d.ExchangeWorkload(t.Context(), f.exchangeRequest, f.now.Add(time.Second)); err != nil || retried.ID != f.session.ID {
		t.Fatal("exact lost-response recovery changed the source session", err)
	}
	if _, err := f.exchange(t, ApplicationGrant{ID: grantID}, f.now.Add(time.Second)); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatal("lost-response recovery widened the original delegation", err)
	}
	access, err := f.exchange(t, f.application.Grants[1], f.now)
	if err != nil {
		t.Fatal(err)
	}
	replacement := "pkey_" + strings.Repeat("X", 22)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := publisherproof.Sign(f.application.ID, replacement, access.GrantID, publisherTestAudience, private, f.now)
	if err != nil {
		t.Fatal(err)
	}
	currentProof, err := publisherproof.Sign(f.application.ID, f.application.KeyID, access.GrantID, publisherproof.RotationAudience(publisherTestAudience, replacement, public), f.sessionKey, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.RotatePublisherKey(t.Context(), access.Token, "", replacement, publisherTestAudience, public, proof, currentProof, f.now); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatal("session key was eligible for persistent key rotation", err)
	}
	_ = applicationAccess(t, d, f.persistentApplication(t), f.application.Grants[1], f.persistentKey, f.now)
}

func TestIntegrationApplicationSessionSourceFences(t *testing.T) {
	for _, fault := range []string{"lease", "identity-expiry", "hard-deadline", "revoke", "binding", "key", "grant", "retention"} {
		t.Run(fault, func(t *testing.T) {
			f := newApplicationSessionFixture(t)
			d := f.database
			grant := f.application.Grants[1]
			access, err := f.exchange(t, grant, f.now)
			if err != nil {
				t.Fatal(err)
			}
			at := f.now.Add(time.Second)
			var statement string
			switch fault {
			case "lease":
				statement = `UPDATE control.workload_sessions SET lease_expires_at=$2 WHERE id=$1`
			case "identity-expiry":
				statement = `UPDATE control.workload_sessions SET identity_expires_at=$2,lease_expires_at=$2 WHERE id=$1`
			case "hard-deadline":
				statement = `UPDATE control.workload_sessions SET expires_at=$2,lease_expires_at=$2 WHERE id=$1`
			case "revoke":
				statement = `UPDATE control.workload_sessions SET revoked_at=$2 WHERE id=$1`
			case "binding":
				statement = `UPDATE control.workload_applications SET revoked_at=$2 WHERE id='binding' AND $1<>''`
			case "key":
				statement = `UPDATE control.publisher_identity_keys SET retired_at=$2 WHERE workload_session_id=$1`
			case "grant":
				statement = `DELETE FROM control.workload_session_application_grants WHERE workload_session_id=$1 AND $2::timestamptz IS NOT NULL`
			case "retention":
				statement = `UPDATE control.publisher_identity_keys SET workload_session_id='wls_XXXXXXXXXXXXXXXXXXXXXX' WHERE workload_session_id=$1 AND $2::timestamptz IS NOT NULL`
			}
			if _, err := d.pool.Exec(t.Context(), statement, f.session.ID, at); err != nil {
				t.Fatal(err)
			}
			if _, err := d.AuthenticatePublisherAccess(t.Context(), access.Token, "", at); !errors.Is(err, ErrPublisherIdentity) {
				t.Fatal("existing token escaped source fence", err)
			}
			if _, err := f.exchange(t, grant, at); !errors.Is(err, ErrPublisherIdentity) {
				t.Fatal("new exchange escaped source fence", err)
			}
			_ = applicationAccess(t, d, f.persistentApplication(t), grant, f.persistentKey, at)
		})
	}
}

func TestIntegrationApplicationSessionBoundsPublicAndServiceRunLeases(t *testing.T) {
	f := newApplicationSessionFixture(t)
	d := f.database
	until := f.now.Add(20 * time.Second)
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.workload_sessions SET lease_expires_at=$2 WHERE id=$1`, f.session.ID, until); err != nil {
		t.Fatal(err)
	}
	access, err := f.exchange(t, f.application.Grants[1], f.now)
	if err != nil {
		t.Fatal(err)
	}
	url, err := d.GetPublicURLForAuthorization(t.Context(), f.application.Grants[1].Scope.PublicURLID)
	if err != nil {
		t.Fatal(err)
	}
	request := reviewRunRequest(t, d, access.PublisherIdentity, f.sessionKey, url, "session-run")
	run, err := d.CreatePublishRun(t.Context(), request, f.now, time.Hour, time.Hour)
	if err != nil || !run.ExpiresAt.Equal(until) {
		t.Fatal("public run exceeded its workload authority", run.ExpiresAt, err)
	}
	auth := PublishRunAuthentication{PublishRunID: run.PublishRunID, PublicURLID: run.PublicURLID, PublishRunNumber: run.PublishRunNumber, PublishRunToken: run.PublishRunToken}
	renewed, err := d.HeartbeatPublishRun(t.Context(), auth, f.now.Add(5*time.Second), time.Hour, time.Hour)
	if err != nil || !renewed.ExpiresAt.Equal(until) {
		t.Fatal("public heartbeat exceeded its workload authority", renewed.ExpiresAt, err)
	}
	serviceAccess, err := f.exchange(t, f.application.Grants[4], f.now)
	if err != nil {
		t.Fatal(err)
	}
	service, err := d.GetServiceForPublisher(t.Context(), f.application.Grants[4].Scope.ServiceID, serviceAccess.PublisherIdentity, f.now)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := d.PrepareServiceRun(t.Context(), service.ID, serviceAccess.PublisherIdentity, "session-service", f.now, service.ServiceMetadata)
	if err != nil || !prepared.ExpiresAt.Equal(until) {
		t.Fatal("service preparation exceeded its workload authority", prepared.ExpiresAt, err)
	}
	started, err := d.StartServiceRun(t.Context(), service.ID, prepared.RunID, prepared.RunNumber, serviceAccess.PublisherIdentity, f.now)
	if err != nil || !started.ExpiresAt.Equal(until) {
		t.Fatal("service start exceeded its workload authority", started.ExpiresAt, err)
	}
	serviceRenewed, err := d.HeartbeatServiceRun(t.Context(), service.ID, started.RunID, started.Token, f.now.Add(5*time.Second), ServiceRunHealth{Healthy: true, StreamCapacity: 1})
	if err != nil || !serviceRenewed.ExpiresAt.Equal(until) {
		t.Fatal("service heartbeat exceeded its workload authority", serviceRenewed.ExpiresAt, err)
	}
	if err := d.RevokeWorkloadSession(t.Context(), f.session.ID, f.session.Credential, f.now.Add(6*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.HeartbeatPublishRun(t.Context(), auth, f.now.Add(7*time.Second), time.Hour, time.Hour); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatal("revoked source renewed a public run", err)
	}
	if _, err := d.HeartbeatServiceRun(t.Context(), service.ID, started.RunID, started.Token, f.now.Add(7*time.Second), ServiceRunHealth{Healthy: true, StreamCapacity: 1}); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("revoked source renewed a service run", err)
	}
}

func TestIntegrationApplicationSessionRetainsCapturedGrantExpiry(t *testing.T) {
	f := newApplicationSessionFixture(t, 30*time.Second)
	grant := f.application.Grants[1]
	if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.publisher_grants SET expires_at=$2 WHERE id=$1`, grant.ID, f.now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	access, err := f.exchange(t, grant, f.now.Add(time.Second))
	if err != nil || !access.Until.Equal(f.now.Add(30*time.Second)) {
		t.Fatal("parent expiry extension widened the captured delegation", access.Until, err)
	}
	if _, err := f.exchange(t, grant, f.now.Add(30*time.Second)); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatal("captured grant expiry was ignored", err)
	}
	_ = applicationAccess(t, f.database, f.persistentApplication(t), grant, f.persistentKey, f.now.Add(30*time.Second))
}

func TestIntegrationApplicationSessionsShareIdentityButNotProofOrLifetime(t *testing.T) {
	f := newApplicationSessionFixture(t)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request := f.exchangeRequest
	request.PublicKey, request.Nonce = public, rand.Text()
	github := *request.Execution.GitHub
	github.RunID, github.CheckRunID, github.JTI = "333", "444", "another-execution"
	request.Execution.GitHub = &github
	signWorkloadRequest(&request, private)
	second, err := f.database.ExchangeWorkload(t.Context(), request, f.now)
	if err != nil || second.ID == f.session.ID {
		t.Fatal("independent job did not get its own session", err)
	}
	registration := f.application
	if err := f.database.pool.QueryRow(t.Context(), `SELECT id FROM control.publisher_identity_keys WHERE publisher_identity_id=$1 AND workload_session_id=$2`, registration.ID, second.ID).Scan(&registration.KeyID); err != nil {
		t.Fatal(err)
	}
	if registration.KeyID == f.application.KeyID {
		t.Fatal("independent jobs shared a signing key")
	}
	grant := registration.Grants[1]
	access := applicationAccess(t, f.database, registration, grant, private, f.now)
	if err := f.database.RevokeWorkloadSession(t.Context(), f.session.ID, f.session.Credential, f.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.exchange(t, grant, f.now.Add(time.Second)); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatal("revoked job retained authority", err)
	}
	if _, err := f.database.AuthenticatePublisherAccess(t.Context(), access.Token, "", f.now.Add(time.Second)); err != nil {
		t.Fatal("revoking one job affected another job's delegation", err)
	}
	wrong, err := publisherproof.Sign(registration.ID, registration.KeyID, grant.ID, publisherTestAudience, f.sessionKey, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.ExchangePublisherAssertion(t.Context(), registration.ID, grant.ID, publisherTestAudience, wrong, "", f.now); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatal("one job signed for another job's key", err)
	}
}

func TestIntegrationApplicationSessionDoesNotBlockPersistentKeyRotation(t *testing.T) {
	f := newApplicationSessionFixture(t)
	grant := f.application.Grants[1]
	persistent := f.persistentApplication(t)
	access := applicationAccess(t, f.database, persistent, grant, f.persistentKey, f.now)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	replacement := "pkey_" + strings.Repeat("R", 22)
	proof, err := publisherproof.Sign(persistent.ID, replacement, grant.ID, publisherTestAudience, private, f.now)
	if err != nil {
		t.Fatal(err)
	}
	current, err := publisherproof.Sign(persistent.ID, persistent.KeyID, grant.ID, publisherproof.RotationAudience(publisherTestAudience, replacement, public), f.persistentKey, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.database.RotatePublisherKey(t.Context(), access.Token, "", replacement, publisherTestAudience, public, proof, current, f.now); err != nil {
		t.Fatal("session signing key blocked independent persistent-key rotation", err)
	}
	persistent.KeyID = replacement
	_ = applicationAccess(t, f.database, persistent, grant, private, f.now)
	if _, err := f.exchange(t, grant, f.now); err != nil {
		t.Fatal("persistent-key rotation retired an unrelated session key", err)
	}
	if _, err := f.database.AuthenticatePublisherAccess(t.Context(), access.Token, "", f.now); err != nil {
		t.Fatal("rotation revoked an already-issued persistent access token", err)
	}
}

func TestIntegrationApplicationSessionAllocationCannotUseExpiredSource(t *testing.T) {
	f := newApplicationSessionFixture(t)
	grant := f.application.Grants[2]
	access, err := f.exchange(t, grant, f.now)
	if err != nil {
		t.Fatal(err)
	}
	url, err := f.database.AllocatePublisherPublicURL(t.Context(), access.PublisherIdentity, "ivk_"+strings.Repeat("A", 22), "http://127.0.0.1:3000", nil, nil, f.now)
	if err != nil {
		t.Fatal(err)
	}
	at := f.session.LeaseExpiresAt
	if _, err := f.database.AllocatePublisherPublicURL(t.Context(), access.PublisherIdentity, "ivk_"+strings.Repeat("B", 22), "http://127.0.0.1:3000", nil, nil, at); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatal("cached publisher identity allocated after source expiry", err)
	}
	deletion := AuthorizedPublicURLDeleteRequest{PublicURLID: url.ID, TeamID: url.TeamID, ActingIdentityID: access.CreatorID, PublisherIdentityID: access.ID, PublisherGrantID: grant.ID, PublisherKeyID: access.KeyID}
	if err := f.database.DeleteAuthorizedPublicURL(t.Context(), deletion, at); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatal("cleanup escaped its source deadline", err)
	}
}
