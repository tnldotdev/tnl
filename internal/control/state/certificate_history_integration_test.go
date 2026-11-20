package state

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"
)

func TestIntegrationCertificateHistoryWithoutCountLimit(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "certificate_history")
	ctx := t.Context()
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{Settings: &DeploymentSettings{}, Services: map[string]ProjectServiceConfiguration{
		"app": {Target: "localhost:3000"},
	}}
	r = selectedProjectRequest(r, "production")
	if _, err := d.ApplyProjectConfiguration(ctx, r); err != nil {
		t.Fatal(err)
	}
	enrollment, err := testDeploymentPublisherEnrollment(d, ctx, r.TeamID, r.ProjectKey, "production", r.ActorID, 1, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	replica := enrollAppliedDeployment(t, d, r, enrollment, now)
	assignment := replica.assignments.Services[0]
	access := deploymentAssignmentAccess(t, d, replica, assignment, now)
	registerCertificatePlanRelays(t, d, now)
	prep, err := d.PrepareServiceRun(ctx, assignment.ServiceID, access.PublisherIdentity, "history", now,
		ServiceRunRequest{Metadata: ServiceMetadata{Protocol: assignment.Configuration.Protocol, TrustRevision: assignment.TrustRevision}})
	if err != nil {
		t.Fatal(err)
	}
	run, err := d.StartServiceRun(ctx, assignment.ServiceID, prep.RunID, prep.RunNumber, access.PublisherIdentity, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.pool.Exec(ctx, `INSERT INTO control.publisher_certificate_checkpoints
		SELECT $1, encode(sha256(convert_to(plan::text,'UTF8')),'hex'), plan
		FROM (SELECT jsonb_build_object('cache_key','plan-'||n||'.example',
			'scope','plan-'||n||'.example','identifiers',jsonb_build_array('plan-'||n||'.example'),
			'challenge_method','dns-01') AS plan FROM generate_series(1,1024) n) plans`, replica.member.PublisherIdentityID); err != nil {
		t.Fatal(err)
	}
	const directory = "https://acme.example.test/directory"
	if _, err := d.EnsureACMEAccount(ctx, directory, "operator@example.test", now); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: prep.CertificatePlan.Identifiers}, key)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := d.CreateServiceCertificateIssuance(ctx, run.ServiceID, run.RunID, run.Token, directory, "history", run.RunNumber, csr, now); err != nil {
			t.Fatal("could not issue with 1024 existing certificate plans", err)
		}
	}
	assignments, err := d.GetDeploymentPublisherAssignments(ctx, replica.lease.AccessToken, now)
	if err != nil || len(assignments.CertificateStatePlans) != 1025 {
		t.Fatal("assignment response lost plan history or duplicated a retry", len(assignments.CertificateStatePlans), err)
	}
}
