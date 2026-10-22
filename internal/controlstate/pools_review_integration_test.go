package controlstate

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/publisheridentity"
)

func poolReviewFixtures(t *testing.T) ([]publishRunFixture, []PublisherIdentity, []ed25519.PrivateKey, CreatePublicURLRequest) {
	t.Helper()
	d, now, base, leases := newPublishRunPrerequisites(t)
	creation := oidcRouteRequest(t, d, now)
	creation.PublisherPool = true
	url, err := d.CreatePublicURL(t.Context(), creation, now)
	if err != nil || !url.PublisherPool {
		t.Fatal("explicit authorized pool creation failed", err)
	}
	base.PublicURLID, base.TeamID, base.ActingIdentityID, base.MembershipID, base.PolicyRevision = url.ID, url.TeamID, creation.ActingIdentityID, url.MembershipID, uint64(url.PolicyRevision)
	var runs []publishRunFixture
	var publishers []PublisherIdentity
	var keys []ed25519.PrivateKey
	for index := range 2 {
		enrollment := publisherEnrollment(t, d, creation, PublisherScope{TeamID: url.TeamID, Kind: "saved_url", PublicURLID: url.ID}, now)
		public, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		publisher, err := d.RedeemPublisherEnrollment(t.Context(), enrollment.Key, public, now)
		if err != nil {
			t.Fatal(err)
		}
		current, err := d.GetPublicURLForAuthorization(t.Context(), url.ID)
		if err != nil {
			t.Fatal(err)
		}
		plan, err := d.PublisherRunPlan(t.Context(), publisher, current, false)
		if err != nil {
			t.Fatal(err)
		}
		request := base
		request.ExpectedMutationRevision = current.MutationRevision
		request.IdempotencyKey = fmt.Sprintf("pool-review-%d", index)
		request.RequestDigest = sha256.Sum256([]byte(request.IdempotencyKey))
		request.CertificateCacheKey, request.CertificateScope, request.CertificateIdentifiers, request.CertificateChallenge = plan.CacheKey, plan.Scope, plan.Identifiers, plan.ChallengeMethod
		request.PublisherIdentityID, request.PublisherGrantID, request.PublisherKeyID = publisher.ID, publisher.GrantID, publisher.KeyID
		request.PublisherRunProof, err = publisheridentity.SignRun(key, url.ID, request.IdempotencyKey)
		if err != nil {
			t.Fatal(err)
		}
		setup, err := d.CreatePublishRun(t.Context(), request, now, time.Minute, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		fixture := publishRunFixture{database: d, now: now, request: request, setup: setup, leases: leases}
		readyTestSession(t, fixture)
		runs = append(runs, fixture)
		publishers = append(publishers, publisher)
		keys = append(keys, key)
	}
	return runs, publishers, keys, creation
}

func TestIntegrationSharedPublisherStorageAndPoolAuthorizationReview(t *testing.T) {
	runs, publishers, keys, creation := poolReviewFixtures(t)
	d, now := runs[0].database, runs[0].now
	for _, relation := range []struct{ name, kind string }{{"publisher_service_connection_slots", "r"}, {"publish_run_connection_slots", "v"}, {"private_service_connection_slots", "v"}, {"publisher_service_runs", "v"}} {
		var kind string
		if err := d.pool.QueryRow(t.Context(), `SELECT relkind::text FROM pg_class WHERE oid=to_regclass('control.'||$1)`, relation.name).Scan(&kind); err != nil || kind != relation.kind {
			t.Fatalf("%s is not the shared storage/view model: %q %v", relation.name, kind, err)
		}
	}
	var mirrors int
	if err := d.pool.QueryRow(t.Context(), `SELECT count(*) FROM pg_proc WHERE proname IN('project_publisher_service_run','bind_public_publisher_runtime')`).Scan(&mirrors); err != nil || mirrors != 0 {
		t.Fatal("runtime mirror triggers remain", err)
	}
	if page, err := d.ListPublicURLs(t.Context(), creation.ActingIdentityID, creation.TeamID, ""); err != nil || len(page.PublicURLs) != 1 {
		t.Fatalf("identity listing scalar assumes one run: %+v %v", page, err)
	}
	if page, err := d.ListAuthorizedPublicURLs(t.Context(), creation.TeamID, ""); err != nil || len(page.PublicURLs) != 1 {
		t.Fatalf("authorized listing scalar assumes one run: %+v %v", page, err)
	}
	if _, err := d.GetPublicURL(t.Context(), creation.ActingIdentityID, runs[0].setup.PublicURLID); err != nil {
		t.Fatal("identity get assumes one run", err)
	}
	if _, err := d.GetAuthorizedPublicURLByHostname(t.Context(), creation.TeamID, creation.CanonicalHostname); err != nil {
		t.Fatal("hostname get assumes one run", err)
	}
	if _, err := d.CreatePublicURL(t.Context(), creation, now); err != nil {
		t.Fatal("creation retry scalar assumes one run", err)
	}
	current, err := d.GetPublicURLForAuthorization(t.Context(), runs[0].setup.PublicURLID)
	if err != nil {
		t.Fatal(err)
	}
	duplicate := runs[0].request
	duplicate.IdempotencyKey = "duplicate"
	duplicate.ExpectedMutationRevision = current.MutationRevision
	duplicate.PublisherRunProof, err = publisheridentity.SignRun(keys[0], current.ID, duplicate.IdempotencyKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.CreatePublishRun(t.Context(), duplicate, now, time.Minute, time.Minute); !errors.Is(err, ErrPublishRunConflict) {
		t.Fatalf("same publisher joined a pool twice: %v", err)
	}
	_, err = d.pool.Exec(t.Context(), `UPDATE control.publish_runs SET publisher_identity_id=$2,publisher_grant_id=$3 WHERE id=$1`, runs[1].setup.PublishRunID, publishers[0].ID, publishers[0].GrantID)
	var violation *pgconn.PgError
	if !errors.As(err, &violation) || violation.ConstraintName != "publish_runs_current_publisher" {
		t.Fatalf("one-active-run invariant is not in authoritative run storage: %v", err)
	}
	ingress := registerTestIngress(t, d, now)
	if err = d.ClosePublishRun(t.Context(), runs[0].setup.PublishRunID, runs[0].setup.PublishRunToken, now); err != nil {
		t.Fatal(err)
	}
	snapshot, err := d.ReadIngressRoutingTableSnapshot(t.Context(), ingress.IngressLeaseIdentity, now)
	if err != nil || len(snapshot.Entries) != 1 || snapshot.Entries[0].Projection.PublishRunID != runs[1].setup.PublishRunID {
		t.Fatalf("run eviction tombstoned a sibling: %+v %v", snapshot, err)
	}
	var live int
	if err = d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.publisher_service_connection_slots WHERE service_id=$1 AND session_open`, current.ID).Scan(&live); err != nil || live != 2 {
		t.Fatalf("shared slot parent cascade did not preserve sibling: %d %v", live, err)
	}
	private, err := d.CreatePrivateService(t.Context(), creation.TeamID, creation.ActingIdentityID, "private", "private", now)
	if err != nil {
		t.Fatal(err)
	}
	meta := private.PrivateServiceMetadata
	meta.PublisherPool = true
	updated, err := d.ConfigurePrivateService(t.Context(), private.ID, creation.ActingIdentityID, meta, now)
	if err != nil || updated.TrustRevision != private.TrustRevision+1 {
		t.Fatal("operator pool edits are not revision fenced", err)
	}
	if _, err = d.ConfigurePrivateService(t.Context(), private.ID, creation.ActingIdentityID, private.PrivateServiceMetadata, now); !errors.Is(err, ErrPrivateServiceConflict) {
		t.Fatalf("stale operator silently reverted approved pool: %v", err)
	}
	if saved, err := d.GetPrivateService(t.Context(), private.ID, creation.ActingIdentityID); err != nil || !saved.PublisherPool || saved.TrustRevision != updated.TrustRevision {
		t.Fatal("stale configuration changed the saved service", err)
	}
}

func TestIntegrationPublisherCertificateCacheAndDNSRetryWindow(t *testing.T) {
	runs, _, keys, _ := poolReviewFixtures(t)
	d, now := runs[0].database, runs[0].now
	q := controlstatedb.New(d.pool)
	source, err := q.GetPublishRun(t.Context(), runs[0].setup.PublishRunID)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := q.GetPublishRun(t.Context(), runs[1].setup.PublishRunID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.MarkPublicURLCertificateInstalled(t.Context(), runs[0].authentication(), foreign.CertificateIssuanceID.String, foreign.CertificateNotAfter.Time, now); !errors.Is(err, ErrPublicURLCertificate) {
		t.Fatalf("publisher reused another publisher's CSR/key cache: %v", err)
	}
	if err = d.ClosePublishRun(t.Context(), runs[0].setup.PublishRunID, runs[0].setup.PublishRunToken, now); err != nil {
		t.Fatal(err)
	}
	current, err := d.GetPublicURLForAuthorization(t.Context(), source.PublicURLID)
	if err != nil {
		t.Fatal(err)
	}
	request := runs[0].request
	request.IdempotencyKey = "restart"
	request.ExpectedMutationRevision = current.MutationRevision
	request.PublisherRunProof, err = publisheridentity.SignRun(keys[0], current.ID, request.IdempotencyKey)
	if err != nil {
		t.Fatal(err)
	}
	setup, err := d.CreatePublishRun(t.Context(), request, now, time.Minute, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	run := publishRunFixture{database: d, now: now, request: request, setup: setup, leases: runs[0].leases}
	if _, err = d.MarkPublicURLCertificateInstalled(t.Context(), run.authentication(), source.CertificateIssuanceID.String, source.CertificateNotAfter.Time, now); err != nil {
		t.Fatal("same publisher lost reusable public certificate cache", err)
	}
	newer := createPlanIssuanceWork(t, d, now.Add(time.Second), run.authentication(), run.certificatePlan(), true, nil)
	if _, err = d.MarkPublicURLCertificateInstalled(t.Context(), run.authentication(), newer.ID, *newer.NotAfter, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err = d.MarkPublicURLCertificateInstalled(t.Context(), run.authentication(), source.CertificateIssuanceID.String, source.CertificateNotAfter.Time, now.Add(2*time.Second)); !errors.Is(err, ErrPublicURLCertificate) {
		t.Fatalf("old installation retry rolled back a newer certificate: %v", err)
	}
	for index := range 2 {
		claimTestConnection(t, run, index, now)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: run.request.CertificateIdentifiers}, key)
	if err != nil {
		t.Fatal(err)
	}
	account, err := d.EnsureACMEAccount(t.Context(), "https://acme.example.test/directory", "operator@example.test", now)
	if err != nil {
		t.Fatal(err)
	}
	issuance, err := d.CreateCertificateIssuance(t.Context(), CreateCertificateIssuanceRequest{Authentication: run.authentication(), DirectoryURL: account.DirectoryURL, IdempotencyKey: "renew-b", RequestDigest: sha256.Sum256(csr), CSRDER: csr}, now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.pool.Exec(t.Context(), `UPDATE control.acme_orders SET state='authorizing',attempts=3,retry_not_before=$2,available_at=$2,last_error='CA retry window' WHERE id=$1`, issuance.ID, now.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	stored, err := q.GetACMEOrder(t.Context(), issuance.ID)
	if err != nil || !stored.AvailableAt.Time.Equal(now.Add(5*time.Minute)) || stored.Attempts != 3 {
		t.Fatalf("node acknowledgment bypassed CA retry window: %+v %v", stored, err)
	}
	if work, found, err := d.ClaimACMEOrderWork(t.Context(), "rate-window-review", now.Add(4*time.Second), time.Minute); err != nil || found {
		t.Fatalf("CA work was claimed before retry window: %s %t %v", work.ID, found, err)
	}
	actual, err := q.GetPublishRun(t.Context(), setup.PublishRunID)
	if err != nil || actual.CertificateIssuanceID.String != newer.ID {
		t.Fatal("old retry changed installed certificate", err)
	}
}
