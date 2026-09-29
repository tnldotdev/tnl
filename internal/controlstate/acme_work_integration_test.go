package controlstate

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

func TestIntegrationACMEAccount(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "acme_account")
	account, err := database.EnsureACMEAccount(t.Context(), "https://acme.example.test/directory", "operator@example.test", now)
	if err != nil {
		t.Fatal(err)
	}
	var ciphertext []byte
	if err := database.pool.QueryRow(t.Context(), `SELECT account_key_ciphertext FROM control.acme_accounts WHERE id = $1`, account.ID).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, account.AccountKeyDER) {
		t.Fatal("account key persisted as plaintext")
	}
	repeated, err := database.EnsureACMEAccount(t.Context(), account.DirectoryURL, account.ContactEmail, now)
	if err != nil || repeated.ID != account.ID || !bytes.Equal(repeated.AccountKeyDER, account.AccountKeyDER) {
		t.Fatalf("account retry changed key or identity: %v", err)
	}
	registered, err := database.UpdateACMEAccountRegistration(t.Context(), account.ID, account.ContactEmail, "https://acme.example.test/account/1", "https://acme.example.test/terms", now)
	if err != nil || registered.AccountURL != "https://acme.example.test/account/1" || registered.AcceptedTerms != "https://acme.example.test/terms" {
		t.Fatalf("registered account = %#v, %v", registered, err)
	}
}

func TestIntegrationCertificateIssuanceCreation(t *testing.T) {
	f := newPublishRunFixture(t)
	request := newTestIssuanceRequest(t, f)
	issuance, err := f.database.CreateCertificateIssuance(t.Context(), request, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if issuance.State != "pending" || issuance.PublishRunID != f.setup.PublishRunID ||
		issuance.PublishRunNumber != f.setup.PublishRunNumber || !reflect.DeepEqual(issuance.CertificatePlan.Identifiers, f.request.CertificateIdentifiers) {
		t.Fatalf("issuance = %#v", issuance)
	}
	repeated, err := f.database.CreateCertificateIssuance(t.Context(), request, f.now.Add(time.Millisecond))
	if err != nil || !reflect.DeepEqual(repeated, issuance) {
		t.Fatalf("issuance replay = %#v, %v", repeated, err)
	}
	request.RequestDigest = sha256.Sum256([]byte("changed"))
	if _, err := f.database.CreateCertificateIssuance(t.Context(), request, f.now); !errors.Is(err, ErrCertificateIssuanceIdempotency) {
		t.Fatalf("issuance idempotency: %v", err)
	}
	loaded, err := f.database.GetCertificateIssuance(t.Context(), issuance.ID, f.setup.PublishRunToken, f.now)
	if err != nil || !reflect.DeepEqual(loaded, issuance) {
		t.Fatalf("loaded issuance = %#v, %v", loaded, err)
	}
}

func TestIntegrationACMEWorkLeaseRecovery(t *testing.T) {
	f := newPublishRunFixture(t)
	database, now := f.database, f.now
	issuance, err := database.CreateCertificateIssuance(t.Context(), newTestIssuanceRequest(t, f), now)
	if err != nil {
		t.Fatal(err)
	}
	first, found, err := database.ClaimACMEOrderWork(t.Context(), "first", now, time.Second)
	if err != nil || !found || first.ID != issuance.ID || first.WorkEpoch != 1 || first.Account.AccountURL != "https://acme.example.test/account/1" {
		t.Fatalf("first work = %#v, %t, %v", first, found, err)
	}
	if _, found, err := database.ClaimACMEOrderWork(t.Context(), "other", now, time.Minute); err != nil || found {
		t.Fatalf("concurrent work = %t, %v", found, err)
	}
	recovered, found, err := database.ClaimACMEOrderWork(t.Context(), "other", now.Add(time.Second), time.Minute)
	if err != nil || !found || recovered.ID != first.ID || recovered.WorkEpoch != first.WorkEpoch+1 {
		t.Fatalf("recovered work = %#v, %t, %v", recovered, found, err)
	}
	first.AvailableAt = now
	if _, err := database.SaveACMEOrderWork(t.Context(), first, now.Add(time.Second)); !errors.Is(err, ErrACMEWorkStale) {
		t.Fatalf("old owner save: %v", err)
	}
	expires := now.Add(time.Hour)
	recovered.State, recovered.AvailableAt = "authorizing", now
	recovered.Authorizations = []ACMEAuthorizationWork{{Identifier: f.request.CertificateIdentifiers[0], AuthorizationURL: "https://acme.example.test/authz/1",
		ChallengeType: "tls-alpn-01", ChallengeURL: "https://acme.example.test/challenge/1", ChallengeToken: "token", ChallengeDigest: sha256.Sum256([]byte("token")),
		State: "presenting", AvailableAt: now, ExpiresAt: &expires, CreatedAt: now, UpdatedAt: now}}
	saved, err := database.SaveACMEOrderWork(t.Context(), recovered, now.Add(time.Second))
	if err != nil || saved.OrderRevision != recovered.OrderRevision+1 || len(saved.Authorizations) != 1 ||
		!opaqueid.Valid(saved.Authorizations[0].ID, "acme_authorization_") || saved.Authorizations[0].Revision != 1 {
		t.Fatalf("saved work = %#v, %v", saved, err)
	}
	released, found, err := database.ClaimACMEOrderWork(t.Context(), "third", now.Add(2*time.Second), time.Minute)
	if err != nil || !found || released.ID != saved.ID || released.WorkEpoch != recovered.WorkEpoch+1 {
		t.Fatalf("released work = %#v, %t, %v", released, found, err)
	}
}

func TestIntegrationInstalledCertificateRetainsCleanupWork(t *testing.T) {
	database, now := newCertificatePlanDatabase(t)
	const hostname = "api.member.routes.example.test"
	plan := CertificatePlan{CacheKey: hostname, Scope: hostname, Identifiers: []string{hostname}, ChallengeMethod: "dns-01"}
	_, authentication := newExternalPlanSession(t, database, now, "team_external", hostname, "managed:routes.example.test", plan)
	renewAt := now.Add(16 * time.Hour)
	prepared := createPlanIssuanceWork(t, database, now, authentication, plan, true, func(work *ACMEOrderWork) {
		work.Authorizations[0].State = "valid"
		work.Authorizations[0].CleanupCompletedAt = nil
		work.RenewAt, work.AvailableAt = &renewAt, now
	})
	issued, err := database.GetCertificateIssuance(t.Context(), prepared.ID, authentication.PublishRunToken, now)
	if err != nil || issued.State != "waiting_for_install" || issued.CertificatePEM == "" {
		t.Fatalf("certificate blocked on DNS cleanup: state=%q certificate=%t error=%v", issued.State, issued.CertificatePEM != "", err)
	}
	claimed, found, err := database.ClaimACMEOrderWork(t.Context(), "before-install", now.Add(time.Second), time.Second)
	if err != nil || !found || claimed.ID != prepared.ID || claimed.Authorizations[0].State != "valid" {
		t.Fatalf("uninstalled cleanup claim: found=%t error=%v", found, err)
	}
	if _, err := database.MarkPublicURLCertificateInstalled(t.Context(), authentication, prepared.ID, *prepared.NotAfter, now.Add(1500*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	claimed.Authorizations[0].State = "cleaning"
	if _, err := database.SaveACMEOrderWork(t.Context(), claimed, now.Add(1500*time.Millisecond)); !errors.Is(err, ErrACMEWorkStale) {
		t.Fatalf("cleanup overwrote concurrent certificate installation: %v", err)
	}
	current, found, err := database.ClaimACMEOrderWork(t.Context(), "after-install", now.Add(2*time.Second), time.Second)
	if err != nil || !found || current.State != "installed" || current.Authorizations[0].State != "valid" {
		t.Fatalf("installed cleanup work was lost: found=%t state=%q error=%v", found, current.State, err)
	}
	current.Authorizations[0].State, current.Authorizations[0].AvailableAt = "cleaning", now
	current.AvailableAt = now
	if _, err := database.SaveACMEOrderWork(t.Context(), current, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	cleanup, found, err := database.ClaimACMEOrderWork(t.Context(), "after-restart", now.Add(3*time.Second), time.Second)
	if err != nil || !found || cleanup.State != "installed" || cleanup.Authorizations[0].State != "cleaning" {
		t.Fatalf("cleanup did not survive restart: found=%t state=%q error=%v", found, cleanup.State, err)
	}
	challenge, err := database.GetDNSChallengeContext(t.Context(), authentication.PublicURLID, cleanup.Authorizations[0].ID)
	if err != nil || len(challenge.Presentations) != 1 || challenge.Presentations[0].Active {
		t.Fatalf("installed certificate kept DNS presentation active: %+v, %v", challenge.Presentations, err)
	}
	cleanup.Authorizations[0].State, cleanup.Authorizations[0].CleanupCompletedAt = "complete", &now
	cleanup.AvailableAt = renewAt
	if _, err := database.SaveACMEOrderWork(t.Context(), cleanup, now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, found, err := database.ClaimACMEOrderWork(t.Context(), "after-cleanup", now.Add(4*time.Second), time.Second); err != nil || found {
		t.Fatalf("cleaned installed order remained claimable: found=%t error=%v", found, err)
	}
	installed, err := database.GetCertificateIssuance(t.Context(), prepared.ID, authentication.PublishRunToken, now.Add(4*time.Second))
	if err != nil || installed.State != "installed" || installed.CertificatePEM != issued.CertificatePEM {
		t.Fatalf("cleanup changed installed material: state=%q error=%v", installed.State, err)
	}
}

func TestIntegrationACMEWorkRejectsStaleState(t *testing.T) {
	for _, kind := range []string{"lease", "order_revision", "authorization_revision"} {
		t.Run(kind, func(t *testing.T) {
			f := newPublishRunFixture(t)
			prepared := createPlanIssuanceWork(t, f.database, f.now, f.authentication(), f.certificatePlan(), false, nil)
			work, found, err := f.database.ClaimACMEOrderWork(t.Context(), "stale-test", f.now, time.Minute)
			if err != nil || !found || work.ID != prepared.ID {
				t.Fatalf("claim prerequisite = %t, %v", found, err)
			}
			at := f.now
			switch kind {
			case "lease":
				at = at.Add(time.Minute)
			case "order_revision":
				if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.acme_orders SET order_revision = order_revision + 1 WHERE id = $1`, work.ID); err != nil {
					t.Fatal(err)
				}
			case "authorization_revision":
				if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.acme_authorizations SET authorization_revision = authorization_revision + 1 WHERE order_id = $1`, work.ID); err != nil {
					t.Fatal(err)
				}
			}
			work.AvailableAt = f.now
			if _, err := f.database.SaveACMEOrderWork(t.Context(), work, at); !errors.Is(err, ErrACMEWorkStale) {
				t.Fatalf("%s stale save = %v", kind, err)
			}
		})
	}
}

func TestIntegrationTLSChallengeRoutingAndFailedCleanup(t *testing.T) {
	f := newPublishRunFixture(t)
	database, now := f.database, f.now
	ingress := registerTestIngress(t, database, now)
	claimTestConnection(t, f, 0, now)
	work := createPlanIssuanceWork(t, database, now, f.authentication(), f.certificatePlan(), false, nil)
	for range 2 {
		presented, err := database.MarkCertificateChallengeReady(t.Context(), work.ID, f.setup.PublishRunToken, now)
		if err != nil || len(presented.Challenges) != 1 || presented.Challenges[0].Token != work.Authorizations[0].ChallengeToken {
			t.Fatalf("presented challenge = %#v, %v", presented, err)
		}
	}
	if _, found, err := database.ClaimACMEOrderWork(t.Context(), "before-ingress", now, time.Minute); err != nil || found {
		t.Fatalf("work before ingress applied = %t, %v", found, err)
	}
	var revision uint64
	if err := database.pool.QueryRow(t.Context(), `SELECT current_revision FROM control.ingress_routing_table_clock WHERE singleton = true`).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	if _, err := database.RenewIngress(t.Context(), IngressRenewal{IngressLeaseIdentity: ingress.IngressLeaseIdentity, RoutingTableRevision: revision}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	claimed, found, err := database.ClaimACMEOrderWork(t.Context(), "after-ingress", now, time.Minute)
	if err != nil || !found || claimed.ID != work.ID {
		t.Fatalf("work after ingress applied = %#v, %t, %v", claimed, found, err)
	}
	claimed.State, claimed.AvailableAt = "failed", now
	claimed.Authorizations[0].State = "failed"
	if _, err := database.SaveACMEOrderWork(t.Context(), claimed, now); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		removed, err := database.MarkCertificateChallengeRemoved(t.Context(), work.ID, f.setup.PublishRunToken, now)
		if err != nil || len(removed.Challenges) != 0 {
			t.Fatalf("failed challenge cleanup = %#v, %v", removed, err)
		}
	}
	page, err := database.ReadIngressRoutingTableEvents(t.Context(), ingress.IngressLeaseIdentity, 0, 10, now)
	if err != nil || len(page.Events) != 2 || page.Events[0].Kind != "challenge_upsert" || page.Events[1].Kind != "challenge_tombstone" {
		t.Fatalf("challenge events = %#v, %v", page, err)
	}
}

func TestIntegrationClosingSessionCleansDNSAuthorizations(t *testing.T) {
	database, now := newCertificatePlanDatabase(t)
	plan := CertificatePlan{CacheKey: "api.example.test", Scope: "api.example.test", Identifiers: []string{"api.example.test"}, ChallengeMethod: "dns-01"}
	route, authentication := newExternalPlanSession(t, database, now, "team_external", "api.example.test", "managed:example.test", plan)
	work := createPlanIssuanceWork(t, database, now, authentication, plan, false, nil)
	if len(work.Authorizations) != 1 || !opaqueid.Valid(work.Authorizations[0].PresentationReference, "acme_presentation_") {
		t.Fatalf("DNS authorizations = %#v", work.Authorizations)
	}
	challenge, err := database.GetDNSChallengeContext(t.Context(), route.ID, work.Authorizations[0].ID)
	if err != nil || len(challenge.Presentations) != 1 || !challenge.Presentations[0].Active || challenge.PresentationReference != work.Authorizations[0].PresentationReference {
		t.Fatalf("DNS challenge = %#v, %v", challenge, err)
	}
	wrong, _, _, err := credentials.NewPublishRunToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := database.ClosePublishRun(t.Context(), authentication.PublishRunID, wrong, now); !errors.Is(err, ErrPublishRunCredential) {
		t.Fatalf("wrong close credential: %v", err)
	}
	if err := database.ClosePublishRun(t.Context(), authentication.PublishRunID, authentication.PublishRunToken, now); err != nil {
		t.Fatal(err)
	}
	cleanup, found, err := database.ClaimACMEOrderWork(t.Context(), "cleanup", now, time.Minute)
	if err != nil || !found || cleanup.ID != work.ID || cleanup.State != "canceled" ||
		len(cleanup.Authorizations) != 1 || cleanup.Authorizations[0].State != "cleaning" {
		t.Fatalf("canceled cleanup = %#v, %t, %v", cleanup, found, err)
	}
	challenge, err = database.GetDNSChallengeContext(t.Context(), route.ID, cleanup.Authorizations[0].ID)
	if err != nil || len(challenge.Presentations) != 1 || challenge.Presentations[0].Active {
		t.Fatalf("cleaning challenge = %#v, %v", challenge, err)
	}
	cleanup.Authorizations[0].State, cleanup.Authorizations[0].CleanupCompletedAt, cleanup.Authorizations[0].AvailableAt = "complete", &now, now
	cleanup.AvailableAt = now
	if _, err := database.SaveACMEOrderWork(t.Context(), cleanup, now); err != nil {
		t.Fatal(err)
	}
	if err := database.ClosePublishRun(t.Context(), authentication.PublishRunID, authentication.PublishRunToken, now); err != nil {
		t.Fatalf("close replay: %v", err)
	}
	if _, found, err := database.ClaimACMEOrderWork(t.Context(), "completed", now.Add(time.Second), time.Minute); err != nil || found {
		t.Fatalf("completed cleanup still claimable = %t, %v", found, err)
	}
}

func newTestIssuanceRequest(t *testing.T, f publishRunFixture) CreateCertificateIssuanceRequest {
	t.Helper()
	account, err := f.database.EnsureACMEAccount(t.Context(), "https://acme.example.test/directory", "operator@example.test", f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.UpdateACMEAccountRegistration(t.Context(), account.ID, account.ContactEmail, "https://acme.example.test/account/1", "", f.now); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: f.request.CertificateIdentifiers}, key)
	if err != nil {
		t.Fatal(err)
	}
	return CreateCertificateIssuanceRequest{
		Authentication: f.authentication(), DirectoryURL: account.DirectoryURL,
		IdempotencyKey: "issuance", RequestDigest: sha256.Sum256(csr), CSRDER: csr,
	}
}
