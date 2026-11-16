package state

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

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/credentials"
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
	f := newServicePublicationFixture(t)
	if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.domains SET kind='custom',team_id=$2,dns_authority_reference=NULL WHERE id=$1`, f.service.DomainID, f.service.TeamID); err != nil {
		t.Fatal(err)
	}
	csr := newTestIssuanceCSR(t, f)
	issuance, err := f.database.CreateServiceCertificateIssuance(t.Context(), f.service.ID, f.run.RunID, f.run.Token, "https://acme.example.test/directory", "issuance", f.run.RunNumber, csr, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if !issuance.NewOrder || issuance.DomainKind != DomainKindCustom {
		t.Fatal("new committed order did not identify its domain kind")
	}
	// creation facts are not part of the durable issuance returned on replay.
	issuance.NewOrder, issuance.DomainKind = false, ""
	if issuance.State != "pending" || issuance.ServiceRunID != f.run.RunID ||
		issuance.ServiceRunNumber != uint64(f.run.RunNumber) || !reflect.DeepEqual(issuance.CertificatePlan.Identifiers, f.prepared.CertificatePlan.Identifiers) {
		t.Fatalf("issuance = %#v", issuance)
	}
	repeated, err := f.database.CreateServiceCertificateIssuance(t.Context(), f.service.ID, f.run.RunID, f.run.Token, "https://acme.example.test/directory", "issuance", f.run.RunNumber, csr, f.now.Add(time.Millisecond))
	if err != nil || !reflect.DeepEqual(repeated, issuance) {
		t.Fatalf("issuance replay = %#v, %v", repeated, err)
	}
	changed := newTestIssuanceCSR(t, f)
	if _, err := f.database.CreateServiceCertificateIssuance(t.Context(), f.service.ID, f.run.RunID, f.run.Token, "https://acme.example.test/directory", "issuance", f.run.RunNumber, changed, f.now); !errors.Is(err, ErrCertificateIssuanceIdempotency) {
		t.Fatalf("issuance idempotency: %v", err)
	}
	loaded, err := f.database.GetServiceCertificateIssuance(t.Context(), f.service.ID, f.run.RunID, f.run.Token, issuance.ID, f.now)
	if err != nil || !reflect.DeepEqual(loaded, issuance) {
		t.Fatalf("loaded issuance = %#v, %v", loaded, err)
	}
}

func TestIntegrationManagedCertificateOrderFacts(t *testing.T) {
	f := newServicePublicationFixture(t)
	csr := newTestIssuanceCSR(t, f)
	created, err := f.database.CreateServiceCertificateIssuance(t.Context(), f.service.ID, f.run.RunID, f.run.Token, "https://acme.example.test/directory", "issuance", f.run.RunNumber, csr, f.now)
	if err != nil || !created.NewOrder || created.DomainKind != DomainKindManaged {
		t.Fatalf("managed order creation facts = %t/%q, %v", created.NewOrder, created.DomainKind, err)
	}
	repeated, err := f.database.CreateServiceCertificateIssuance(t.Context(), f.service.ID, f.run.RunID, f.run.Token, "https://acme.example.test/directory", "issuance", f.run.RunNumber, csr, f.now)
	if err != nil || repeated.NewOrder || repeated.ID != created.ID {
		t.Fatalf("replayed managed order = new %t, %v", repeated.NewOrder, err)
	}
}

func TestIntegrationACMEWorkLeaseRecovery(t *testing.T) {
	f := newServicePublicationFixture(t)
	database, now := f.database, f.now
	issuance, err := database.CreateServiceCertificateIssuance(t.Context(), f.service.ID, f.run.RunID, f.run.Token, "https://acme.example.test/directory", "issuance", f.run.RunNumber, newTestIssuanceCSR(t, f), now)
	if err != nil {
		t.Fatal(err)
	}
	first, found, err := database.ClaimACMEOrderWork(t.Context(), "first", now, time.Second)
	if err != nil || !found || first.ID != issuance.ID || first.WorkEpoch != 1 || first.Account.AccountURL != "https://acme.example.test/account/1" {
		t.Fatalf("first work = %#v, %t, %v", first, found, err)
	}
	crossed := first
	crossed.Subject.RunNumber++
	if _, err := database.SaveACMEOrderWork(t.Context(), crossed, now); !errors.Is(err, ErrCertificateIssuanceInvalid) {
		t.Fatalf("crossed certificate subject save: %v", err)
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
	recovered.Authorizations = []ACMEAuthorizationWork{{Identifier: f.prepared.CertificatePlan.Identifiers[0], AuthorizationURL: "https://acme.example.test/authz/1",
		ChallengeType: "dns-01", ChallengeURL: "https://acme.example.test/challenge/1", ChallengeToken: "token", ChallengeDigest: sha256.Sum256([]byte("token")),
		State: "presenting", AvailableAt: now, ExpiresAt: &expires, CreatedAt: now, UpdatedAt: now}}
	saved, err := database.SaveACMEOrderWork(t.Context(), recovered, now.Add(time.Second))
	if err != nil || saved.OrderRevision != recovered.OrderRevision+1 || len(saved.Authorizations) != 1 ||
		!opaqueid.Valid(saved.Authorizations[0].ID, opaqueid.ACMEAuthorizationPrefix) || saved.Authorizations[0].Revision != 1 {
		t.Fatalf("saved work = %#v, %v", saved, err)
	}
	released, found, err := database.ClaimACMEOrderWork(t.Context(), "third", now.Add(2*time.Second), time.Minute)
	if err != nil || !found || released.ID != saved.ID || released.WorkEpoch != recovered.WorkEpoch+1 {
		t.Fatalf("released work = %#v, %t, %v", released, found, err)
	}
}

func TestIntegrationInstalledCertificateRetainsCleanupWork(t *testing.T) {
	f := newServicePublicationFixture(t)
	database, now, authentication, plan := f.database, f.now, f.run, f.prepared.CertificatePlan
	renewAt := now.Add(16 * time.Hour)
	prepared := createPlanIssuanceWork(t, database, now, authentication, plan, true, func(work *ACMEOrderWork) {
		work.Authorizations[0].State = "valid"
		work.Authorizations[0].CleanupCompletedAt = nil
		work.RenewAt, work.AvailableAt = &renewAt, now
	})
	issued, err := database.GetServiceCertificateIssuance(t.Context(), authentication.ServiceID, authentication.RunID, authentication.Token, prepared.ID, now)
	if err != nil || issued.State != "waiting_for_install" || issued.CertificatePEM == "" {
		t.Fatalf("certificate blocked on DNS cleanup: state=%q certificate=%t error=%v", issued.State, issued.CertificatePEM != "", err)
	}
	// installation invalidates the claimed revision. cleanup must resume without
	// waiting out the invalidated worker's remaining lease.
	claimed, found, err := database.ClaimACMEOrderWork(t.Context(), "before-install", now.Add(time.Second), time.Minute)
	if err != nil || !found || claimed.ID != prepared.ID || claimed.Authorizations[0].State != "valid" {
		t.Fatalf("uninstalled cleanup claim: found=%t error=%v", found, err)
	}
	if err := database.MarkServiceCertificateInstalled(t.Context(), authentication.ServiceID, authentication.RunID, authentication.Token, prepared.ID, authentication.RunNumber, *prepared.NotAfter, now.Add(1500*time.Millisecond)); err != nil {
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
	if err := database.MarkServiceCertificateInstalled(t.Context(), authentication.ServiceID, authentication.RunID, authentication.Token, prepared.ID, authentication.RunNumber, *prepared.NotAfter, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
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
	challenge, err := database.GetDNSChallengeContextForSubject(t.Context(), cleanup.Subject, cleanup.Authorizations[0].ID)
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
	installed, err := database.GetServiceCertificateIssuance(t.Context(), authentication.ServiceID, authentication.RunID, authentication.Token, prepared.ID, now.Add(4*time.Second))
	if err != nil || installed.State != "installed" || installed.CertificatePEM != issued.CertificatePEM {
		t.Fatalf("cleanup changed installed material: state=%q error=%v", installed.State, err)
	}
}

func TestIntegrationACMEWorkRejectsStaleState(t *testing.T) {
	for _, kind := range []string{"lease", "order_revision", "authorization_revision"} {
		t.Run(kind, func(t *testing.T) {
			f := newServicePublicationFixture(t)
			prepared := createPlanIssuanceWork(t, f.database, f.now, f.run, f.prepared.CertificatePlan, false, nil)
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

func TestIntegrationClosingSessionCleansDNSAuthorizations(t *testing.T) {
	f := newServicePublicationFixture(t)
	database, now, authentication, plan := f.database, f.now, f.run, f.prepared.CertificatePlan
	work := createPlanIssuanceWork(t, database, now, authentication, plan, false, nil)
	if len(work.Authorizations) != 1 || !opaqueid.Valid(work.Authorizations[0].PresentationReference, opaqueid.ACMEPresentationPrefix) {
		t.Fatalf("DNS authorizations = %#v", work.Authorizations)
	}
	challenge, err := database.GetDNSChallengeContextForSubject(t.Context(), work.Subject, work.Authorizations[0].ID)
	if err != nil || len(challenge.Presentations) != 1 || !challenge.Presentations[0].Active || challenge.PresentationReference != work.Authorizations[0].PresentationReference {
		t.Fatalf("DNS challenge = %#v, %v", challenge, err)
	}
	wrong, _, err := credentials.NewServiceRunToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := database.CloseServiceRun(t.Context(), authentication.ServiceID, authentication.RunID, wrong.String(), now); !errors.Is(err, ErrServiceAccess) {
		t.Fatalf("wrong close credential: %v", err)
	}
	if err := database.CloseServiceRun(t.Context(), authentication.ServiceID, authentication.RunID, authentication.Token, now); err != nil {
		t.Fatal(err)
	}
	cleanup, found, err := database.ClaimACMEOrderWork(t.Context(), "cleanup", now, time.Minute)
	if err != nil || !found || cleanup.ID != work.ID || cleanup.State != "authorizing" ||
		len(cleanup.Authorizations) != 1 || cleanup.Authorizations[0].State != "presenting" {
		t.Fatalf("closing a run lost resumable issuance: found=%t state=%s error=%v", found, cleanup.State, err)
	}
	// the publisher's approved CSR survives a run restart. only a terminal
	// issuance result removes its DNS presentation, not the old run closing.
	cleanup.State, cleanup.Authorizations[0].State = "canceled", "cleaning"
	cleanup, err = database.SaveACMEOrderWork(t.Context(), cleanup, now)
	if err != nil {
		t.Fatal(err)
	}
	cleanup, found, err = database.ClaimACMEOrderWork(t.Context(), "terminal-cleanup", now, time.Minute)
	if err != nil || !found || cleanup.State != "canceled" || cleanup.Authorizations[0].State != "cleaning" {
		t.Fatal("terminal issuance did not retain required DNS cleanup", found, cleanup.State, err)
	}
	challenge, err = database.GetDNSChallengeContextForSubject(t.Context(), cleanup.Subject, cleanup.Authorizations[0].ID)
	if err != nil || len(challenge.Presentations) != 1 || challenge.Presentations[0].Active {
		t.Fatalf("cleaning challenge = %#v, %v", challenge, err)
	}
	cleanup.Authorizations[0].State, cleanup.Authorizations[0].CleanupCompletedAt, cleanup.Authorizations[0].AvailableAt = "complete", &now, now
	cleanup.AvailableAt = now
	if _, err := database.SaveACMEOrderWork(t.Context(), cleanup, now); err != nil {
		t.Fatal(err)
	}
	if err := database.CloseServiceRun(t.Context(), authentication.ServiceID, authentication.RunID, authentication.Token, now); err != nil {
		t.Fatalf("exact close retry did not confirm the terminal run: %v", err)
	}
	if _, err := database.HeartbeatServiceRun(t.Context(), authentication.ServiceID, authentication.RunID, authentication.Token, now,
		ServiceRunHealth{Healthy: true, StreamCapacity: 1}); !errors.Is(err, ErrServiceAccess) {
		t.Fatalf("closed run regained publication authority: %v", err)
	}
	if err := database.CloseServiceRun(t.Context(), authentication.ServiceID, authentication.RunID, wrong.String(), now); !errors.Is(err, ErrServiceAccess) {
		t.Fatalf("terminal close accepted another credential: %v", err)
	}
	if _, found, err := database.ClaimACMEOrderWork(t.Context(), "completed", now.Add(time.Second), time.Minute); err != nil || found {
		t.Fatalf("completed cleanup still claimable = %t, %v", found, err)
	}
}

func newTestIssuanceCSR(t *testing.T, f servicePublicationFixture) []byte {
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
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: f.prepared.CertificatePlan.Identifiers}, key)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}
