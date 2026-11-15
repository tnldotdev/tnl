package state

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/zalando/go-keyring"
)

func TestIntegrationCertificateLifecycle(t *testing.T) {
	for _, scenario := range []string{"same_session_renewal", "closed_before_ack"} {
		t.Run(scenario, func(t *testing.T) {
			f := newServicePublicationFixture(t)
			database, now := f.database, f.now
			keyring.MockInit()
			plan, hostname, authentication := f.prepared.CertificatePlan, f.service.Endpoint.Hostname, f.run
			root := filepath.Join(t.TempDir(), "client")
			local, cache := openLifecycleCache(t, root, f.service.TeamID, f.publisher.ID, plan)
			first := deliverLifecycleCertificate(t, database, cache, authentication, hostname, plan, now)
			if _, found, err := cache.Current(t.Context(), hostname); err != nil || found {
				t.Fatalf("delivered material became current before acknowledgement: %t, %v", found, err)
			}
			if scenario == "same_session_renewal" {
				if err := database.MarkServiceCertificateInstalled(t.Context(), authentication.ServiceID, authentication.RunID, authentication.Token, first.IssuanceID, authentication.RunNumber, first.Certificate.Leaf.NotAfter, now); err != nil {
					t.Fatal(err)
				}
				if err := cache.Promote(t.Context(), hostname, first.IssuanceID); err != nil {
					t.Fatal(err)
				}
				second := deliverLifecycleCertificate(t, database, cache, authentication, hostname, plan, now.Add(time.Second))
				current, found, err := cache.Current(t.Context(), hostname)
				if err != nil || !found || current.IssuanceID != first.IssuanceID || first.IssuanceID == second.IssuanceID {
					t.Fatalf("staging renewal replaced current: %t, %v", found, err)
				}
				for retry := range 2 {
					err := database.MarkServiceCertificateInstalled(t.Context(), authentication.ServiceID, authentication.RunID, authentication.Token, second.IssuanceID, authentication.RunNumber, second.Certificate.Leaf.NotAfter, now.Add(time.Duration(retry+1)*time.Second))
					if err != nil {
						t.Fatalf("distinct-issuance acknowledgement/retry %d in same live run: %v", retry, err)
					}
				}
				if err := cache.Promote(t.Context(), hostname, second.IssuanceID); err != nil {
					t.Fatal(err)
				}
				var installedID string
				if err := database.pool.QueryRow(t.Context(), `SELECT certificate_issuance_id FROM control.service_runs WHERE id = $1`, authentication.RunID).Scan(&installedID); err != nil || installedID != second.IssuanceID {
					t.Fatalf("renewal did not replace persisted session certificate: %q, %v", installedID, err)
				}
				return
			}
			// material is delivered and staged, but neither control nor the local cache has acknowledged it.
			if err := database.CloseServiceRun(t.Context(), authentication.ServiceID, authentication.RunID, authentication.Token, now); err != nil {
				t.Fatal(err)
			}
			var state string
			var certificate []byte
			if err := database.pool.QueryRow(t.Context(), `SELECT state, certificate_pem FROM control.acme_orders WHERE id = $1`, first.IssuanceID).Scan(&state, &certificate); err != nil || state != "waiting_for_install" || len(certificate) == 0 {
				t.Fatalf("closing session destroyed delivered issuance: %q, %v", state, err)
			}
			if err := database.MarkServiceCertificateInstalled(t.Context(), authentication.ServiceID, authentication.RunID, authentication.Token, first.IssuanceID, authentication.RunNumber, first.Certificate.Leaf.NotAfter, now); !errors.Is(err, ErrServiceAccess) {
				t.Fatalf("closed session acknowledged material: %v", err)
			}
			if err := local.Close(); err != nil {
				t.Fatal(err)
			}
			_, cache = openLifecycleCache(t, root, f.service.TeamID, f.publisher.ID, plan)
			f.start(t, "replacement", now)
			replacement := f.run
			staged, found, err := cache.Staged(t.Context(), hostname)
			if err != nil || !found || !bytes.Equal(staged.Certificate.Certificate[0], first.Certificate.Certificate[0]) {
				t.Fatalf("restart lost staged material: %t, %v", found, err)
			}
			if err := database.MarkServiceCertificateInstalled(t.Context(), replacement.ServiceID, replacement.RunID, replacement.Token, staged.IssuanceID, replacement.RunNumber, staged.Certificate.Leaf.NotAfter, now); err != nil {
				t.Fatalf("replacement could not acknowledge delivered material after restart: %v", err)
			}
			if err := cache.Promote(t.Context(), hostname, staged.IssuanceID); err != nil {
				t.Fatal(err)
			}
			current, found, err := cache.Current(t.Context(), hostname)
			if err != nil || !found || current.IssuanceID != first.IssuanceID {
				t.Fatalf("sibling promotion: %t, %v", found, err)
			}
			var count int
			if err := database.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.acme_orders`).Scan(&count); err != nil || count != 1 {
				t.Fatalf("cache recovery created another issuance: %d, %v", count, err)
			}
		})
	}
}

func openLifecycleCache(t *testing.T, root, team, publisher string, plan CertificatePlan) (*clientstate.Database, *clientstate.CertificateCache) {
	t.Helper()
	local, err := clientstate.Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = local.Close() })
	store, err := local.Server(t.Context(), "https://control.example.test")
	if err != nil {
		t.Fatal(err)
	}
	cache, err := store.CertificatesForPublisher(team, publisher, controlv1.CertificatePlan{
		CacheKey: plan.CacheKey, Scope: plan.Scope, Identifiers: plan.Identifiers, ChallengeMethod: controlv1.CertificateChallengeMethod(plan.ChallengeMethod),
	})
	if err != nil {
		t.Fatal(err)
	}
	return local, cache
}

func deliverLifecycleCertificate(t *testing.T, database *Database, cache *clientstate.CertificateCache, run ServiceRunState, hostname string, plan CertificatePlan, now time.Time) clientstate.Material {
	t.Helper()
	pending, err := cache.Pending(t.Context(), hostname)
	if err != nil {
		t.Fatal(err)
	}
	account, err := database.EnsureACMEAccount(t.Context(), "https://acme.example.test/directory", "operator@example.test", now)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(pending.CSRDER)
	issuance, err := database.CreateServiceCertificateIssuance(t.Context(), run.ServiceID, run.RunID, run.Token,
		account.DirectoryURL, fmt.Sprintf("issuance_%x", digest), run.RunNumber, pending.CSRDER, now)
	if err != nil {
		t.Fatal(err)
	}
	work, found, err := database.ClaimACMEOrderWork(t.Context(), "lifecycle-test", now, time.Minute)
	if err != nil || !found || work.ID != issuance.ID {
		t.Fatalf("claim lifecycle issuance: %t, %v", found, err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano()), DNSNames: plan.Identifiers,
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, pending.Key.Public(), pending.Key)
	if err != nil {
		t.Fatal(err)
	}
	work.State, work.CertificatePEM = "waiting_for_install", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	work.NotBefore, work.NotAfter, work.AvailableAt = &leaf.NotBefore, &leaf.NotAfter, now
	renewAt, expiresAt := now.Add(16*time.Hour), now.Add(time.Hour)
	work.RenewAt = &renewAt
	for index, identifier := range plan.Identifiers {
		work.Authorizations = append(work.Authorizations, ACMEAuthorizationWork{
			Identifier: identifier, AuthorizationURL: fmt.Sprintf("https://acme.example.test/authz/%s/%d", work.ID, index),
			ChallengeType: plan.ChallengeMethod, ChallengeURL: fmt.Sprintf("https://acme.example.test/challenge/%s/%d", work.ID, index),
			ChallengeToken: fmt.Sprintf("token-%d", index), ChallengeDigest: sha256.Sum256([]byte(identifier)),
			State: "complete", AvailableAt: now, PresentedAt: &now, ValidatedAt: &now, CleanupCompletedAt: &now, ExpiresAt: &expiresAt,
		})
	}
	if _, err := database.SaveACMEOrderWork(t.Context(), work, now); err != nil {
		t.Fatal(err)
	}
	delivered, err := database.GetServiceCertificateIssuance(t.Context(), run.ServiceID, run.RunID, run.Token, work.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	material, err := cache.Stage(t.Context(), hostname, pending, []byte(delivered.CertificatePEM), now.Add(16*time.Hour), delivered.ID)
	if err != nil {
		t.Fatal(err)
	}
	return material
}
