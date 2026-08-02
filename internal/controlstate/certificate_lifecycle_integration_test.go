package controlstate

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

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"github.com/zalando/go-keyring"
)

func TestIntegrationCertificateLifecycle(t *testing.T) {
	for _, scenario := range []string{"same_session_renewal", "closed_before_ack"} {
		t.Run(scenario, func(t *testing.T) {
			database, now := newCertificatePlanDatabase(t)
			keyring.MockInit()
			plan := CertificatePlan{CacheKey: "member.routes.example.test", Scope: "member.routes.example.test",
				Identifiers: []string{"*.member.routes.example.test", "member.routes.example.test"}, ChallengeMethod: "dns-01"}
			hostname := "first.member.routes.example.test"
			_, authentication := newExternalPlanSession(t, database, now, "team_external", hostname, "managed:routes.example.test", plan)
			root := filepath.Join(t.TempDir(), "client")
			local, cache := openLifecycleCache(t, root, plan)
			first := deliverLifecycleCertificate(t, database, cache, authentication, hostname, plan, now)
			if _, found, err := cache.Current(t.Context(), hostname); err != nil || found {
				t.Fatalf("delivered material became current before acknowledgement: %t, %v", found, err)
			}
			if scenario == "same_session_renewal" {
				if _, err := database.MarkRouteCertificateInstalled(t.Context(), authentication, first.IssuanceID, first.Certificate.Leaf.NotAfter, now); err != nil {
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
					lifecycle, err := database.MarkRouteCertificateInstalled(t.Context(), authentication, second.IssuanceID, second.Certificate.Leaf.NotAfter, now.Add(time.Duration(retry+1)*time.Second))
					if err != nil || lifecycle.CertificateAt == nil || !lifecycle.CertificateAt.Equal(now.Add(time.Second)) || lifecycle.Routable {
						t.Fatalf("distinct-issuance acknowledgement/retry %d in same live session: %#v, %v", retry, lifecycle, err)
					}
				}
				if err := cache.Promote(t.Context(), hostname, second.IssuanceID); err != nil {
					t.Fatal(err)
				}
				var installedID string
				if err := database.pool.QueryRow(t.Context(), `SELECT certificate_issuance_id FROM control.route_sessions WHERE id = $1`, authentication.RouteSessionID).Scan(&installedID); err != nil || installedID != second.IssuanceID {
					t.Fatalf("renewal did not replace persisted session certificate: %q, %v", installedID, err)
				}
				return
			}
			// Material has been delivered and staged, but neither control nor the local cache has an ACK.
			if err := database.CloseRouteSession(t.Context(), authentication.RouteSessionID, authentication.RouteSessionToken, now); err != nil {
				t.Fatal(err)
			}
			var state string
			var certificate []byte
			if err := database.pool.QueryRow(t.Context(), `SELECT state, certificate_pem FROM control.acme_orders WHERE id = $1`, first.IssuanceID).Scan(&state, &certificate); err != nil || state != "waiting_for_install" || len(certificate) == 0 {
				t.Fatalf("closing session destroyed delivered issuance: %q, %v", state, err)
			}
			if _, err := database.MarkRouteCertificateInstalled(t.Context(), authentication, first.IssuanceID, first.Certificate.Leaf.NotAfter, now); !errors.Is(err, ErrRouteSessionStale) {
				t.Fatalf("closed session acknowledged material: %v", err)
			}
			if err := local.Close(); err != nil {
				t.Fatal(err)
			}
			_, cache = openLifecycleCache(t, root, plan)
			hostname = "second.member.routes.example.test"
			_, sibling := newExternalPlanSession(t, database, now, "team_external", hostname, "managed:routes.example.test", plan)
			staged, found, err := cache.Staged(t.Context(), hostname)
			if err != nil || !found || !bytes.Equal(staged.Certificate.Certificate[0], first.Certificate.Certificate[0]) {
				t.Fatalf("restart lost staged material: %t, %v", found, err)
			}
			if _, err := database.MarkRouteCertificateInstalled(t.Context(), sibling, staged.IssuanceID, staged.Certificate.Leaf.NotAfter, now); err != nil {
				t.Fatalf("sibling could not acknowledge delivered material after restart: %v", err)
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

func openLifecycleCache(t *testing.T, root string, plan CertificatePlan) (*clientstate.Database, *clientstate.CertificateCache) {
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
	cache, err := store.Certificates("team_external", controlv1.CertificatePlan{
		CacheKey: plan.CacheKey, Scope: plan.Scope, Identifiers: plan.Identifiers, ChallengeMethod: controlv1.CertificateChallengeMethod(plan.ChallengeMethod),
	})
	if err != nil {
		t.Fatal(err)
	}
	return local, cache
}

func deliverLifecycleCertificate(t *testing.T, database *Database, cache *clientstate.CertificateCache, authentication RouteSessionAuthentication, hostname string, plan CertificatePlan, now time.Time) clientstate.Material {
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
	issuance, err := database.CreateCertificateIssuance(t.Context(), CreateCertificateIssuanceRequest{
		Authentication: authentication, DirectoryURL: account.DirectoryURL, IdempotencyKey: fmt.Sprintf("issuance_%x", digest), RequestDigest: digest, CSRDER: pending.CSRDER,
	}, now)
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
	for index, identifier := range plan.Identifiers {
		work.Authorizations = append(work.Authorizations, ACMEAuthorizationWork{
			Identifier: identifier, AuthorizationURL: fmt.Sprintf("https://acme.example.test/authz/%s/%d", work.ID, index),
			ChallengeType: plan.ChallengeMethod, ChallengeURL: fmt.Sprintf("https://acme.example.test/challenge/%s/%d", work.ID, index),
			ChallengeToken: fmt.Sprintf("token-%d", index), ChallengeDigest: sha256.Sum256([]byte(identifier)),
			State: "complete", AvailableAt: now, PresentedAt: &now, ValidatedAt: &now, CleanupCompletedAt: &now,
		})
	}
	if _, err := database.SaveACMEOrderWork(t.Context(), work, now); err != nil {
		t.Fatal(err)
	}
	delivered, err := database.GetCertificateIssuance(t.Context(), work.ID, authentication.RouteSessionToken, now)
	if err != nil {
		t.Fatal(err)
	}
	material, err := cache.Stage(t.Context(), hostname, pending, []byte(delivered.CertificatePEM), now.Add(16*time.Hour), delivered.ID)
	if err != nil {
		t.Fatal(err)
	}
	return material
}
