package clientstate

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestCertificateMaterialLifecycleSurvivesRestart(t *testing.T) {
	for _, test := range []struct {
		name      string
		plan      controlv1.CertificatePlan
		hostnames []string
	}{
		{name: "exact_host", plan: exactCertificateTestPlan(), hostnames: []string{"route.example"}},
		{
			name: "namespace",
			plan: controlv1.CertificatePlan{
				CacheKey: "member.example", Scope: "member.example",
				Identifiers: []string{"member.example", "*.member.example"}, ChallengeMethod: controlv1.Dns01,
			},
			hostnames: []string{"member.example", "app.member.example"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "state")
			store := testStore(t, root, "https://server.example")
			cache, err := store.Certificates("team_1", test.plan)
			if err != nil {
				t.Fatal(err)
			}
			pending, err := cache.Pending(t.Context(), test.hostnames[0])
			if err != nil {
				t.Fatal(err)
			}
			csr := bytes.Clone(pending.CSRDER)
			renewAt := time.Now().Add(30 * 24 * time.Hour).UTC().Truncate(time.Second)
			material, err := cache.Stage(
				t.Context(), test.hostnames[0], pending,
				signedCertificate(t, pending.Key, test.plan.Identifiers...), renewAt, "issuance_current",
			)
			if err != nil {
				t.Fatal(err)
			}
			if material.Certificate.Leaf == nil || !material.RenewAt.Equal(renewAt) {
				t.Fatalf("staged material = %+v", material)
			}
			for _, hostname := range test.hostnames {
				loaded, found, err := cache.Staged(t.Context(), hostname)
				if err != nil || !found || !bytes.Equal(loaded.Certificate.Certificate[0], material.Certificate.Certificate[0]) ||
					!loaded.RenewAt.Equal(renewAt) || loaded.IssuanceID != material.IssuanceID {
					t.Fatalf("staged material for %s: found=%t material=%+v error=%v", hostname, found, loaded, err)
				}
				if _, found, err := cache.Current(t.Context(), hostname); err != nil || found {
					t.Fatalf("unacknowledged material for %s became current: found=%t error=%v", hostname, found, err)
				}
			}
			if err := store.database.Close(); err != nil {
				t.Fatal(err)
			}
			store = testStore(t, root, "https://server.example")
			slices.Reverse(test.plan.Identifiers)
			cache, err = store.Certificates("team_1", test.plan)
			if err != nil {
				t.Fatal(err)
			}
			for _, hostname := range test.hostnames {
				loaded, found, err := cache.Staged(t.Context(), hostname)
				if err != nil || !found || !bytes.Equal(loaded.Certificate.Certificate[0], material.Certificate.Certificate[0]) {
					t.Fatalf("staged material for %s after restart: found=%t error=%v", hostname, found, err)
				}
				recovered, err := cache.Pending(t.Context(), hostname)
				if err != nil || !bytes.Equal(recovered.CSRDER, csr) {
					t.Fatalf("staged CSR recovery for %s after restart: %v", hostname, err)
				}
			}
			if err := cache.Promote(t.Context(), test.hostnames[0], material.IssuanceID); err != nil {
				t.Fatal(err)
			}
			if _, found, err := cache.Staged(t.Context(), test.hostnames[0]); err != nil || found {
				t.Fatalf("staged material remained after promotion: found=%t error=%v", found, err)
			}
			if err := store.database.Close(); err != nil {
				t.Fatal(err)
			}
			store = testStore(t, root, "https://server.example")
			cache, err = store.Certificates("team_1", test.plan)
			if err != nil {
				t.Fatal(err)
			}
			for _, hostname := range test.hostnames {
				current, found, err := cache.Current(t.Context(), hostname)
				if err != nil || !found || !bytes.Equal(current.Certificate.Certificate[0], material.Certificate.Certificate[0]) {
					t.Fatalf("current material for %s after restart: found=%t error=%v", hostname, found, err)
				}
			}
			replacement, err := cache.NewPending(t.Context(), test.hostnames[0])
			if err != nil {
				t.Fatal(err)
			}
			selected, err := cache.Pending(t.Context(), test.hostnames[0])
			if err != nil {
				t.Fatal(err)
			}
			if replacement.Key.PublicKey.Equal(&pending.Key.PublicKey) || !bytes.Equal(selected.CSRDER, replacement.CSRDER) || bytes.Equal(selected.CSRDER, csr) {
				t.Fatal("renewal did not replace the recovered certificate key and CSR")
			}
		})
	}
}

func TestCertificateStageRejectsInvalidCSRBeforeReplacingCurrent(t *testing.T) {
	for _, name := range []string{"invalid_DER", "wrong_key", "extra_SAN"} {
		t.Run(name, func(t *testing.T) {
			store := testStore(t, filepath.Join(t.TempDir(), "state"), "https://server.example")
			route, err := store.Certificates("team_1", exactCertificateTestPlan())
			if err != nil {
				t.Fatal(err)
			}
			original, err := route.Pending(t.Context(), "route.example")
			if err != nil {
				t.Fatal(err)
			}
			material, err := route.Stage(t.Context(), "route.example", original, signedCertificate(t, original.Key, "route.example"), time.Now().Add(time.Hour), "issuance_original")
			if err != nil {
				t.Fatal(err)
			}
			if err := route.Promote(t.Context(), "route.example", material.IssuanceID); err != nil {
				t.Fatal(err)
			}
			pending, err := route.NewPending(t.Context(), "route.example")
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "invalid_DER":
				pending.CSRDER = []byte("invalid CSR")
			case "wrong_key":
				pending.CSRDER = original.CSRDER
			case "extra_SAN":
				pending.CSRDER, err = x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"route.example", "other.example"}}, pending.Key)
				if err != nil {
					t.Fatal(err)
				}
			}
			_, err = route.Stage(t.Context(), "route.example", pending, signedCertificate(t, pending.Key, "route.example"), time.Now().Add(time.Hour), "issuance_invalid")
			if err == nil {
				t.Error("invalid CSR was committed")
			}
			current, found, err := route.Current(t.Context(), "route.example")
			if err != nil || !found || current.IssuanceID != material.IssuanceID {
				t.Errorf("invalid CSR replaced recoverable current material: found=%t issuance=%q error=%v", found, current.IssuanceID, err)
			}
		})
	}
}

func TestCertificateCacheIsolationAndTransactionLocks(t *testing.T) {
	store := testStore(t, filepath.Join(t.TempDir(), "state"), "https://server.example")
	plan := exactCertificateTestPlan()
	cache, err := store.Certificates("team_1", plan)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := cache.Pending(t.Context(), "route.example")
	if err != nil {
		t.Fatal(err)
	}
	otherPlan := plan
	otherPlan.Scope = "other-scope"
	lock, err := cache.Lock(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	for _, test := range []struct {
		name, server, team string
		plan               controlv1.CertificatePlan
		shared             bool
	}{
		{"same", "https://server.example", "team_1", plan, true},
		{"other_plan", "https://server.example", "team_1", otherPlan, true},
		{"other_team", "https://server.example", "team_2", plan, false},
		{"other_server", "https://other.example", "team_1", plan, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			otherStore, err := store.database.Server(t.Context(), test.server)
			if err != nil {
				t.Fatal(err)
			}
			other, err := otherStore.Certificates(test.team, test.plan)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
			defer cancel()
			otherLock, err := other.Lock(ctx)
			if test.shared {
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("shared lock = %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer otherLock.Close()
			otherPending, err := other.Pending(t.Context(), "route.example")
			if err != nil || bytes.Equal(pending.CSRDER, otherPending.CSRDER) {
				t.Fatalf("certificate key crossed server/team boundary: %v", err)
			}
		})
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	isolated, err := store.Certificates("team_1", otherPlan)
	if err != nil {
		t.Fatal(err)
	}
	isolatedPending, err := isolated.Pending(t.Context(), "route.example")
	if err != nil || bytes.Equal(pending.CSRDER, isolatedPending.CSRDER) {
		t.Fatalf("certificate key crossed plan boundary: %v", err)
	}
	reopened, err := store.Certificates("team_1", plan)
	if err != nil {
		t.Fatal(err)
	}
	lock, err = reopened.Lock(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	got, err := reopened.Pending(t.Context(), "route.example")
	if err != nil || !bytes.Equal(pending.CSRDER, got.CSRDER) {
		t.Fatalf("shared CSR recovery = %v", err)
	}
}

func signedCertificate(t *testing.T, key *ecdsa.PrivateKey, hostnames ...string) []byte {
	t.Helper()
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{}, DNSNames: hostnames,
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(90 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func exactCertificateTestPlan() controlv1.CertificatePlan {
	return controlv1.CertificatePlan{CacheKey: "route.example", Scope: "route.example", Identifiers: []string{"route.example"}, ChallengeMethod: controlv1.TlsAlpn01}
}
