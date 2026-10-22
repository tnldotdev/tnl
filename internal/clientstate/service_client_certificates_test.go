package clientstate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/visitorcert"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestServiceClientCertificateRecoversCSRAndKeepsNativeClientKey(t *testing.T) {
	ctx := t.Context()
	root := filepath.Join(t.TempDir(), "state")
	db := openFileDatabase(t, root)
	store, err := db.Server(ctx, "https://control.example")
	if err != nil {
		t.Fatal(err)
	}
	id := func(prefix string) string {
		t.Helper()
		value, err := opaqueid.New(prefix)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	identity, service, device := id(opaqueid.IdentityPrefix), id(opaqueid.PrivateServicePrefix), id(opaqueid.VisitorDevicePrefix)
	seed := make([]byte, ed25519.SeedSize)
	if _, err = rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	issuer, err := visitorcert.New(seed)
	if err != nil {
		t.Fatal(err)
	}
	var csr []byte
	var issued controlv1.ServiceClientCertificate
	calls := 0
	lost := errors.New("lost committed certificate response")
	issue := func(_ context.Context, request []byte) (controlv1.ServiceClientCertificate, error) {
		calls++
		if calls >= 4 {
			if !bytes.Equal(csr, request) {
				t.Fatal("revalidation changed the issued CSR")
			}
			return issued, nil
		}
		if calls == 2 {
			if !bytes.Equal(csr, request) {
				t.Fatal("restart changed the pending CSR")
			}
			return issued, nil
		}
		now := time.Now().UTC().Truncate(time.Second)
		expires := now.Add(visitorcert.MaxLifetime)
		if calls == 1 {
			csr = bytes.Clone(request)
			expires = now.Add(12 * time.Hour)
		}
		certificate, err := issuer.Issue(request, service, identity, device, expires, now)
		if err != nil {
			return controlv1.ServiceClientCertificate{}, err
		}
		issued = controlv1.ServiceClientCertificate{PrivateServiceId: service, CertificatePem: string(certificate), IssuerPem: string(issuer.CertificatePEM()), ExpiresAt: expires}
		csr = bytes.Clone(request)
		if calls == 1 {
			return controlv1.ServiceClientCertificate{}, lost
		}
		return issued, nil
	}
	if _, err = store.EnsureServiceClientCertificate(ctx, identity, service, device, issue); !errors.Is(err, lost) {
		t.Fatal("uncertain issuance was hidden", err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db = openFileDatabase(t, root)
	store, err = db.Server(ctx, "https://control.example")
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := store.EnsureServiceClientCertificate(ctx, identity, service, device, issue)
	if err != nil || calls != 2 {
		t.Fatal("pending certificate did not survive task-local restart", err, calls)
	}
	key, err := os.ReadFile(recovered.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := store.EnsureServiceClientCertificate(ctx, identity, service, device, issue)
	if err != nil || calls != 3 || renewed.KeyFile != recovered.KeyFile || renewed.CertificateFile != recovered.CertificateFile || !renewed.ExpiresAt.After(recovered.ExpiresAt) {
		t.Fatal("renewal changed the native client profile", err, calls)
	}
	after, err := os.ReadFile(renewed.KeyFile)
	if err != nil || !bytes.Equal(key, after) {
		t.Fatal("renewal replaced the exported client key", err)
	}
	for _, path := range []string{renewed.KeyFile, renewed.CertificateFile} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("native client credential is not protected", err)
		}
	}
	if _, err = store.EnsureServiceClientCertificate(ctx, identity, service, device, issue); err != nil || calls != 4 {
		t.Fatal("valid credentials did not revalidate the same issuance", err, calls)
	}
	if _, err = tls.LoadX509KeyPair(renewed.CertificateFile, renewed.KeyFile); err != nil {
		t.Fatal("native TLS client could not use the exported credential", err)
	}
	if err = os.Remove(renewed.KeyFile); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(renewed.CertificateFile, renewed.KeyFile); err != nil {
		t.Fatal(err)
	}
	if _, err = store.EnsureServiceClientCertificate(ctx, identity, service, device, issue); !errors.Is(err, ErrPublisherStateConflict) {
		t.Fatal("credential export followed a substituted key path", err)
	}
}

func TestServiceClientCertificateRejectsUndurableAndMismatchedReplies(t *testing.T) {
	for _, rejection := range []string{"denied", "wrong-key", "expired", "save-failed", "revalidation-changed"} {
		t.Run(rejection, func(t *testing.T) {
			db := openFileDatabase(t, filepath.Join(t.TempDir(), "state"))
			store, err := db.Server(t.Context(), "https://control.example")
			if err != nil {
				t.Fatal(err)
			}
			identity, _ := opaqueid.New(opaqueid.IdentityPrefix)
			service, _ := opaqueid.New(opaqueid.PrivateServicePrefix)
			device, _ := opaqueid.New(opaqueid.VisitorDevicePrefix)
			issuer, err := visitorcert.New(make([]byte, ed25519.SeedSize))
			if err != nil {
				t.Fatal(err)
			}
			denied := errors.New("rejected by current control session")
			var saved []byte
			var old ServiceClientMaterial
			valid := func(_ context.Context, csr []byte) (controlv1.ServiceClientCertificate, error) {
				now := time.Now().UTC().Truncate(time.Second)
				expires := now.Add(visitorcert.MaxLifetime)
				certificate, err := issuer.Issue(csr, service, identity, device, expires, now)
				return controlv1.ServiceClientCertificate{PrivateServiceId: service, CertificatePem: string(certificate), IssuerPem: string(issuer.CertificatePEM()), ExpiresAt: expires}, err
			}
			if rejection == "revalidation-changed" {
				old, err = store.EnsureServiceClientCertificate(t.Context(), identity, service, device, valid)
				if err != nil {
					t.Fatal(err)
				}
				saved, err = os.ReadFile(old.CertificateFile)
				if err != nil {
					t.Fatal(err)
				}
			}
			if rejection == "save-failed" {
				if _, err := db.db.Exec(`CREATE TRIGGER fail_service_certificate BEFORE UPDATE OF certificate_pem ON service_client_certificates BEGIN SELECT RAISE(ABORT,'fixture durability failure'); END`); err != nil {
					t.Fatal(err)
				}
			}
			issue := func(ctx context.Context, csr []byte) (controlv1.ServiceClientCertificate, error) {
				if rejection == "denied" {
					return controlv1.ServiceClientCertificate{}, denied
				}
				if rejection == "wrong-key" {
					_, key, err := ed25519.GenerateKey(rand.Reader)
					if err != nil {
						return controlv1.ServiceClientCertificate{}, err
					}
					csr, err = x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
					if err != nil {
						return controlv1.ServiceClientCertificate{}, err
					}
				}
				if rejection == "expired" {
					now := time.Now().UTC().Truncate(time.Second).Add(-2 * time.Hour)
					expires := now.Add(time.Hour)
					certificate, err := issuer.Issue(csr, service, identity, device, expires, now)
					return controlv1.ServiceClientCertificate{PrivateServiceId: service, CertificatePem: string(certificate), IssuerPem: string(issuer.CertificatePEM()), ExpiresAt: expires}, err
				}
				// issuing the same CSR again here deliberately returns another leaf,
				// unlike control's idempotent response. revalidation must reject it.
				return valid(ctx, csr)
			}
			material, err := store.EnsureServiceClientCertificate(t.Context(), identity, service, device, issue)
			if err == nil || material.CertificateFile != "" || material.KeyFile != "" || material.Certificate.PrivateKey != nil {
				t.Fatal("rejection exposed unusable credentials", err)
			}
			if rejection == "revalidation-changed" {
				current, err := os.ReadFile(old.CertificateFile)
				if err != nil || !bytes.Equal(saved, current) {
					t.Fatal("rejection replaced a durable certificate", err)
				}
				if _, err := tls.LoadX509KeyPair(old.CertificateFile, old.KeyFile); err != nil {
					t.Fatal(err)
				}
			} else if entries, err := os.ReadDir(filepath.Join(db.root, "service-clients")); !errors.Is(err, os.ErrNotExist) || len(entries) != 0 {
				t.Fatal("rejected issuance created exported credential paths", err)
			}
		})
	}
}

func TestExpiredServiceClientCertificateRenewsWithStableKey(t *testing.T) {
	db := openFileDatabase(t, filepath.Join(t.TempDir(), "state"))
	store, err := db.Server(t.Context(), "https://control.example")
	if err != nil {
		t.Fatal(err)
	}
	identity, _ := opaqueid.New(opaqueid.IdentityPrefix)
	service, _ := opaqueid.New(opaqueid.PrivateServicePrefix)
	device, _ := opaqueid.New(opaqueid.VisitorDevicePrefix)
	issuer, err := visitorcert.New(make([]byte, ed25519.SeedSize))
	if err != nil {
		t.Fatal(err)
	}
	var original []byte
	issue := func(_ context.Context, csr []byte) (controlv1.ServiceClientCertificate, error) {
		now := time.Now().UTC().Truncate(time.Second)
		certificate, err := issuer.Issue(csr, service, identity, device, now.Add(visitorcert.MaxLifetime), now)
		if original == nil {
			original = bytes.Clone(csr)
		} else if bytes.Equal(original, csr) {
			t.Fatal("expired leaf reused its old issuance request")
		}
		return controlv1.ServiceClientCertificate{PrivateServiceId: service, CertificatePem: string(certificate), IssuerPem: string(issuer.CertificatePEM()), ExpiresAt: now.Add(visitorcert.MaxLifetime)}, err
	}
	before, err := store.EnsureServiceClientCertificate(t.Context(), identity, service, device, issue)
	if err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(before.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	expired, err := issuer.Issue(original, service, identity, device, now.Add(-time.Hour), now.Add(-2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.db.Exec(`UPDATE service_client_certificates SET certificate_pem=?`, expired); err != nil {
		t.Fatal(err)
	}
	after, err := store.EnsureServiceClientCertificate(t.Context(), identity, service, device, issue)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(after.KeyFile)
	if err != nil || !bytes.Equal(key, got) || after.CertificateFile != before.CertificateFile {
		t.Fatal("expiration replaced stable key or paths", err)
	}
	if _, err := tls.LoadX509KeyPair(after.CertificateFile, after.KeyFile); err != nil {
		t.Fatal(err)
	}
}
