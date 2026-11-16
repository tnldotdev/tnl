package service

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/security/certificateidentity"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestServiceCertificateRejectsInconsistentIssuanceBeforeCommit(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*controlv1.ServiceCertificateIssuance)
	}{
		{"empty issuance", func(i *controlv1.ServiceCertificateIssuance) { i.Id = "" }},
		{"empty pending issuance", func(i *controlv1.ServiceCertificateIssuance) {
			i.Id, i.State, i.CertificatePem, i.NotBefore, i.NotAfter = "", controlv1.CertificateIssuanceStatePending, nil, nil, nil
		}},
		{"publisher", func(i *controlv1.ServiceCertificateIssuance) {
			i.PublisherIdentityId = "pub_" + strings.Repeat("X", 22)
		}},
		{"service", func(i *controlv1.ServiceCertificateIssuance) { i.ServiceId = "" }},
		{"run", func(i *controlv1.ServiceCertificateIssuance) { i.ServiceRunId = "" }},
		{"number", func(i *controlv1.ServiceCertificateIssuance) { i.RunNumber = 0 }},
		{"plan key", func(i *controlv1.ServiceCertificateIssuance) { i.CertificatePlan.CacheKey = "different-key" }},
		{"plan scope", func(i *controlv1.ServiceCertificateIssuance) { i.CertificatePlan.Scope = "different-scope" }},
		{"plan identifiers", func(i *controlv1.ServiceCertificateIssuance) {
			i.CertificatePlan.Identifiers = []string{"other.example"}
		}},
		{"plan method", func(i *controlv1.ServiceCertificateIssuance) { i.CertificatePlan.ChallengeMethod = "unsupported" }},
		{"unknown state", func(i *controlv1.ServiceCertificateIssuance) { i.State = "unknown"; i.CertificatePem = nil }},
		{"unknown state with material", func(i *controlv1.ServiceCertificateIssuance) { i.State = "unknown" }},
		{"installed without material", func(i *controlv1.ServiceCertificateIssuance) {
			i.State = controlv1.CertificateIssuanceStateInstalled
			i.CertificatePem = nil
		}},
		{"waiting without material", func(i *controlv1.ServiceCertificateIssuance) { i.CertificatePem = nil }},
		{"pending with material", func(i *controlv1.ServiceCertificateIssuance) { i.State = controlv1.CertificateIssuanceStatePending }},
		{"authorizing with material", func(i *controlv1.ServiceCertificateIssuance) { i.State = controlv1.CertificateIssuanceStateAuthorizing }},
		{"ready with material", func(i *controlv1.ServiceCertificateIssuance) {
			i.State = controlv1.CertificateIssuanceStateReadyToFinalize
		}},
		{"finalizing with material", func(i *controlv1.ServiceCertificateIssuance) { i.State = controlv1.CertificateIssuanceStateFinalizing }},
		{"failed with material", func(i *controlv1.ServiceCertificateIssuance) { i.State = controlv1.CertificateIssuanceStateFailed }},
		{"canceled with material", func(i *controlv1.ServiceCertificateIssuance) { i.State = controlv1.CertificateIssuanceStateCanceled }},
		{"missing validity", func(i *controlv1.ServiceCertificateIssuance) { i.NotBefore = nil }},
		{"missing expiry", func(i *controlv1.ServiceCertificateIssuance) { i.NotAfter = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				certificates, control, prepared := certificateRecoveryFixture(t)
				var response controlv1.ServiceCertificateIssuance
				control.create = func(csr []byte, _ string) (controlv1.ServiceCertificateIssuance, error) {
					var err error
					response, err = certificateFixtureIssuance(control.lifecycleControl, csr, nil)
					test.change(&response)
					return response, err
				}
				polls, acknowledgments := 0, 0
				control.get = func(context.Context, string) (controlv1.ServiceCertificateIssuance, error) {
					polls++
					return response, nil
				}
				control.installed = func(string, time.Time) error { acknowledgments++; return nil }
				ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
				defer cancel()
				material, err := certificates.advance(ctx, true)
				if err == nil {
					_ = certificates.Install(material.Certificate)
					t.Error("inconsistent issuance was accepted")
				}
				if errors.Is(err, context.DeadlineExceeded) || polls != 0 {
					t.Error("malformed issuance was polled instead of rejected", polls, err)
				}
				if acknowledgments != 0 {
					t.Error("malformed issuance was acknowledged", acknowledgments)
				}
				certificateAssertNoMaterial(t, certificates, prepared)
			})
		})
	}
}

func certificateAssertNoMaterial(t *testing.T, certificates Certificates, prepared *Prepared) {
	t.Helper()
	if _, found, err := certificates.Cache.Current(t.Context(), certificates.Hostname); err != nil || found {
		t.Error("invalid issuance changed durable current material", found, err)
	}
	if _, found, err := certificates.Cache.Staged(t.Context(), certificates.Hostname); err != nil || found {
		t.Error("invalid issuance staged certificate material", found, err)
	}
	if _, err := prepared.currentCertificate(); err == nil {
		t.Error("invalid issuance became available to visitors")
	}
}

func TestServiceCertificatePollKeepsSelectedIssuance(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		certificates, control, prepared := certificateRecoveryFixture(t)
		var issued controlv1.ServiceCertificateIssuance
		control.create = func(csr []byte, _ string) (controlv1.ServiceCertificateIssuance, error) {
			var err error
			issued, err = certificateFixtureIssuance(control.lifecycleControl, csr, nil)
			pending := issued
			pending.State, pending.CertificatePem, pending.NotBefore, pending.NotAfter = controlv1.CertificateIssuanceStatePending, nil, nil, nil
			return pending, err
		}
		polls, acknowledgments := 0, 0
		control.get = func(_ context.Context, id string) (controlv1.ServiceCertificateIssuance, error) {
			polls++
			if id != issued.Id {
				t.Error("poll did not select the original issuance")
			}
			changed := issued
			changed.Id = "different-certificate-order"
			return changed, nil
		}
		control.installed = func(string, time.Time) error { acknowledgments++; return nil }
		if _, err := certificates.advance(t.Context(), true); err == nil || polls != 1 || acknowledgments != 0 {
			t.Error("poll substituted another issuance", polls, acknowledgments, err)
		}
		certificateAssertNoMaterial(t, certificates, prepared)
	})
}

func TestServiceCertificateAcceptsSharedOrderFromAnotherRun(t *testing.T) {
	certificates, control, prepared := certificateRecoveryFixture(t)
	originService, originRun := "svc_"+strings.Repeat("O", 22), "srun_"+strings.Repeat("O", 22)
	control.create = func(csr []byte, _ string) (controlv1.ServiceCertificateIssuance, error) {
		issued, err := certificateFixtureIssuance(control.lifecycleControl, csr, nil)
		issued.ServiceId, issued.ServiceRunId, issued.RunNumber = originService, originRun, 42
		issued.State = controlv1.CertificateIssuanceStateInstalled
		return issued, err
	}
	acknowledged := false
	control.installed = func(string, time.Time) error { acknowledged = true; return nil }
	material, err := certificates.advance(t.Context(), true)
	if err != nil || !acknowledged {
		t.Fatal("compatible shared order was not acknowledged by the consuming run", acknowledged, err)
	}
	if err := certificates.Install(material.Certificate); err != nil {
		t.Fatal(err)
	}
	if current, err := prepared.currentCertificate(); err != nil || !bytes.Equal(current.Certificate[0], material.Certificate.Certificate[0]) {
		t.Fatal("shared order did not reach the consuming serving owner", err)
	}
}

func TestServiceCertificateRejectsInvalidMaterialBeforeCommit(t *testing.T) {
	for _, test := range []struct {
		name   string
		leaf   func(*x509.Certificate)
		change func(*testing.T, *controlv1.ServiceCertificateIssuance)
	}{
		{name: "extra SAN", leaf: func(c *x509.Certificate) { c.DNSNames = append(c.DNSNames, "other.example") }},
		{name: "CA", leaf: func(c *x509.Certificate) { c.IsCA, c.BasicConstraintsValid = true, true }},
		{name: "wrong EKU", leaf: func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }},
		{name: "expired", leaf: func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Second) }},
		{name: "future", leaf: func(c *x509.Certificate) {
			c.NotBefore, c.NotAfter = time.Now().Add(time.Hour), time.Now().Add(2*time.Hour)
		}},
		{name: "invalid PEM", change: func(_ *testing.T, i *controlv1.ServiceCertificateIssuance) {
			i.CertificatePem = new("not a certificate")
		}},
		{name: "validity metadata", change: func(_ *testing.T, i *controlv1.ServiceCertificateIssuance) {
			i.NotBefore = new(i.NotBefore.Add(time.Second))
		}},
		{name: "wrong key", change: func(t *testing.T, i *controlv1.ServiceCertificateIssuance) {
			certificate, _ := managedTestCertificate(t, i.CertificatePlan.Identifiers[0])
			i.CertificatePem = new(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]})))
			leaf, err := x509.ParseCertificate(certificate.Certificate[0])
			if err != nil {
				t.Fatal(err)
			}
			i.NotBefore, i.NotAfter = &leaf.NotBefore, &leaf.NotAfter
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			certificates, control, prepared := certificateRecoveryFixture(t)
			control.create = func(csr []byte, _ string) (controlv1.ServiceCertificateIssuance, error) {
				issued, err := certificateFixtureIssuance(control.lifecycleControl, csr, test.leaf)
				if test.change != nil && err == nil {
					test.change(t, &issued)
				}
				return issued, err
			}
			acknowledgments := 0
			control.installed = func(string, time.Time) error { acknowledgments++; return nil }
			if _, err := certificates.advance(t.Context(), true); err == nil {
				t.Error("invalid certificate material was accepted")
			}
			if acknowledgments != 0 {
				t.Error("invalid certificate material was acknowledged")
			}
			certificateAssertNoMaterial(t, certificates, prepared)
		})
	}
}

func TestServiceCertificateInstallationDoesNotTrustSuppliedLeaf(t *testing.T) {
	_, _, prepared := certificateRecoveryFixture(t)
	certificate, _ := managedTestCertificate(t, "other.example")
	disguised, _ := managedTestCertificate(t, prepared.managedHostname)
	var err error
	certificate.Leaf, err = x509.ParseCertificate(disguised.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := prepared.installManagedCertificate(certificate); err == nil {
		t.Fatal("supplied Leaf concealed a different certificate identity")
	}
	if _, err := certificateidentity.ValidateCertificate(certificate, prepared.managedHostname, prepared.Preparation.CertificatePlan.Identifiers); err == nil {
		t.Fatal("shared validation trusted the caller's Leaf")
	}
	if _, err := prepared.currentCertificate(); err == nil {
		t.Fatal("disguised certificate became available to visitors")
	}
}

func TestServiceCertificateUsesAuthoritativeNamespaceCSRAndCoverage(t *testing.T) {
	plan := controlv1.CertificatePlan{CacheKey: "member.example", Scope: "member.example",
		Identifiers: []string{"member.example", "*.member.example"}, ChallengeMethod: controlv1.Dns01}
	for _, hostname := range []string{"member.example", "app.member.example"} {
		t.Run(hostname, func(t *testing.T) {
			cfg, base := lifecycleFixture(t)
			base.prep.Hostname, base.prep.CertificatePlan = hostname, &plan
			approved, err := base.GetPublisherService(t.Context(), cfg.ServiceID, "")
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := newManagedPrepared(base.prep, approved, cfg)
			if err != nil {
				t.Fatal(err)
			}
			cache, err := cfg.State.CertificatesForPublisher(base.prep.TeamId, cfg.PublisherIdentityID, plan)
			if err != nil {
				t.Fatal(err)
			}
			control := &certificateRecoveryControl{lifecycleControl: base, store: cfg.State}
			submitted := false
			control.create = func(der []byte, _ string) (controlv1.ServiceCertificateIssuance, error) {
				csr, err := x509.ParseCertificateRequest(der)
				if err != nil {
					return controlv1.ServiceCertificateIssuance{}, err
				}
				got, want := slices.Clone(csr.DNSNames), slices.Clone(plan.Identifiers)
				slices.Sort(got)
				slices.Sort(want)
				if !slices.Equal(got, want) {
					t.Error("CSR replaced the authoritative namespace plan with the visitor hostname", got, want)
				}
				submitted = true
				return certificateFixtureIssuance(base, der, nil)
			}
			certificates := Certificates{Control: control, Cache: cache, ServiceID: base.prep.ServiceId,
				RunID: base.prep.ServiceRunId, RunNumber: base.prep.RunNumber, PublisherIdentityID: cfg.PublisherIdentityID,
				Token: credentials.ServiceRunToken(base.setup.RunToken), Hostname: hostname, Plan: plan, Install: prepared.installManagedCertificate}
			material, err := certificates.advance(t.Context(), true)
			if err != nil || !submitted || base.installs != 1 {
				t.Fatal("namespace issuance did not acknowledge the consuming run", submitted, base.installs, err)
			}
			if err := certificates.Install(material.Certificate); err != nil {
				t.Fatal("approved namespace certificate did not cover its serving hostname", err)
			}
			if serving, err := prepared.currentCertificate(); err != nil || !bytes.Equal(serving.Certificate[0], material.Certificate.Certificate[0]) {
				t.Fatal("namespace certificate was not selected by its serving owner", err)
			}
			for _, outside := range []string{"deep.app.member.example", "other.example"} {
				changed := base.prep
				changed.Hostname = outside
				other := approved
				endpoint := *other.Endpoint
				endpoint.Hostname = outside
				other.Endpoint = &endpoint
				if _, err := newManagedPrepared(changed, other, cfg); !errors.Is(err, ErrPrivateStream) {
					t.Error("namespace plan authorized an uncovered service hostname", outside, err)
				}
			}
		})
	}
}
