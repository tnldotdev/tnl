package publisher

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestAutomaticRouteAcceptsNamespaceCertificate(t *testing.T) {
	control := newCertificateTestControl(t, "member.example", namespaceCertificateTestPlan())
	key := control.signer.PrivateKey
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: control.setup.CertificatePlan.Identifiers}, key)
	if err != nil {
		t.Fatal(err)
	}
	issuance, err := control.issue(csr)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair([]byte(*issuance.CertificatePem), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	for _, hostname := range []string{"member.example", "app.member.example"} {
		t.Run(hostname, func(t *testing.T) {
			route := certificateTestPublicURL(t, hostname, control.setup.CertificatePlan)
			if err := route.InstallCertificate(certificate); err != nil {
				t.Fatalf("authorized namespace certificate rejected: %v", err)
			}
			selected, err := route.getCertificate(&tls.ClientHelloInfo{ServerName: hostname})
			if err != nil || !bytes.Equal(selected.Certificate[0], certificate.Certificate[0]) {
				t.Fatalf("namespace certificate selection = %v", err)
			}
			if _, err := route.getCertificate(&tls.ClientHelloInfo{ServerName: "other.member.example"}); err == nil {
				t.Fatal("wildcard certificate allowed SNI for a different route")
			}
		})
	}
	t.Run("uncovered_depth", func(t *testing.T) {
		route, err := NewPublicURLServer(PublicURLServerConfig{Hostname: "deep.app.member.example", Target: "http://127.0.0.1:3000", Certificate: certificate, CertificatePlan: control.setup.CertificatePlan})
		if err == nil {
			_ = route.Close()
			t.Fatal("namespace wildcard certificate covered a deeper hostname")
		}
	})
}

func TestCertificateIssuanceNamespaceCoverage(t *testing.T) {
	control := newCertificateTestControl(t, "member.example", namespaceCertificateTestPlan())
	issuance := controlv1.CertificateIssuance{Id: "issuance_1", PublicUrlId: control.setup.PublicUrl.Id, PublishRunId: control.setup.PublishRun.Id,
		PublishRunNumber: 1, CertificatePlan: control.setup.CertificatePlan, State: controlv1.CertificateIssuanceStatePending}
	for _, test := range []struct {
		hostname string
		valid    bool
	}{
		{"member.example", true}, {"app.member.example", true}, {"deep.app.member.example", false}, {"other.example", false},
	} {
		t.Run(test.hostname, func(t *testing.T) {
			err := validateCertificateIssuance(issuance, issuance.PublishRunId, issuance.PublicUrlId, 1, test.hostname, issuance.Id, control.setup.CertificatePlan)
			if (err == nil) != test.valid {
				t.Fatalf("namespace issuance for %s: %v; want accepted = %t", test.hostname, err, test.valid)
			}
		})
	}
}

func TestCertificateIssuanceRejectsInconsistentIdentityAndState(t *testing.T) {
	control := newCertificateTestControl(t, "member.example", namespaceCertificateTestPlan())
	for _, test := range []struct {
		name   string
		change func(*controlv1.CertificateIssuance)
	}{
		{"session", func(i *controlv1.CertificateIssuance) { i.PublishRunId = "session_other" }},
		{"route", func(i *controlv1.CertificateIssuance) { i.PublicUrlId = "public_url_other" }},
		{"version", func(i *controlv1.CertificateIssuance) { i.PublishRunNumber++ }},
		{"issuance", func(i *controlv1.CertificateIssuance) { i.Id = "issuance_other" }},
		{"empty_issuance", func(i *controlv1.CertificateIssuance) { i.Id = "" }},
		{"plan_key", func(i *controlv1.CertificateIssuance) { i.CertificatePlan.CacheKey = "another-key" }},
		{"plan_scope", func(i *controlv1.CertificateIssuance) { i.CertificatePlan.Scope = "another-scope" }},
		{"plan_identifiers", func(i *controlv1.CertificateIssuance) { i.CertificatePlan.Identifiers = []string{"member.example"} }},
		{"plan_method", func(i *controlv1.CertificateIssuance) { i.CertificatePlan.ChallengeMethod = controlv1.TlsAlpn01 }},
		{"unknown_state", func(i *controlv1.CertificateIssuance) { i.State = "unknown" }},
		{"installed_without_material", func(i *controlv1.CertificateIssuance) { i.State = controlv1.CertificateIssuanceStateInstalled }},
		{"pending_with_material", func(i *controlv1.CertificateIssuance) { i.CertificatePem = pointer("invalid") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			i := controlv1.CertificateIssuance{Id: "issuance_1", PublicUrlId: control.setup.PublicUrl.Id, PublishRunId: control.setup.PublishRun.Id,
				PublishRunNumber: 1, CertificatePlan: control.setup.CertificatePlan, State: controlv1.CertificateIssuanceStatePending}
			test.change(&i)
			if err := validateCertificateIssuance(i, control.setup.PublishRun.Id, control.setup.PublicUrl.Id, 1, "member.example", "issuance_1", control.setup.CertificatePlan); err == nil {
				t.Fatal("inconsistent issuance was accepted")
			}
		})
	}
}

func TestCertificateTransactionRejectsInvalidMaterialBeforeCommit(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*controlv1.CertificateIssuance, *x509.Certificate)
	}{
		{"extra_SAN", func(_ *controlv1.CertificateIssuance, leaf *x509.Certificate) {
			leaf.DNSNames = append(leaf.DNSNames, "other.example")
		}},
		{"CA", func(_ *controlv1.CertificateIssuance, leaf *x509.Certificate) {
			leaf.IsCA, leaf.BasicConstraintsValid = true, true
		}},
		{"wrong_EKU", func(_ *controlv1.CertificateIssuance, leaf *x509.Certificate) {
			leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}},
		{"expired", func(_ *controlv1.CertificateIssuance, leaf *x509.Certificate) {
			leaf.NotAfter = time.Now().Add(-time.Second)
		}},
		{"future", func(_ *controlv1.CertificateIssuance, leaf *x509.Certificate) {
			leaf.NotBefore = time.Now().Add(time.Hour)
		}},
		{"invalid_PEM", func(i *controlv1.CertificateIssuance, _ *x509.Certificate) {
			i.CertificatePem = pointer("not a certificate")
		}},
		{"key_mismatch", func(i *controlv1.CertificateIssuance, _ *x509.Certificate) {
			certificate := publicURLTestCertificate(t, "route.example")
			i.CertificatePem = pointer(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]})))
		}},
		{"validity_metadata", func(i *controlv1.CertificateIssuance, _ *x509.Certificate) {
			i.NotBefore = pointer(i.NotBefore.Add(time.Second))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			control, route, state := newCertificateTransactionTest(t)
			control.change = test.change
			acks := 0
			control.installed = func(string, uint64, string, time.Time) error { acks++; return nil }
			if _, err := attemptCertificateTransaction(t.Context(), control, route, state, control.setup, false); err == nil {
				t.Error("invalid certificate material was accepted")
			}
			if _, found, err := state.Current(t.Context(), "route.example"); err != nil || found {
				t.Errorf("invalid issuance changed durable current material: found=%t error=%v", found, err)
			}
			if acks != 0 {
				t.Errorf("invalid issuance installation acknowledgements = %d", acks)
			}
			if _, err := route.getCertificate(&tls.ClientHelloInfo{ServerName: "route.example"}); err == nil {
				t.Error("invalid issuance became available to visitors")
			}
		})
	}
}
