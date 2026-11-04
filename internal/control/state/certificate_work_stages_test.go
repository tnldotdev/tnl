package state

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/security/certificateidentity"
)

func TestCertificateWorkIssuedPayload(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	notBefore, notAfter, renewAt := now.Add(-time.Hour), now.Add(time.Hour), now.Add(time.Minute)
	for _, name := range []string{"valid", "missing_pem", "missing_not_before", "missing_not_after", "missing_renewal", "zero_date", "early_renewal", "late_renewal"} {
		t.Run(name, func(t *testing.T) {
			work := ACMEOrderWork{
				ID: "order", Subject: CertificateSubject{Kind: CertificateSubjectPublicURL, ID: "url", RunID: "run", RunNumber: 1},
				State: ACMEOrderWaitingForInstall, CertificatePEM: []byte("issued"), NotBefore: &notBefore, NotAfter: &notAfter, RenewAt: &renewAt,
				WorkerID: "worker", OrderRevision: 1, WorkEpoch: 1, WorkExpiresAt: now.Add(time.Minute), AvailableAt: now, ChallengeMethod: "dns-01",
			}
			switch name {
			case "missing_pem":
				work.CertificatePEM = nil
			case "missing_not_before":
				work.NotBefore = nil
			case "missing_not_after":
				work.NotAfter = nil
			case "missing_renewal":
				work.RenewAt = nil
			case "zero_date":
				work.NotBefore = new(time.Time)
			case "early_renewal":
				work.RenewAt = &notBefore
			case "late_renewal":
				work.RenewAt = &notAfter
			}
			certificate, err := work.IssuedCertificate()
			relay := RelayCertificateOrderWork{State: RelayCertificateCleaning, CertificatePEM: work.CertificatePEM, NotBefore: work.NotBefore, NotAfter: work.NotAfter, RenewAt: work.RenewAt}
			_, relayErr := relay.IssuedCertificate()
			if name != "valid" {
				if !errors.Is(err, ErrCertificateIssuanceInvalid) || !errors.Is(relayErr, ErrRelayCertificateWorkInvalid) ||
					!errors.Is(validateACMEOrderWork(work), ErrCertificateIssuanceInvalid) {
					t.Fatalf("incomplete issued stage accepted: public=%v relay=%v", err, relayErr)
				}
				return
			}
			if err != nil || relayErr != nil || validateACMEOrderWork(work) != nil || !certificate.RenewAt.Equal(renewAt) {
				t.Fatalf("issued stage: public=%v relay=%v certificate=%+v", err, relayErr, certificate)
			}
		})
	}
}

func TestCertificateWorkFinalizationPayload(t *testing.T) {
	for _, name := range []string{"valid", "wrong_stage", "missing_order", "missing_finalize", "missing_csr"} {
		t.Run(name, func(t *testing.T) {
			work := ACMEOrderWork{State: ACMEOrderReadyToFinalize, OrderURL: "https://acme.example/order", FinalizeURL: "https://acme.example/finalize", CSRDER: []byte("csr")}
			switch name {
			case "wrong_stage":
				work.State = ACMEOrderAuthorizing
			case "missing_order":
				work.OrderURL = ""
			case "missing_finalize":
				work.FinalizeURL = ""
			case "missing_csr":
				work.CSRDER = nil
			}
			finalization, err := work.Finalization()
			relay := RelayCertificateOrderWork{State: RelayCertificateOrderState(work.State), OrderURL: work.OrderURL, FinalizeURL: work.FinalizeURL, CSRDER: work.CSRDER}
			_, relayErr := relay.Finalization()
			if name == "valid" {
				if err != nil || relayErr != nil || finalization.OrderURL != work.OrderURL || finalization.FinalizeURL != work.FinalizeURL || !reflect.DeepEqual(finalization.CSRDER, work.CSRDER) {
					t.Fatal("finalization lost required request material", err, relayErr)
				}
			} else if !errors.Is(err, ErrCertificateIssuanceInvalid) || !errors.Is(relayErr, ErrRelayCertificateWorkInvalid) {
				t.Fatal("invalid finalization accepted", err, relayErr)
			}
		})
	}
}

func TestCertificateWorkChallengePayload(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	expires := now.Add(time.Hour)
	for _, name := range []string{"valid", "missing_authorization", "missing_challenge", "missing_token", "missing_digest", "missing_reference", "missing_expiry", "zero_expiry"} {
		t.Run(name, func(t *testing.T) {
			work := ACMEAuthorizationWork{
				Identifier: "app.example.test", State: ACMEAuthorizationPresented, AvailableAt: now, ChallengeType: "dns-01",
				AuthorizationURL: "https://acme.example/authz", ChallengeURL: "https://acme.example/challenge",
				ChallengeToken: "token", ChallengeDigest: [32]byte{1}, PresentationReference: "presentation", ExpiresAt: &expires,
			}
			switch name {
			case "missing_authorization":
				work.AuthorizationURL = ""
			case "missing_challenge":
				work.ChallengeURL = ""
			case "missing_token":
				work.ChallengeToken = ""
			case "missing_digest":
				work.ChallengeDigest = [32]byte{}
			case "missing_reference":
				work.PresentationReference = ""
			case "missing_expiry":
				work.ExpiresAt = nil
			case "zero_expiry":
				work.ExpiresAt = new(time.Time)
			}
			challenge, err := work.Challenge()
			relay := RelayCertificateOrderWork{
				State: RelayCertificatePresented, AuthorizationURL: work.AuthorizationURL, ChallengeURL: work.ChallengeURL,
				ChallengeToken: work.ChallengeToken, ChallengeDigest: work.ChallengeDigest, PresentationReference: work.PresentationReference, AuthorizationExpiresAt: work.ExpiresAt,
			}
			_, relayErr := relay.Challenge()
			if name == "valid" {
				if err != nil || relayErr != nil || validateACMEAuthorizationWork(work) != nil || !challenge.ExpiresAt.Equal(expires) {
					t.Fatal("valid challenge rejected", err, relayErr)
				}
			} else if !errors.Is(err, ErrCertificateIssuanceInvalid) || !errors.Is(relayErr, ErrRelayCertificateWorkInvalid) || validateACMEAuthorizationWork(work) == nil {
				t.Fatal("incomplete challenge accepted", err, relayErr)
			}
		})
	}
}

func TestCertificateWorkRecordsIssuedTransition(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	const hostname = "relay-a.example.test"
	certificate, keyPEM := testRelayCertificate(t, hostname, now)
	block, _ := pem.Decode(keyPEM)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{hostname}}, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, stage := range []ACMEOrderState{ACMEOrderFinalizing, ACMEOrderFailed, ACMEOrderCanceled} {
		t.Run(string(stage), func(t *testing.T) {
			work := ACMEOrderWork{
				State: stage, FinalizationPossible: true, CSRDER: csr, CertificateIdentifiers: []string{hostname},
				Subject: CertificateSubject{Kind: CertificateSubjectService, ID: "service", RunID: "run", RunNumber: 3}, OrderRevision: 7, WorkEpoch: 11,
			}
			before := work
			if _, err := work.RecordIssuedCertificate([]byte("bad PEM"), now); !errors.Is(err, ErrCertificateIssuanceInvalid) || !reflect.DeepEqual(work, before) {
				t.Fatal("invalid issuance changed work", err)
			}
			issued, err := work.RecordIssuedCertificate(certificate, now)
			if err != nil || work.State != ACMEOrderWaitingForInstall || work.NotAfter == nil || !work.NotAfter.Equal(issued.NotAfter) || work.RenewAt == nil || !work.RenewAt.Equal(issued.RenewAt) ||
				work.Subject != before.Subject || work.OrderRevision != before.OrderRevision || work.WorkEpoch != before.WorkEpoch || work.NeedsFinalizationRecovery() {
				t.Fatal("issuance lost material, lifetime, or binding", err)
			}
			if _, err := work.RecordIssuedCertificate(certificate, now); !errors.Is(err, ErrCertificateIssuanceInvalid) {
				t.Fatal("certificate installation stage accepted another issuance")
			}
		})
	}
	for _, challenge := range []string{"", "https://acme.example/challenge"} {
		work := RelayCertificateOrderWork{State: RelayCertificateFinalizing, TLSServerName: hostname, CSRDER: csr, PrivateKeyPEM: keyPEM, ChallengeURL: challenge}
		if err := work.RecordIssuedCertificate(certificate, now); err != nil {
			t.Fatal(err)
		}
		issued, err := work.IssuedCertificate()
		if err != nil || challenge == "" && (work.State != RelayCertificateComplete || !work.AvailableAt.Equal(issued.RenewAt)) ||
			challenge != "" && (work.State != RelayCertificateCleaning || !work.AvailableAt.Equal(now)) {
			t.Fatal("relay issuance skipped cleanup or lost renewal scheduling", err)
		}
		if err := validateRelayCertificateMaterial(work, now); err != nil {
			t.Fatal("valid relay material cannot be installed", err)
		}
		// cleanup views retain lifetime after expiry; installation still rejects it.
		if _, err := work.IssuedCertificate(); err != nil || validateRelayCertificateMaterial(work, issued.NotAfter) == nil {
			t.Fatal("certificate expiry confused cleanup with installation", err)
		}
		before := work
		if err := work.RecordIssuedCertificate(certificate, now); !errors.Is(err, ErrRelayCertificateWorkInvalid) || !reflect.DeepEqual(work, before) {
			t.Fatal("relay cleanup accepted another issuance", err)
		}
	}
}

func TestCertificateWorkChallengeMethodStorageBoundary(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	expires := now.Add(time.Hour)
	for _, test := range []struct {
		name, method, reference string
		valid                   bool
	}{
		{"dns", "dns-01", "presentation", true},
		{"dns_without_reference", "dns-01", "", false},
		// this baseline is DNS-01 only, including the persisted challenge type.
		{"tls_alpn_without_reference", "tls-alpn-01", "", false},
		{"tls_alpn_with_reference", "tls-alpn-01", "presentation", false},
		{"reused_without_challenge", "", "", true},
		{"reused_with_reference", "", "presentation", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			authorization := ACMEAuthorizationWork{
				ID: "authorization", Identifier: "app.example.test", AuthorizationURL: "https://acme.example/authz",
				State: ACMEAuthorizationPresented, AvailableAt: now, CreatedAt: now, UpdatedAt: now,
				ChallengeType: certificateidentity.ChallengeMethod(test.method), ChallengeURL: "https://acme.example/challenge",
				ChallengeToken: "token", ChallengeDigest: [32]byte{1}, PresentationReference: test.reference, ExpiresAt: &expires,
			}
			if test.method == "" {
				authorization.State = ACMEAuthorizationComplete
				authorization.ChallengeURL, authorization.ChallengeToken, authorization.ChallengeDigest = "", "", [32]byte{}
				authorization.ValidatedAt, authorization.CleanupCompletedAt = &now, &now
			}
			if err := validateACMEAuthorizationWork(authorization); (err == nil) != test.valid {
				t.Fatalf("storage payload validity = %v, want %v", err, test.valid)
			}
			challenge, challengeErr := authorization.Challenge()
			if test.valid && test.method != "" {
				if challengeErr != nil || challenge.Method != certificateidentity.ChallengeDNS01 || challenge.PresentationReference != test.reference {
					t.Fatal("DNS challenge lost its required presentation reference", challengeErr)
				}
			} else if !errors.Is(challengeErr, ErrCertificateIssuanceInvalid) {
				t.Fatal("unsupported or reused authorization fabricated challenge work", challengeErr)
			}
			order := controlstatedb.ControlAcmeOrder{
				ID: "order", PublicURLID: "public-url", PublishRunID: "run", PublishRunNumber: 1,
				OrderRevision: 1, WorkEpoch: 1, Attempts: 1, WorkOwner: text("worker"), WorkExpiresAt: timestamptz(expires),
				AvailableAt: timestamptz(now), CreatedAt: timestamptz(now), UpdatedAt: timestamptz(now),
				CsrDigest: make([]byte, 32), State: "authorizing", ChallengeMethod: "dns-01", CertificateIdentifiers: []string{authorization.Identifier},
			}
			row := controlstatedb.ControlAcmeAuthorization{
				ID: authorization.ID, OrderID: order.ID, Identifier: authorization.Identifier, AuthorizationUrl: authorization.AuthorizationURL,
				State: string(authorization.State), AuthorizationRevision: 1,
				ChallengeType: nullableText(test.method), ChallengeUrl: nullableText(authorization.ChallengeURL), ChallengeToken: nullableText(authorization.ChallengeToken),
				PresentationReference: nullableText(test.reference), ExpiresAt: timestamptz(expires),
				AvailableAt: timestamptz(now), CreatedAt: timestamptz(now), UpdatedAt: timestamptz(now),
				ValidatedAt: nullableTime(authorization.ValidatedAt), CleanupCompletedAt: nullableTime(authorization.CleanupCompletedAt),
			}
			if test.method != "" {
				row.ChallengeDigest = authorization.ChallengeDigest[:]
			}
			loaded, err := acmeOrderWork(order, ACMEAccount{}, []controlstatedb.ControlAcmeAuthorization{row}, true)
			if (err == nil) != test.valid {
				t.Fatalf("stored challenge row validity = %v, want %v", err, test.valid)
			}
			if test.valid && validateACMEOrderWork(loaded) != nil {
				t.Fatal("loaded challenge cannot be saved")
			}
		})
	}
}
