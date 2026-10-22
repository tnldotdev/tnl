package certificates

import (
	"context"
	"errors"
	"testing"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
)

type subjectDNSStub struct {
	subject controlstate.CertificateSubject
	calls   int
}

func (s *subjectDNSStub) PresentSubject(_ context.Context, subject controlstate.CertificateSubject, _ string) error {
	s.subject = subject
	s.calls++
	return nil
}

func (s *subjectDNSStub) VerifySubject(ctx context.Context, subject controlstate.CertificateSubject, id string) (bool, error) {
	return true, s.PresentSubject(ctx, subject, id)
}

func (s *subjectDNSStub) CleanupSubject(ctx context.Context, subject controlstate.CertificateSubject, id string) error {
	return s.PresentSubject(ctx, subject, id)
}

func TestCertificateDNSSubjectBoundary(t *testing.T) {
	for _, kind := range []controlstate.CertificateSubjectKind{controlstate.CertificateSubjectPublicURL, controlstate.CertificateSubjectService} {
		for _, crossed := range []bool{false, true} {
			t.Run(string(kind)+map[bool]string{false: "/current", true: "/crossed"}[crossed], func(t *testing.T) {
				subject := controlstate.CertificateSubject{Kind: kind, ID: "opaque-service", RunID: "opaque-run", RunNumber: 7}
				work := controlstate.ACMEOrderWork{Subject: subject}
				if crossed {
					work.Subject.RunID = ""
				}
				dns := &subjectDNSStub{}
				worker := &PublicURLWorker{config: PublicURLConfig{DNSChallenges: dns}}
				for _, action := range []func() error{
					func() error { return worker.presentSubject(t.Context(), &work, "authorization") },
					func() error { _, err := worker.verifySubject(t.Context(), &work, "authorization"); return err },
					func() error { return worker.cleanupSubject(t.Context(), &work, "authorization") },
				} {
					err := action()
					if crossed && !errors.Is(err, controlstate.ErrCertificateIssuanceInvalid) || !crossed && err != nil {
						t.Fatalf("certificate DNS subject: %v", err)
					}
				}
				if crossed && dns.calls != 0 || !crossed && (dns.calls != 3 || dns.subject != subject) {
					t.Fatal("DNS worker crossed or discarded its certificate subject")
				}
			})
		}
	}
}
