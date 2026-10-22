package certificates

import (
	"context"

	"github.com/tnldotdev/tnl/internal/controlstate"
)

type subjectDNSChallenges interface {
	PresentSubject(context.Context, controlstate.CertificateSubject, string) error
	VerifySubject(context.Context, controlstate.CertificateSubject, string) (bool, error)
	CleanupSubject(context.Context, controlstate.CertificateSubject, string) error
}

// claimed work carries a checked subject. the legacy interface remains available
// to in-process adapters while the parent integrates the typed DNS boundary.
func (w *PublicURLWorker) dnsSubject(work *controlstate.ACMEOrderWork) (subjectDNSChallenges, controlstate.CertificateSubject, error) {
	if work.Subject == (controlstate.CertificateSubject{}) {
		return nil, controlstate.CertificateSubject{}, nil
	}
	subject, err := work.CertificateSubject()
	if err != nil {
		return nil, subject, err
	}
	manager, _ := w.config.DNSChallenges.(subjectDNSChallenges)
	return manager, subject, nil
}

func (w *PublicURLWorker) presentSubject(ctx context.Context, work *controlstate.ACMEOrderWork, authorizationID string) error {
	manager, subject, err := w.dnsSubject(work)
	if err != nil {
		return err
	}
	if manager != nil {
		return manager.PresentSubject(ctx, subject, authorizationID)
	}
	return w.config.DNSChallenges.Present(ctx, work.ServiceID(), authorizationID)
}

func (w *PublicURLWorker) verifySubject(ctx context.Context, work *controlstate.ACMEOrderWork, authorizationID string) (bool, error) {
	manager, subject, err := w.dnsSubject(work)
	if err != nil {
		return false, err
	}
	if manager != nil {
		return manager.VerifySubject(ctx, subject, authorizationID)
	}
	return w.config.DNSChallenges.Verify(ctx, work.ServiceID(), authorizationID)
}

func (w *PublicURLWorker) cleanupSubject(ctx context.Context, work *controlstate.ACMEOrderWork, authorizationID string) error {
	manager, subject, err := w.dnsSubject(work)
	if err != nil {
		return err
	}
	if manager != nil {
		return manager.CleanupSubject(ctx, subject, authorizationID)
	}
	return w.config.DNSChallenges.Cleanup(ctx, work.ServiceID(), authorizationID)
}
