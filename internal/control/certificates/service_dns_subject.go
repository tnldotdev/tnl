package certificates

import (
	"context"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
)

func (w *ServiceWorker) presentSubject(ctx context.Context, work *controlstate.ACMEOrderWork, authorizationID string) error {
	if work.Subject.Kind != controlstate.CertificateSubjectService || !work.Subject.Valid() {
		return controlstate.ErrCertificateIssuanceInvalid
	}
	return w.config.DNSChallenges.PresentSubject(ctx, work.Subject, authorizationID)
}

func (w *ServiceWorker) verifySubject(ctx context.Context, work *controlstate.ACMEOrderWork, authorizationID string) (bool, error) {
	if work.Subject.Kind != controlstate.CertificateSubjectService || !work.Subject.Valid() {
		return false, controlstate.ErrCertificateIssuanceInvalid
	}
	return w.config.DNSChallenges.VerifySubject(ctx, work.Subject, authorizationID)
}

func (w *ServiceWorker) cleanupSubject(ctx context.Context, work *controlstate.ACMEOrderWork, authorizationID string) error {
	if work.Subject.Kind != controlstate.CertificateSubjectService || !work.Subject.Valid() {
		return controlstate.ErrCertificateIssuanceInvalid
	}
	return w.config.DNSChallenges.CleanupSubject(ctx, work.Subject, authorizationID)
}
