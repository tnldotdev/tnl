package certificates

import (
	"context"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
)

func (w *PublicURLWorker) presentSubject(ctx context.Context, work *controlstate.ACMEOrderWork, authorizationID string) error {
	if !work.Subject.Valid() {
		return controlstate.ErrCertificateIssuanceInvalid
	}
	return w.config.DNSChallenges.PresentSubject(ctx, work.Subject, authorizationID)
}

func (w *PublicURLWorker) verifySubject(ctx context.Context, work *controlstate.ACMEOrderWork, authorizationID string) (bool, error) {
	if !work.Subject.Valid() {
		return false, controlstate.ErrCertificateIssuanceInvalid
	}
	return w.config.DNSChallenges.VerifySubject(ctx, work.Subject, authorizationID)
}

func (w *PublicURLWorker) cleanupSubject(ctx context.Context, work *controlstate.ACMEOrderWork, authorizationID string) error {
	if !work.Subject.Valid() {
		return controlstate.ErrCertificateIssuanceInvalid
	}
	return w.config.DNSChallenges.CleanupSubject(ctx, work.Subject, authorizationID)
}
