package state

import (
	"fmt"
	"time"

	"github.com/tnldotdev/tnl/internal/security/certificateidentity"
)

func (work RelayCertificateOrderWork) Finalization() (ACMEFinalization, error) {
	if work.State != RelayCertificateReadyToFinalize {
		return ACMEFinalization{}, ErrRelayCertificateWorkInvalid
	}
	return acmeFinalization(work.OrderURL, work.FinalizeURL, work.CSRDER, ErrRelayCertificateWorkInvalid)
}

func (work RelayCertificateOrderWork) IssuedCertificate() (IssuedCertificate, error) {
	switch work.State {
	case RelayCertificateCleaning, RelayCertificateComplete:
		return issuedCertificate(work.CertificatePEM, work.NotBefore, work.NotAfter, work.RenewAt, ErrRelayCertificateWorkInvalid)
	default:
		return IssuedCertificate{}, ErrRelayCertificateWorkInvalid
	}
}

func (work RelayCertificateOrderWork) Challenge() (ACMEAuthorizationChallenge, error) {
	switch work.State {
	case RelayCertificatePresenting, RelayCertificatePresented, RelayCertificateValidating:
		return acmeAuthorizationChallenge(certificateidentity.ChallengeDNS01, work.AuthorizationURL, work.ChallengeURL, work.ChallengeToken,
			work.ChallengeDigest, work.PresentationReference, work.AuthorizationExpiresAt, ErrRelayCertificateWorkInvalid)
	default:
		return ACMEAuthorizationChallenge{}, ErrRelayCertificateWorkInvalid
	}
}

// RecordIssuedCertificate schedules cleanup before installation. reused
// authorizations have no challenge to clean and can complete immediately.
func (work *RelayCertificateOrderWork) RecordIssuedCertificate(pem []byte, now time.Time) error {
	if work.State != RelayCertificateFinalizing {
		return ErrRelayCertificateWorkInvalid
	}
	leaf, err := certificateidentity.ValidateIssuedCertificate(pem, work.CSRDER, []string{work.TLSServerName}, now)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrRelayCertificateWorkInvalid, err)
	}
	if err := leaf.VerifyHostname(work.TLSServerName); err != nil {
		return fmt.Errorf("%w: %w", ErrRelayCertificateWorkInvalid, err)
	}
	certificate := issuedCertificateFromLeaf(pem, leaf)
	work.CertificatePEM = certificate.PEM
	work.NotBefore, work.NotAfter, work.RenewAt = &certificate.NotBefore, &certificate.NotAfter, &certificate.RenewAt
	work.State, work.AvailableAt = RelayCertificateCleaning, now
	if work.ChallengeURL == "" {
		work.State, work.AvailableAt = RelayCertificateComplete, certificate.RenewAt
	}
	return nil
}
