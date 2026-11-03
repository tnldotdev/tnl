package state

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/tnldotdev/tnl/internal/security/certificateidentity"
)

// these are validated payload views of the persisted work DTOs, not new stored
// models. workers request the payload for an action before making external calls.
type ACMEFinalization struct {
	OrderURL, FinalizeURL string
	CSRDER                []byte
}

type IssuedCertificate struct {
	PEM                          []byte
	NotBefore, NotAfter, RenewAt time.Time
}

type ACMEAuthorizationChallenge struct {
	Method                                                       certificateidentity.ChallengeMethod
	AuthorizationURL, ChallengeURL, Token, PresentationReference string
	Digest                                                       [32]byte
	ExpiresAt                                                    time.Time
}

func (work ACMEOrderWork) Finalization() (ACMEFinalization, error) {
	if work.State != ACMEOrderReadyToFinalize {
		return ACMEFinalization{}, ErrCertificateIssuanceInvalid
	}
	return acmeFinalization(work.OrderURL, work.FinalizeURL, work.CSRDER, ErrCertificateIssuanceInvalid)
}

func acmeFinalization(orderURL, finalizeURL string, csrDER []byte, invalid error) (ACMEFinalization, error) {
	if orderURL == "" || finalizeURL == "" || len(csrDER) == 0 {
		return ACMEFinalization{}, invalid
	}
	return ACMEFinalization{OrderURL: orderURL, FinalizeURL: finalizeURL, CSRDER: csrDER}, nil
}

func (work ACMEOrderWork) IssuedCertificate() (IssuedCertificate, error) {
	switch work.State {
	case ACMEOrderFinalizing, ACMEOrderWaitingForInstall, ACMEOrderInstalled, ACMEOrderFailed, ACMEOrderCanceled:
		return issuedCertificate(work.CertificatePEM, work.NotBefore, work.NotAfter, work.RenewAt, ErrCertificateIssuanceInvalid)
	default:
		return IssuedCertificate{}, ErrCertificateIssuanceInvalid
	}
}

func issuedCertificate(pem []byte, notBefore, notAfter, renewAt *time.Time, invalid error) (IssuedCertificate, error) {
	if len(pem) == 0 || notBefore == nil || notAfter == nil || renewAt == nil ||
		notBefore.IsZero() || notAfter.IsZero() || renewAt.IsZero() ||
		!renewAt.After(*notBefore) || !renewAt.Before(*notAfter) {
		return IssuedCertificate{}, invalid
	}
	// expiry is checked at issuance/installation, not here: DNS cleanup must
	// still finish if the certificate expires while the provider is unavailable.
	return IssuedCertificate{PEM: pem, NotBefore: *notBefore, NotAfter: *notAfter, RenewAt: *renewAt}, nil
}

func issuedCertificateFromLeaf(pem []byte, leaf *x509.Certificate) IssuedCertificate {
	notBefore, notAfter := leaf.NotBefore.UTC(), leaf.NotAfter.UTC()
	return IssuedCertificate{
		PEM: pem, NotBefore: notBefore, NotAfter: notAfter,
		RenewAt: notBefore.Add(notAfter.Sub(notBefore) * 2 / 3).UTC(),
	}
}

// RecordIssuedCertificate retains the actual CA lifetime even when this is
// recovery of a failed/canceled finalization. installation remains separate.
func (work *ACMEOrderWork) RecordIssuedCertificate(pem []byte, now time.Time) (IssuedCertificate, error) {
	if work.State != ACMEOrderFinalizing && !work.NeedsFinalizationRecovery() {
		return IssuedCertificate{}, ErrCertificateIssuanceInvalid
	}
	leaf, err := certificateidentity.ValidateIssuedCertificate(pem, work.CSRDER, work.CertificateIdentifiers, now)
	if err != nil {
		return IssuedCertificate{}, fmt.Errorf("%w: %w", ErrCertificateIssuanceInvalid, err)
	}
	certificate := issuedCertificateFromLeaf(pem, leaf)
	work.CertificatePEM = certificate.PEM
	work.NotBefore, work.NotAfter, work.RenewAt = &certificate.NotBefore, &certificate.NotAfter, &certificate.RenewAt
	work.State, work.AvailableAt = ACMEOrderWaitingForInstall, now
	return certificate, nil
}

func (authorization ACMEAuthorizationWork) Challenge() (ACMEAuthorizationChallenge, error) {
	if !authorization.State.valid() {
		return ACMEAuthorizationChallenge{}, ErrCertificateIssuanceInvalid
	}
	return acmeAuthorizationChallenge(authorization.ChallengeType, authorization.AuthorizationURL, authorization.ChallengeURL,
		authorization.ChallengeToken, authorization.ChallengeDigest, authorization.PresentationReference,
		authorization.ExpiresAt, ErrCertificateIssuanceInvalid)
}

func acmeAuthorizationChallenge(method certificateidentity.ChallengeMethod, authorizationURL, challengeURL, token string, digest [32]byte, reference string, expiresAt *time.Time, invalid error) (ACMEAuthorizationChallenge, error) {
	if !method.Valid() || !validStateText(authorizationURL) || !validStateText(challengeURL) || !validStateText(token) ||
		digest == ([32]byte{}) || expiresAt == nil || expiresAt.IsZero() ||
		method == certificateidentity.ChallengeDNS01 && !validStateText(reference) ||
		method != certificateidentity.ChallengeDNS01 && reference != "" {
		return ACMEAuthorizationChallenge{}, invalid
	}
	return ACMEAuthorizationChallenge{
		Method: method, AuthorizationURL: authorizationURL, ChallengeURL: challengeURL, Token: token,
		Digest: digest, PresentationReference: reference, ExpiresAt: *expiresAt,
	}, nil
}

// NeedsFinalizationRecovery deliberately does not classify failed/canceled as
// terminal: the CA may have issued after a lost finalize reply.
func (work ACMEOrderWork) NeedsFinalizationRecovery() bool {
	return (work.State == ACMEOrderFailed || work.State == ACMEOrderCanceled) && work.FinalizationPossible && work.NotAfter == nil
}
