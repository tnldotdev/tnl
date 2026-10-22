package publisher

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	controlclient "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/security/certificateidentity"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

var (
	errCertificateExpired = errors.New("publisher: application certificate expired")
	renewalRetry          = time.Minute
)

func logRenewalFailure(logf func(string, ...any), err error) {
	if logf != nil {
		logf("certificate renewal failed; retrying while the current certificate remains valid: %v", err)
	}
}

func issueInitialCertificate(
	ctx context.Context,
	authority publicRunAuthority,
	route *PublicURLServer,
	state *clientstate.CertificateCache,
) (clientstate.Material, error) {
	hostname := authority.identity.Hostname
	current, found, err := state.Current(ctx, hostname)
	if err != nil && !errors.Is(err, clientstate.ErrCertificateExpired) {
		return clientstate.Material{}, err
	}
	if err == nil && found {
		if err := installCertificateMaterial(ctx, authority, route, state, current, false); err != nil {
			return clientstate.Material{}, err
		}
		return current, nil
	}
	lock, err := state.Lock(ctx)
	if err != nil {
		return clientstate.Material{}, err
	}
	defer lock.Close()
	var material clientstate.Material
	retriedTerminal := false
	for {
		attempted, err := attemptCertificateTransaction(
			ctx, authority, route, state, false,
		)
		if attempted.Certificate.Leaf != nil {
			material = attempted
		}
		if err == nil {
			return attempted, nil
		}
		if ctx.Err() != nil {
			return material, context.Cause(ctx)
		}
		var terminal *terminalCertificateIssuanceError
		if errors.As(err, &terminal) && !retriedTerminal {
			retriedTerminal = true
		} else if !errors.Is(err, controlclient.ErrUnavailable) && !errors.Is(err, controlclient.ErrRateLimited) {
			return material, err
		}
		if err := waitCertificateRetry(ctx, certificateRetryDelay(err)); err != nil {
			return material, err
		}
	}
}

// attemptCertificateTransaction advances every issuance phase at most once.
// retrying this entire function is safe because the pending slot preserves
// the CSR until it has saved the server's installation acknowledgement.
// the caller holds the cache lock while issuing or retrying the certificate.
func attemptCertificateTransaction(
	ctx context.Context,
	authority publicRunAuthority,
	route *PublicURLServer,
	state *clientstate.CertificateCache,
	renew bool,
) (_ clientstate.Material, result error) {
	ctx, finish := observability.PublisherOperation(ctx, "certificate")
	defer func() { finish(result) }()
	publishRunID, publicURLID, hostname := authority.identity.PublishRunID, authority.identity.PublicURLID, authority.identity.Hostname
	version := authority.identity.Number
	staged, found, err := state.Staged(ctx, hostname)
	if errors.Is(err, clientstate.ErrCertificateExpired) {
		if _, err := state.NewPending(ctx, hostname); err != nil {
			return clientstate.Material{}, err
		}
	} else if err != nil {
		return clientstate.Material{}, err
	} else if found {
		if err := installCertificateMaterial(ctx, authority, route, state, staged, true); err != nil {
			return clientstate.Material{}, err
		}
		return staged, nil
	}
	current, found, err := state.Current(ctx, hostname)
	if err != nil && !errors.Is(err, clientstate.ErrCertificateExpired) {
		return clientstate.Material{}, err
	}
	if err == nil && found && (!renew || time.Now().Before(current.RenewAt)) {
		if err := installCertificateMaterial(ctx, authority, route, state, current, false); err != nil {
			return clientstate.Material{}, err
		}
		return current, nil
	}
	pending, err := state.Pending(ctx, hostname)
	if err != nil {
		return clientstate.Material{}, err
	}
	idempotencyKey := certificateIdempotencyKey(pending.CSRDER)
	issuance, err := authority.createCertificate(ctx, pending.CSRDER, idempotencyKey)
	if err != nil {
		return clientstate.Material{}, err
	}
	if err := validateCertificateAttempt(
		ctx, state, issuance, publishRunID, publicURLID, version, hostname, authority.plan,
	); err != nil {
		return clientstate.Material{}, err
	}
	if issuance.CertificatePem == nil {
		return clientstate.Material{}, &pendingCertificateIssuanceError{retryAt: issuance.RetryAt}
	}
	block, _ := pem.Decode([]byte(*issuance.CertificatePem))
	if block == nil || block.Type != "CERTIFICATE" {
		return clientstate.Material{}, errors.New("publisher: server returned invalid certificate material")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !leaf.NotBefore.Equal(*issuance.NotBefore) || !leaf.NotAfter.Equal(*issuance.NotAfter) {
		return clientstate.Material{}, errors.New("publisher: server certificate validity does not match certificate material")
	}
	renewAt := certificateRenewAt(*issuance.NotBefore, *issuance.NotAfter)
	material, err := state.Stage(ctx, hostname, pending, []byte(*issuance.CertificatePem), renewAt, issuance.Id)
	if err != nil {
		return material, err
	}
	if err := installCertificateMaterial(ctx, authority, route, state, material, true); err != nil {
		return clientstate.Material{}, err
	}
	return material, nil
}

func installCertificateMaterial(
	ctx context.Context,
	authority publicRunAuthority,
	route *PublicURLServer,
	state *clientstate.CertificateCache,
	material clientstate.Material,
	staged bool,
) error {
	// a shared cache entry never authorizes this publish run to serve it.
	if err := authority.certificateInstalled(
		ctx, material.IssuanceID, material.Certificate.Leaf.NotAfter,
	); err != nil {
		return err
	}
	if staged {
		if err := state.Promote(ctx, authority.identity.Hostname, material.IssuanceID); err != nil {
			return err
		}
	}
	return route.InstallCertificate(material.Certificate)
}

func validateCertificateAttempt(
	ctx context.Context,
	state *clientstate.CertificateCache,
	issuance controlv1.CertificateIssuance,
	publishRunID, publicURLID string,
	version uint64,
	hostname string,
	plan controlv1.CertificatePlan,
) error {
	err := validateCertificateIssuance(issuance, publishRunID, publicURLID, version, hostname, "", plan)
	var terminal *terminalCertificateIssuanceError
	if !errors.As(err, &terminal) {
		return err
	}
	if _, rotateErr := state.NewPending(ctx, hostname); rotateErr != nil {
		return rotateErr
	}
	return err
}

func validateCertificateIssuance(
	issuance controlv1.CertificateIssuance,
	publishRunID, publicURLID string,
	version uint64,
	hostname string,
	expectedID string,
	plan controlv1.CertificatePlan,
) error {
	if issuance.Id == "" || issuance.PublishRunId != publishRunID || issuance.PublicUrlId != publicURLID ||
		issuance.PublishRunNumber != int64(version) || expectedID != "" && issuance.Id != expectedID ||
		!certificateidentity.SamePlan(issuance.CertificatePlan, plan) || !certificateidentity.Covers(plan.Identifiers, hostname) {
		return errors.New("publisher: server returned a certificate issuance for a different publish run")
	}
	if !issuance.State.Valid() {
		return errors.New("publisher: server returned an unknown certificate issuance state")
	}
	if err := certificateIssuanceStateError(issuance.State); err != nil {
		return err
	}
	if issuance.CertificatePem != nil {
		if issuance.State != controlv1.CertificateIssuanceStateWaitingForInstall && issuance.State != controlv1.CertificateIssuanceStateInstalled ||
			issuance.NotBefore == nil || issuance.NotAfter == nil {
			return errors.New("publisher: server returned certificate material in an inconsistent issuance state")
		}
	} else if issuance.State == controlv1.CertificateIssuanceStateWaitingForInstall || issuance.State == controlv1.CertificateIssuanceStateInstalled {
		return errors.New("publisher: server returned an installed issuance without certificate material")
	}
	return nil
}

func certificateIssuanceStateError(state controlv1.CertificateIssuanceState) error {
	if state == controlv1.CertificateIssuanceStateFailed || state == controlv1.CertificateIssuanceStateCanceled {
		return &terminalCertificateIssuanceError{state: state}
	}
	return nil
}

func certificateRenewAt(notBefore, notAfter time.Time) time.Time {
	return notBefore.Add(notAfter.Sub(notBefore) * 2 / 3).UTC()
}

func certificateIdempotencyKey(csrDER []byte) string {
	digest := sha256.Sum256(csrDER)
	return "certificate_" + base64.RawURLEncoding.EncodeToString(digest[:])
}

type terminalCertificateIssuanceError struct {
	state controlv1.CertificateIssuanceState
}

func (e *terminalCertificateIssuanceError) Error() string {
	return fmt.Sprintf("publisher: certificate issuance became %s", e.state)
}

type pendingCertificateIssuanceError struct {
	retryAt *time.Time
}

func (*pendingCertificateIssuanceError) Error() string {
	return "publisher: certificate issuance is pending"
}

func (*pendingCertificateIssuanceError) Unwrap() error { return controlclient.ErrUnavailable }

func certificatePendingRetryDelay(err error) (time.Duration, bool) {
	var pending *pendingCertificateIssuanceError
	if !errors.As(err, &pending) {
		return 0, false
	}
	if pending.retryAt != nil && pending.retryAt.After(time.Now()) {
		return time.Until(*pending.retryAt), true
	}
	return activationRetry, true
}

func waitCertificateRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-timer.C:
		return nil
	}
}

func certificateRetryDelay(err error) time.Duration {
	if delay, ok := certificatePendingRetryDelay(err); ok {
		return delay
	}
	var limited *controlclient.RateLimitError
	if errors.As(err, &limited) && limited.RetryAfter > 0 {
		return limited.RetryAfter
	}
	return activationRetry
}

func certificateRenewalRetryDelay(err error, notAfter time.Time) time.Duration {
	delay := renewalRetry
	if pendingDelay, ok := certificatePendingRetryDelay(err); ok {
		delay = pendingDelay
	} else {
		var limited *controlclient.RateLimitError
		if errors.As(err, &limited) && limited.RetryAfter > 0 {
			delay = limited.RetryAfter
		}
	}
	return max(min(delay, time.Until(notAfter)), 0)
}
