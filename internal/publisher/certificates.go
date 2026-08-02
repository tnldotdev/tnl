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

	"github.com/tnldotdev/tnl/internal/certificateidentity"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/tlschallenge"
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
	server RouteControlClient,
	route *RouteServer,
	state *clientstate.CertificateCache,
	setup controlv1.RouteSessionSetup,
) (clientstate.Material, error) {
	hostname := setup.Route.CanonicalHostname
	current, found, err := state.Current(ctx, hostname)
	if err != nil && !errors.Is(err, clientstate.ErrCertificateExpired) {
		return clientstate.Material{}, err
	}
	if err == nil && found {
		if err := installCertificateMaterial(ctx, server, route, state, setup, current, false); err != nil {
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
			ctx, server, route, state, setup, false,
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
// Retrying this entire function is safe because the pending slot preserves
// the CSR until it has saved the server's installation acknowledgement.
// The caller holds the cache lock while issuing or retrying the certificate.
func attemptCertificateTransaction(
	ctx context.Context,
	server RouteControlClient,
	route *RouteServer,
	state *clientstate.CertificateCache,
	setup controlv1.RouteSessionSetup,
	renew bool,
) (clientstate.Material, error) {
	routeSessionID, routeID, hostname := setup.RouteSession.Id, setup.Route.Id, setup.Route.CanonicalHostname
	version, routeSessionToken := uint64(setup.RouteSession.RouteVersion), credentials.RouteSessionToken(setup.RouteSessionToken)
	staged, found, err := state.Staged(ctx, hostname)
	if errors.Is(err, clientstate.ErrCertificateExpired) {
		if _, err := state.NewPending(ctx, hostname); err != nil {
			return clientstate.Material{}, err
		}
	} else if err != nil {
		return clientstate.Material{}, err
	} else if found {
		if err := installCertificateMaterial(ctx, server, route, state, setup, staged, true); err != nil {
			return clientstate.Material{}, err
		}
		return staged, nil
	}
	current, found, err := state.Current(ctx, hostname)
	if err != nil && !errors.Is(err, clientstate.ErrCertificateExpired) {
		return clientstate.Material{}, err
	}
	if err == nil && found && (!renew || time.Now().Before(current.RenewAt)) {
		if err := installCertificateMaterial(ctx, server, route, state, setup, current, false); err != nil {
			return clientstate.Material{}, err
		}
		return current, nil
	}
	pending, err := state.Pending(ctx, hostname)
	if err != nil {
		return clientstate.Material{}, err
	}
	idempotencyKey := certificateIdempotencyKey(pending.CSRDER)
	issuance, err := server.CreateCertificateIssuance(ctx, routeSessionID, version, routeSessionToken, pending.CSRDER, idempotencyKey)
	if err != nil {
		return clientstate.Material{}, err
	}
	if err := validateCertificateAttempt(
		ctx, server, route, state, issuance, routeSessionID, routeID, version, routeSessionToken, hostname, route.challengeIssuanceID, setup.CertificatePlan,
	); err != nil {
		return clientstate.Material{}, err
	}
	challenge := tlsALPNChallenge(issuance.Challenges, hostname)
	if issuance.CertificatePem == nil && challenge == nil {
		return clientstate.Material{}, &pendingCertificateIssuanceError{retryAt: issuance.RetryAt}
	}
	if issuance.CertificatePem == nil {
		if !certificateIssuanceStateAllowsChallenge(issuance.State) {
			return clientstate.Material{}, &pendingCertificateIssuanceError{retryAt: issuance.RetryAt}
		}
		installedChallenge, err := certificateChallenge(challenge, hostname)
		if err != nil {
			return clientstate.Material{}, err
		}
		if err := route.InstallChallenge(installedChallenge); err != nil {
			return clientstate.Material{}, err
		}
		route.challengeIssuanceID, route.challengeID = issuance.Id, installedChallenge.ID
		issuanceID := issuance.Id
		issuance, err = server.MarkCertificateChallengeReady(ctx, issuanceID, routeSessionToken)
		if err != nil {
			return clientstate.Material{}, err
		}
		if err := validateCertificateAttempt(
			ctx, server, route, state, issuance, routeSessionID, routeID, version, routeSessionToken,
			hostname, issuanceID, setup.CertificatePlan,
		); err != nil {
			return clientstate.Material{}, err
		}
		if issuance.CertificatePem == nil {
			return clientstate.Material{}, &pendingCertificateIssuanceError{retryAt: issuance.RetryAt}
		}
	}
	if err := removeCertificateChallenge(ctx, server, route, issuance, routeSessionToken, hostname); err != nil {
		return clientstate.Material{}, err
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
	if err := installCertificateMaterial(ctx, server, route, state, setup, material, true); err != nil {
		return clientstate.Material{}, err
	}
	return material, nil
}

func installCertificateMaterial(
	ctx context.Context,
	server RouteControlClient,
	route *RouteServer,
	state *clientstate.CertificateCache,
	setup controlv1.RouteSessionSetup,
	material clientstate.Material,
	staged bool,
) error {
	// A shared cache entry is never permission for this route session to serve it.
	if err := server.MarkRouteSessionCertificateInstalled(
		ctx, setup.RouteSession.Id, uint64(setup.RouteSession.RouteVersion), material.IssuanceID,
		material.Certificate.Leaf.NotAfter, credentials.RouteSessionToken(setup.RouteSessionToken),
	); err != nil {
		return err
	}
	if staged {
		if err := state.Promote(ctx, setup.Route.CanonicalHostname, material.IssuanceID); err != nil {
			return err
		}
	}
	return route.InstallCertificate(material.Certificate)
}

func certificateChallenge(challenge *controlv1.CertificateChallenge, hostname string) (tlschallenge.TLSALPNChallenge, error) {
	digest, err := base64.RawURLEncoding.DecodeString(challenge.Digest)
	if err != nil || len(digest) != 32 || base64.RawURLEncoding.EncodeToString(digest) != challenge.Digest ||
		challenge.Token == "" || challenge.Identifier != hostname || challenge.Method != controlv1.TlsAlpn01 || !challenge.ExpiresAt.After(time.Now()) {
		return tlschallenge.TLSALPNChallenge{}, errors.New("publisher: server returned an invalid TLS-ALPN challenge digest")
	}
	result := tlschallenge.TLSALPNChallenge{
		ID: challenge.Token, Hostname: challenge.Identifier, ExpiresAt: challenge.ExpiresAt,
	}
	copy(result.Digest[:], digest)
	return result, nil
}

func validateCertificateAttempt(
	ctx context.Context,
	server RouteControlClient,
	route *RouteServer,
	state *clientstate.CertificateCache,
	issuance controlv1.CertificateIssuance,
	routeSessionID, routeID string,
	version uint64,
	routeSessionToken credentials.RouteSessionToken,
	hostname, expectedID string,
	plan controlv1.CertificatePlan,
) error {
	err := validateCertificateIssuance(issuance, routeSessionID, routeID, version, hostname, expectedID, plan)
	var terminal *terminalCertificateIssuanceError
	if !errors.As(err, &terminal) {
		return err
	}
	if removeErr := removeCertificateChallenge(ctx, server, route, issuance, routeSessionToken, hostname); removeErr != nil {
		return removeErr
	}
	if _, rotateErr := state.NewPending(ctx, hostname); rotateErr != nil {
		return rotateErr
	}
	return err
}

func removeCertificateChallenge(ctx context.Context, server RouteControlClient, route *RouteServer, issuance controlv1.CertificateIssuance, token credentials.RouteSessionToken, hostname string) error {
	id := ""
	if challenge := tlsALPNChallenge(issuance.Challenges, hostname); challenge != nil {
		id = challenge.Token
	}
	if route.challengeIssuanceID == issuance.Id {
		id = route.challengeID
	}
	if id == "" {
		return nil
	}
	route.RemoveChallenge(id)
	if err := server.MarkCertificateChallengeRemoved(ctx, issuance.Id, token); err != nil {
		return err
	}
	route.challengeIssuanceID, route.challengeID = "", ""
	return nil
}

func validateCertificateIssuance(
	issuance controlv1.CertificateIssuance,
	routeSessionID, routeID string,
	version uint64,
	hostname string,
	expectedID string,
	plan controlv1.CertificatePlan,
) error {
	if issuance.Id == "" || issuance.RouteSessionId != routeSessionID || issuance.RouteId != routeID ||
		issuance.RouteVersion != int64(version) || expectedID != "" && issuance.Id != expectedID ||
		!certificateidentity.SamePlan(issuance.CertificatePlan, plan) || !certificateidentity.Covers(plan.Identifiers, hostname) {
		return errors.New("publisher: server returned a certificate issuance for a different route session")
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
	if issuance.Challenges != nil && len(*issuance.Challenges) != 0 && issuance.CertificatePem == nil {
		if !certificateIssuanceStateAllowsChallenge(issuance.State) {
			return errors.New("publisher: server returned a challenge in an inconsistent issuance state")
		}
	}
	if challenge := tlsALPNChallenge(issuance.Challenges, hostname); challenge != nil {
		digest, err := base64.RawURLEncoding.DecodeString(challenge.Digest)
		if err != nil || len(digest) != 32 || base64.RawURLEncoding.EncodeToString(digest) != challenge.Digest ||
			challenge.Token == "" || challenge.Identifier != hostname || challenge.ExpiresAt.IsZero() {
			return errors.New("publisher: server returned invalid TLS-ALPN challenge material")
		}
	}
	return nil
}

func certificateIssuanceStateError(state controlv1.CertificateIssuanceState) error {
	if state == controlv1.CertificateIssuanceStateFailed || state == controlv1.CertificateIssuanceStateCanceled {
		return &terminalCertificateIssuanceError{state: state}
	}
	return nil
}

func certificateIssuanceStateAllowsChallenge(state controlv1.CertificateIssuanceState) bool {
	switch state {
	case controlv1.CertificateIssuanceStateAuthorizing,
		controlv1.CertificateIssuanceStateReadyToFinalize,
		controlv1.CertificateIssuanceStateFinalizing:
		return true
	default:
		return false
	}
}

func tlsALPNChallenge(challenges *[]controlv1.CertificateChallenge, hostname string) *controlv1.CertificateChallenge {
	if challenges == nil {
		return nil
	}
	for index := range *challenges {
		challenge := &(*challenges)[index]
		if challenge.Method == controlv1.TlsAlpn01 && challenge.Identifier == hostname {
			return challenge
		}
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
