package certificates

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/acmeclient"
	"github.com/tnldotdev/tnl/internal/certificateidentity"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

const defaultFailedRetryInterval = time.Hour

type RelayStore interface {
	PrepareRelayCertificateOrder(context.Context, string, time.Time, time.Duration) (bool, error)
	ClaimRelayCertificateOrderWork(context.Context, string, time.Time, time.Duration) (controlstate.RelayCertificateOrderWork, bool, error)
	SaveRelayCertificateOrderWork(context.Context, controlstate.RelayCertificateOrderWork, time.Time) (controlstate.RelayCertificateOrderWork, error)
}

type RelayDNSChallenges interface {
	Present(context.Context, string) error
	Verify(context.Context, string) (bool, error)
	Cleanup(context.Context, string) error
}

type RelayConfig struct {
	WorkerID            string
	AccountID           string
	Profile             string
	HTTPClient          *http.Client
	DNSChallenges       RelayDNSChallenges
	Logger              *slog.Logger
	Observer            RelayWorkObserver
	LeaseDuration       time.Duration
	OperationTimeout    time.Duration
	PollInterval        time.Duration
	IdleInterval        time.Duration
	FailedRetryInterval time.Duration
}

type RelayWorkObserver interface {
	ObserveCertificateClaim(kind string, outcome observability.CertificateClaimOutcome)
	ObserveCertificateIteration(kind, stage string, outcome observability.CertificateWorkOutcome, elapsed time.Duration)
	ObserveCertificateTransition(kind, state string)
}

type RelayWorker struct {
	store  RelayStore
	config RelayConfig
	now    func() time.Time
	client acmeClientFactory
}

func NewRelayWorker(store RelayStore, config RelayConfig) (*RelayWorker, error) {
	if store == nil || !validText(config.WorkerID) || !validText(config.AccountID) || !validText(config.Profile) ||
		config.HTTPClient == nil || config.DNSChallenges == nil {
		return nil, errors.New("certificates: invalid relay worker configuration")
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	timing := workerTimingWithDefaults(
		config.LeaseDuration, config.OperationTimeout, config.PollInterval, config.IdleInterval,
	)
	config.LeaseDuration, config.OperationTimeout = timing.leaseDuration, timing.operationTimeout
	config.PollInterval, config.IdleInterval = timing.pollInterval, timing.idleInterval
	if config.FailedRetryInterval <= 0 {
		config.FailedRetryInterval = defaultFailedRetryInterval
	}
	if config.OperationTimeout >= config.LeaseDuration {
		return nil, errors.New("certificates: relay worker operation timeout must be shorter than the work lease")
	}
	worker := &RelayWorker{store: store, config: config, now: func() time.Time { return time.Now().UTC() }}
	worker.client = newACMEClientFactory(config.HTTPClient)
	return worker, nil
}

func (w *RelayWorker) Run(ctx context.Context) error {
	return runWorkerLoop(
		ctx, w, w.config.Logger, w.config.OperationTimeout, w.config.IdleInterval,
		"relay certificate worker iteration failed",
	)
}

func (w *RelayWorker) processOne(ctx context.Context) (bool, error) {
	now := w.now()
	if _, err := w.store.PrepareRelayCertificateOrder(
		ctx, w.config.AccountID, now, w.config.FailedRetryInterval,
	); err != nil {
		return false, err
	}
	work, found, err := w.store.ClaimRelayCertificateOrderWork(ctx, w.config.WorkerID, now, w.config.LeaseDuration)
	if w.config.Observer != nil && ctx.Err() == nil {
		outcome := observability.CertificateClaimed
		if err != nil {
			outcome = observability.CertificateError
		} else if !found {
			outcome = observability.CertificateEmpty
		}
		w.config.Observer.ObserveCertificateClaim("relay", outcome)
	}
	if err != nil || !found {
		return found, err
	}
	stage, started := work.State, time.Now()
	client, err := w.client(work.Account)
	if err == nil && work.Account.AccountURL == "" {
		err = errors.New("certificates: relay worker ACME account is not registered")
	}
	if err == nil {
		err = w.advance(ctx, client, &work, now)
	}
	completedAt := w.now()
	if err != nil {
		if ctx.Err() != nil {
			return true, ctx.Err()
		}
		w.applyFailure(&work, err, completedAt)
	}
	if work.State == "complete" {
		// collection or DNS cleanup may outlast certificate expiry. once cleanup
		// finishes, retire unusable material without repeating it.
		if _, _, validationErr := validateRelayCertificate(work.CertificatePEM, work.CSRDER, work.TLSServerName, completedAt); validationErr != nil {
			work.State = "failed"
			work.LastError = truncateError(fmt.Errorf("certificates: relay certificate unusable after cleanup: %w", validationErr))
			work.AvailableAt = completedAt.Add(w.config.FailedRetryInterval)
		}
	}
	saved, saveErr := w.store.SaveRelayCertificateOrderWork(ctx, work, completedAt)
	if saveErr != nil {
		if w.config.Observer != nil && ctx.Err() == nil {
			w.config.Observer.ObserveCertificateIteration("relay", string(stage), "save_failed", time.Since(started))
		}
		return true, saveErr
	}
	if w.config.Observer != nil {
		outcome := observability.CertificateProgress
		if saved.State == "failed" {
			outcome = observability.CertificateTerminal
		} else if err != nil {
			outcome = observability.CertificateRetry
		}
		w.config.Observer.ObserveCertificateIteration("relay", string(stage), outcome, time.Since(started))
		if stage != saved.State {
			switch saved.State {
			case "cleaning":
				w.config.Observer.ObserveCertificateTransition("relay", "available")
			case "complete":
				w.config.Observer.ObserveCertificateTransition("relay", "cleanup_complete")
			case "failed":
				w.config.Observer.ObserveCertificateTransition("relay", "failed")
			}
		}
	}
	return true, nil
}

func (w *RelayWorker) advance(ctx context.Context, client acmeAPI, work *controlstate.RelayCertificateOrderWork, now time.Time) error {
	work.LastError = ""
	if work.State == "authorizing" || work.State == "presenting" || work.State == "presented" || work.State == "validating" {
		// recover orders created before the deadline was persisted without
		// depending on DNS propagation after an upgrade.
		if work.AuthorizationURL != "" && work.AuthorizationExpiresAt == nil {
			authorization, err := client.GetAuthorization(ctx, work.AuthorizationURL)
			if err != nil {
				return err
			}
			if authorization.URL != work.AuthorizationURL || authorization.Identifier.Type != "dns" ||
				authorization.Identifier.Value != work.TLSServerName || authorization.Wildcard {
				return terminalf("ACME authorization identity changed")
			}
			work.AuthorizationExpiresAt = relayAuthorizationExpiry(authorization.Expires, nil, now)
		}
		if work.AuthorizationExpiresAt != nil && !work.AuthorizationExpiresAt.After(now) {
			return terminalf("relay authorization expired")
		}
	}
	switch work.State {
	case "pending":
		order, err := client.NewOrder(ctx, []string{work.TLSServerName}, w.config.Profile)
		if err != nil {
			return err
		}
		return w.applyOrder(work, order, now)
	case "authorizing":
		return w.authorize(ctx, client, work, now)
	case "presenting":
		if err := w.config.DNSChallenges.Present(ctx, work.ID); err != nil {
			return err
		}
		work.State = "presented"
		work.AvailableAt = now.Add(w.config.PollInterval)
		return nil
	case "presented":
		verified, err := w.config.DNSChallenges.Verify(ctx, work.ID)
		if err != nil {
			return err
		}
		if !verified {
			work.AvailableAt = now.Add(w.config.PollInterval)
			return nil
		}
		retryAfter, err := client.AcceptChallenge(ctx, work.ChallengeURL)
		if err != nil {
			return err
		}
		work.State = "validating"
		work.AvailableAt = pollAt(now, w.config.PollInterval, retryAfter)
		return nil
	case "validating":
		return w.validateAuthorization(ctx, client, work, now)
	case "ready_to_finalize":
		return w.finalize(ctx, client, work, now)
	case "finalizing":
		return w.collect(ctx, client, work, now)
	case "cleaning":
		if err := w.config.DNSChallenges.Cleanup(ctx, work.ID); err != nil {
			return err
		}
		work.State = "complete"
		work.AvailableAt = *work.RenewAt
		return nil
	case "failed_cleaning":
		if err := w.config.DNSChallenges.Cleanup(ctx, work.ID); err != nil {
			return err
		}
		work.State = "failed"
		work.AvailableAt = now.Add(w.config.FailedRetryInterval)
		return nil
	default:
		return terminalf("cannot process order in state %q", work.State)
	}
}

func (w *RelayWorker) authorize(ctx context.Context, client acmeAPI, work *controlstate.RelayCertificateOrderWork, now time.Time) error {
	order, err := client.GetOrder(ctx, work.OrderURL)
	if err != nil {
		return err
	}
	if order.Status != "pending" {
		return w.applyOrder(work, order, now)
	}
	if work.AuthorizationURL != "" {
		work.AvailableAt = pollAt(now, w.config.PollInterval, order.RetryAfter)
		return nil
	}
	if len(order.Authorizations) != 1 {
		return terminalf("ACME order has %d authorizations", len(order.Authorizations))
	}
	authorization, err := client.GetAuthorization(ctx, order.Authorizations[0])
	if err != nil {
		return err
	}
	if authorization.URL != order.Authorizations[0] || authorization.Identifier.Type != "dns" ||
		authorization.Identifier.Value != work.TLSServerName || authorization.Wildcard {
		return terminalf("ACME authorization identity does not match the relay service")
	}
	expiresAt := relayAuthorizationExpiry(authorization.Expires, order.Expires, now)
	if !expiresAt.After(now) {
		return terminalf("relay authorization expired")
	}
	work.AuthorizationExpiresAt = expiresAt
	if authorization.Status == "valid" {
		work.AuthorizationURL = authorization.URL
		work.AvailableAt = now.Add(w.config.PollInterval)
		return nil
	}
	if authorization.Status != "pending" {
		return terminalf("ACME authorization is %q", authorization.Status)
	}
	for _, challenge := range authorization.Challenges {
		if challenge.Type != "dns-01" {
			continue
		}
		if challenge.URL == "" || challenge.Token == "" {
			return terminalf("ACME authorization has an incomplete DNS-01 challenge")
		}
		keyAuthorization, err := client.KeyAuthorization(challenge.Token)
		if err != nil {
			return err
		}
		work.AuthorizationURL = authorization.URL
		work.ChallengeURL = challenge.URL
		work.ChallengeToken = challenge.Token
		work.ChallengeDigest = sha256.Sum256([]byte(keyAuthorization))
		work.PresentationReference, err = opaqueid.New(opaqueid.RelayACMEPresentationPrefix)
		if err != nil {
			return err
		}
		work.State = "presenting"
		work.AvailableAt = now
		return nil
	}
	return terminalf("ACME authorization has no DNS-01 challenge")
}

func relayAuthorizationExpiry(authorizationExpires, orderExpires *time.Time, now time.Time) *time.Time {
	if authorizationExpires != nil {
		return authorizationExpires
	}
	if orderExpires != nil {
		return orderExpires
	}
	fallback := now.Add(5 * time.Minute)
	return &fallback
}

func (w *RelayWorker) validateAuthorization(
	ctx context.Context,
	client acmeAPI,
	work *controlstate.RelayCertificateOrderWork,
	now time.Time,
) error {
	authorization, err := client.GetAuthorization(ctx, work.AuthorizationURL)
	if err != nil {
		return err
	}
	if authorization.URL != work.AuthorizationURL || authorization.Identifier.Type != "dns" ||
		authorization.Identifier.Value != work.TLSServerName || authorization.Wildcard {
		return terminalf("ACME authorization identity changed")
	}
	switch authorization.Status {
	case "pending", "processing":
		work.AvailableAt = pollAt(now, w.config.PollInterval, authorization.RetryAfter)
	case "valid":
		work.State = "authorizing"
		work.AvailableAt = now
	case "invalid", "deactivated", "expired", "revoked":
		return terminalf("ACME authorization became %q", authorization.Status)
	default:
		return fmt.Errorf("certificates: unknown relay authorization status %q", authorization.Status)
	}
	return nil
}

func (w *RelayWorker) finalize(ctx context.Context, client acmeAPI, work *controlstate.RelayCertificateOrderWork, now time.Time) error {
	order, err := client.GetOrder(ctx, work.OrderURL)
	if err != nil {
		return err
	}
	if err := validateRelayOrder(order, work.TLSServerName); err != nil {
		return err
	}
	switch order.Status {
	case "pending":
		work.State = "authorizing"
		work.AvailableAt = now
		return nil
	case "ready":
		order, err = client.FinalizeOrder(ctx, work.OrderURL, order.Finalize, work.CSRDER)
		if err != nil {
			return err
		}
		return w.applyOrder(work, order, now)
	case "processing", "valid", "invalid":
		return w.applyOrder(work, order, now)
	default:
		return fmt.Errorf("certificates: unknown relay order status %q", order.Status)
	}
}

func (w *RelayWorker) collect(ctx context.Context, client acmeAPI, work *controlstate.RelayCertificateOrderWork, now time.Time) error {
	order, err := client.GetOrder(ctx, work.OrderURL)
	if err != nil {
		return err
	}
	if err := validateRelayOrder(order, work.TLSServerName); err != nil {
		return err
	}
	switch order.Status {
	case "pending":
		work.State = "authorizing"
		work.AvailableAt = now
	case "ready":
		work.State = "ready_to_finalize"
		work.AvailableAt = now
	case "processing":
		work.AvailableAt = pollAt(now, w.config.PollInterval, order.RetryAfter)
	case "invalid":
		return terminalf("ACME order became invalid")
	case "valid":
		if order.Certificate == "" {
			return terminalf("valid relay order has no certificate URL")
		}
		certificatePEM, err := client.DownloadCertificate(ctx, order.Certificate)
		if err != nil {
			return err
		}
		notBefore, notAfter, err := validateRelayCertificate(certificatePEM, work.CSRDER, work.TLSServerName, now)
		if err != nil {
			return terminalf("issued certificate is invalid: %v", err)
		}
		work.CertificateURL = order.Certificate
		work.CertificatePEM = certificatePEM
		work.NotBefore, work.NotAfter = &notBefore, &notAfter
		renewAt := notBefore.Add(notAfter.Sub(notBefore) * 2 / 3).UTC()
		work.RenewAt = &renewAt
		if work.ChallengeURL == "" {
			work.State = "complete"
			work.AvailableAt = renewAt
		} else {
			work.State = "cleaning"
			work.AvailableAt = now
		}
	default:
		return fmt.Errorf("certificates: unknown relay order status %q", order.Status)
	}
	return nil
}

func (w *RelayWorker) applyOrder(work *controlstate.RelayCertificateOrderWork, order acmeclient.Order, now time.Time) error {
	if err := validateRelayOrder(order, work.TLSServerName); err != nil {
		return err
	}
	if work.State != controlstate.RelayCertificatePending && work.State != controlstate.RelayCertificateAuthorizing && work.State != controlstate.RelayCertificateReadyToFinalize {
		return terminalf("cannot apply ACME order status in state %q", work.State)
	}
	stage, availableAt, err := acmeOrderProgress(order.Status, now, order.RetryAfter, w.config.PollInterval)
	if err != nil {
		return err
	}
	work.OrderURL, work.FinalizeURL, work.CertificateURL = order.URL, order.Finalize, order.Certificate
	work.State, work.AvailableAt = controlstate.RelayCertificateOrderState(stage), availableAt
	return nil
}

func (w *RelayWorker) applyFailure(work *controlstate.RelayCertificateOrderWork, operationErr error, now time.Time) {
	work.LastError = truncateError(operationErr)
	work.AvailableAt = now.Add(5 * time.Second)
	if work.State == "failed_cleaning" {
		return
	}
	var acmeError *acmeclient.Error
	if errors.As(operationErr, &acmeError) && !acmeError.RetryAfter.IsZero() {
		work.AvailableAt = acmeError.RetryAfter
	}
	if isTerminal(operationErr) {
		if work.ChallengeURL != "" {
			work.State = "failed_cleaning"
			work.AvailableAt = now
		} else {
			work.State = "failed"
			work.AvailableAt = now.Add(w.config.FailedRetryInterval)
		}
	}
}

func validateRelayOrder(order acmeclient.Order, hostname string) error {
	if order.URL == "" || order.Status == "" || order.Finalize == "" || len(order.Identifiers) != 1 ||
		order.Identifiers[0].Type != "dns" || order.Identifiers[0].Value != hostname {
		return terminalf("ACME order identity does not match the relay service")
	}
	return nil
}

func validateRelayCertificate(certificatePEM, csrDER []byte, hostname string, now time.Time) (time.Time, time.Time, error) {
	leaf, err := certificateidentity.ValidateIssuedCertificate(certificatePEM, csrDER, []string{hostname}, now)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	if leaf.VerifyHostname(hostname) != nil {
		return time.Time{}, time.Time{}, errors.New("certificate identity is invalid")
	}
	return leaf.NotBefore.UTC(), leaf.NotAfter.UTC(), nil
}

func validText(value string) bool {
	return value != "" && len(value) <= 256 && strings.TrimSpace(value) == value
}
