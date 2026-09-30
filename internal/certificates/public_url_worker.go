package certificates

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/acmeclient"
	"github.com/tnldotdev/tnl/internal/certificateidentity"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/dnscontroller"
)

type PublicURLConfig struct {
	WorkerID         string
	Profile          string
	HTTPClient       *http.Client
	Logger           *slog.Logger
	LeaseDuration    time.Duration
	OperationTimeout time.Duration
	PollInterval     time.Duration
	IdleInterval     time.Duration
	DNSChallenges    PublicURLDNSChallenges
	Observer         PublicURLWorkObserver
}

// PublicURLWorkObserver records only fixed worker stages and outcomes.
type PublicURLWorkObserver interface {
	ObserveCertificateWork(stage, outcome string, elapsed time.Duration)
	ObserveCertificateMilestone(milestone string, age time.Duration)
}

type PublicURLDNSChallenges interface {
	Present(context.Context, string, string) error
	Verify(context.Context, string, string) (bool, error)
	Cleanup(context.Context, string, string) error
}

// PublicURLStore is the stored certificate work used by a PublicURLWorker.
type PublicURLStore interface {
	ClaimACMEOrderWork(context.Context, string, time.Time, time.Duration) (controlstate.ACMEOrderWork, bool, error)
	ACMEChallengeRoutingReady(context.Context, string, time.Time) (bool, error)
	SaveACMEOrderWork(context.Context, controlstate.ACMEOrderWork, time.Time) (controlstate.ACMEOrderWork, error)
}

type PublicURLWorker struct {
	store        PublicURLStore
	config       PublicURLConfig
	now          func() time.Time
	client       acmeClientFactory
	clientKey    routeACMEClientKey
	cachedClient acmeAPI
}

type routeACMEClientKey struct {
	directoryURL, accountURL string
	accountKey               [sha256.Size]byte
}

func NewPublicURLWorker(store PublicURLStore, config PublicURLConfig) (*PublicURLWorker, error) {
	if store == nil || strings.TrimSpace(config.WorkerID) != config.WorkerID || config.WorkerID == "" ||
		strings.TrimSpace(config.Profile) != config.Profile || config.Profile == "" || config.HTTPClient == nil {
		return nil, errors.New("certificates: invalid public URL certificate worker configuration")
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	timing := workerTimingWithDefaults(
		config.LeaseDuration, config.OperationTimeout, config.PollInterval, config.IdleInterval,
	)
	config.LeaseDuration, config.OperationTimeout = timing.leaseDuration, timing.operationTimeout
	config.PollInterval, config.IdleInterval = timing.pollInterval, timing.idleInterval
	if config.OperationTimeout >= config.LeaseDuration {
		return nil, errors.New("certificates: public URL certificate worker operation timeout must be shorter than the work lease")
	}
	worker := &PublicURLWorker{store: store, config: config, now: func() time.Time { return time.Now().UTC() }}
	worker.client = newACMEClientFactory(config.HTTPClient)
	return worker, nil
}

func (w *PublicURLWorker) Run(ctx context.Context) error {
	return runWorkerLoop(
		ctx, w, w.config.Logger, w.config.OperationTimeout, w.config.IdleInterval,
		"public URL certificate worker iteration failed",
	)
}

func (w *PublicURLWorker) processOne(ctx context.Context) (bool, error) {
	now := w.now()
	work, found, err := w.store.ClaimACMEOrderWork(ctx, w.config.WorkerID, now, w.config.LeaseDuration)
	if observer, ok := w.config.Observer.(interface{ ObserveCertificateClaim(string, string) }); ok && ctx.Err() == nil {
		outcome := "claimed"
		if err != nil {
			outcome = "error"
		} else if !found {
			outcome = "empty"
		}
		observer.ObserveCertificateClaim("public_url", outcome)
	}
	if err != nil || !found {
		return found, err
	}
	stage := work.State
	hadPendingCleanup := hasPendingDNSCleanup(work.Authorizations)
	started := time.Now()
	client, err := w.clientFor(work.Account)
	if err == nil && work.Account.AccountURL == "" {
		err = errors.New("certificates: public URL certificate worker ACME account is not registered")
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
	saved, saveErr := w.store.SaveACMEOrderWork(ctx, work, completedAt)
	if saveErr != nil {
		if ctx.Err() == nil {
			w.observeWork(string(stage), "save_failed", started)
			w.logWork(work, string(stage), "save_failed", completedAt)
		}
		return true, saveErr
	}
	if w.config.Observer != nil {
		if observer, ok := w.config.Observer.(interface{ ObserveCertificateTransition(string, string) }); ok {
			if stage != saved.State {
				switch saved.State {
				case "waiting_for_install":
					observer.ObserveCertificateTransition("public_url", "available")
				case "failed":
					observer.ObserveCertificateTransition("public_url", "failed")
				}
			}
			if hadPendingCleanup && !hasPendingDNSCleanup(saved.Authorizations) {
				observer.ObserveCertificateTransition("public_url", "cleanup_complete")
			}
		}
		if stage != "waiting_for_install" && saved.State == "waiting_for_install" && len(saved.CertificatePEM) != 0 {
			w.config.Observer.ObserveCertificateMilestone("ready", completedAt.Sub(saved.CreatedAt))
		}
		if hadPendingCleanup && !hasPendingDNSCleanup(saved.Authorizations) &&
			(saved.State == "waiting_for_install" || saved.State == "installed") {
			w.config.Observer.ObserveCertificateMilestone("cleanup", completedAt.Sub(saved.CreatedAt))
		}
	}
	outcome := "progress"
	if work.State == "failed" || work.State == "canceled" {
		outcome = "terminal"
	} else if err != nil {
		outcome = "retry"
	}
	w.observeWork(string(stage), outcome, started)
	if err != nil || work.State != stage && (work.State == "waiting_for_install" || work.State == "failed") && completedAt.Sub(work.CreatedAt) >= 30*time.Second {
		w.logWork(work, string(stage), outcome, completedAt)
	}
	if errors.Is(err, dnscontroller.ErrChallengesNotConfigured) {
		return true, err
	}
	return true, nil
}

func (w *PublicURLWorker) observeWork(stage, outcome string, started time.Time) {
	if w.config.Observer != nil {
		w.config.Observer.ObserveCertificateWork(stage, outcome, time.Since(started))
	}
}

func (w *PublicURLWorker) logWork(work controlstate.ACMEOrderWork, stage, outcome string, now time.Time) {
	if w.config.Logger == nil {
		return
	}
	w.config.Logger.Info("public URL certificate work", "publish_run_id", work.PublishRunID, "publish_run_number", work.PublishRunNumber,
		"issuance_id", work.ID, "stage", stage, "state", work.State, "outcome", outcome,
		"attempts", work.Attempts, "age", now.Sub(work.CreatedAt).Round(time.Second), "next_available_at", work.AvailableAt)
}

func (w *PublicURLWorker) clientFor(account controlstate.ACMEAccount) (acmeAPI, error) {
	key := routeACMEClientKey{
		directoryURL: account.DirectoryURL,
		accountURL:   account.AccountURL,
		accountKey:   sha256.Sum256(account.AccountKeyDER),
	}
	if w.cachedClient != nil && key == w.clientKey {
		return w.cachedClient, nil
	}
	client, err := w.client(account)
	if err != nil {
		return nil, err
	}
	w.clientKey, w.cachedClient = key, client
	return client, nil
}

func (w *PublicURLWorker) advance(ctx context.Context, client acmeAPI, work *controlstate.ACMEOrderWork, now time.Time) error {
	work.LastError = ""
	if w.config.DNSChallenges == nil && (work.ChallengeMethod == "dns-01" ||
		slices.ContainsFunc(work.Authorizations, func(value controlstate.ACMEAuthorizationWork) bool {
			return value.ChallengeType == "dns-01"
		})) {
		return dnscontroller.ErrChallengesNotConfigured
	}
	switch work.State {
	case "pending":
		return w.createOrder(ctx, client, work, now)
	case "authorizing":
		return w.authorizeOrder(ctx, client, work, now)
	case "ready_to_finalize":
		return w.finalizeOrder(ctx, client, work, now)
	case "finalizing":
		return w.collectCertificate(ctx, client, work, now)
	case "waiting_for_install", "installed":
		_, err := w.continueDNSCleanup(ctx, work, now)
		if err == nil && !hasPendingDNSCleanup(work.Authorizations) {
			if work.RenewAt == nil {
				return terminalf("issued public URL certificate has no renewal date")
			}
			work.AvailableAt = *work.RenewAt
		}
		return err
	case "failed", "canceled":
		_, err := w.continueDNSCleanup(ctx, work, now)
		return err
	default:
		return terminalf("cannot process order in state %q", work.State)
	}
}

func (w *PublicURLWorker) createOrder(ctx context.Context, client acmeAPI, work *controlstate.ACMEOrderWork, now time.Time) error {
	if work.ChallengeMethod != "tls-alpn-01" && work.ChallengeMethod != "dns-01" {
		return terminalf("challenge method %q is not supported", work.ChallengeMethod)
	}
	order, err := client.NewOrder(ctx, work.CertificateIdentifiers, w.config.Profile)
	if err != nil {
		return err
	}
	if err := validateRouteOrder(order, work.CertificateIdentifiers); err != nil {
		return err
	}
	work.OrderURL = order.URL
	work.FinalizeURL = order.Finalize
	work.CertificateURL = order.Certificate
	return w.applyOrderStatus(work, order.Status, order.RetryAfter, now)
}

func (w *PublicURLWorker) authorizeOrder(ctx context.Context, client acmeAPI, work *controlstate.ACMEOrderWork, now time.Time) error {
	// A known deadline must still retire the order when the CA cannot be
	// reached; DNS cleanup does not require a fresh response from the CA.
	for _, authorization := range work.Authorizations {
		if authorization.ExpiresAt != nil && !authorization.ExpiresAt.After(now) && authorization.State != "canceled" {
			return terminalf("authorization for %q expired in state %q", authorization.Identifier, authorization.State)
		}
	}
	order, err := client.GetOrder(ctx, work.OrderURL)
	if err != nil {
		return err
	}
	if err := validateRouteOrder(order, work.CertificateIdentifiers); err != nil {
		return err
	}
	work.FinalizeURL = order.Finalize
	work.CertificateURL = order.Certificate
	if len(work.Authorizations) != 0 && !sameAuthorizationURLs(order.Authorizations, work.Authorizations) {
		return terminalf("order authorization URLs changed")
	}
	if order.Status != "pending" {
		if order.Status == "ready" || order.Status == "processing" || order.Status == "valid" {
			markAuthorizationsValid(work.Authorizations, now)
		}
		if order.Status == "invalid" {
			return w.invalidOrder(ctx, client, work)
		}
		return w.applyOrderStatus(work, order.Status, order.RetryAfter, now)
	}
	if len(work.Authorizations) == 0 {
		return w.discoverAuthorizations(ctx, client, work, order, now)
	}
	if err := validateActiveAuthorizations(work.Authorizations); err != nil {
		return err
	}
	if handled, err := w.advanceAuthorizations(ctx, client, work, now); handled || err != nil {
		return err
	}
	if allAuthorizationsValid(work.Authorizations) {
		work.State = "ready_to_finalize"
		work.AvailableAt = now
	} else {
		work.AvailableAt = w.nextAuthorizationAt(work, now)
	}
	return nil
}

func (w *PublicURLWorker) finalizeOrder(ctx context.Context, client acmeAPI, work *controlstate.ACMEOrderWork, now time.Time) error {
	order, err := client.GetOrder(ctx, work.OrderURL)
	if err != nil {
		return err
	}
	if err := validateRouteOrder(order, work.CertificateIdentifiers); err != nil {
		return err
	}
	work.FinalizeURL = order.Finalize
	work.CertificateURL = order.Certificate
	switch order.Status {
	case "pending":
		work.State = "authorizing"
		work.AvailableAt = now
		return nil
	case "ready":
		order, err = client.FinalizeOrder(ctx, work.OrderURL, work.FinalizeURL, work.CSRDER)
		if err != nil {
			return err
		}
		if err := validateRouteOrder(order, work.CertificateIdentifiers); err != nil {
			return err
		}
		work.CertificateURL = order.Certificate
		if order.Status == "invalid" {
			return w.invalidOrder(ctx, client, work)
		}
		return w.applyOrderStatus(work, order.Status, order.RetryAfter, now)
	case "processing", "valid", "invalid":
		if order.Status == "invalid" {
			return w.invalidOrder(ctx, client, work)
		}
		return w.applyOrderStatus(work, order.Status, order.RetryAfter, now)
	default:
		return fmt.Errorf("certificates: unknown public URL order status %q", order.Status)
	}
}

func (w *PublicURLWorker) collectCertificate(ctx context.Context, client acmeAPI, work *controlstate.ACMEOrderWork, now time.Time) error {
	if len(work.CertificatePEM) != 0 {
		if work.RenewAt == nil {
			return terminalf("issued public URL certificate has no renewal date")
		}
		work.State = "waiting_for_install"
		work.AvailableAt = certificateCleanupAvailableAt(work, now)
		return nil
	}
	order, err := client.GetOrder(ctx, work.OrderURL)
	if err != nil {
		return err
	}
	if err := validateRouteOrder(order, work.CertificateIdentifiers); err != nil {
		return err
	}
	work.FinalizeURL = order.Finalize
	work.CertificateURL = order.Certificate
	switch order.Status {
	case "pending":
		work.State = "authorizing"
		work.AvailableAt = now
		return nil
	case "ready":
		work.State = "ready_to_finalize"
		work.AvailableAt = now
		return nil
	case "processing":
		work.AvailableAt = pollAt(now, w.config.PollInterval, order.RetryAfter)
		return nil
	case "invalid":
		return w.invalidOrder(ctx, client, work)
	case "valid":
		if order.Certificate == "" {
			return terminalf("valid public URL order has no certificate URL")
		}
		certificatePEM, err := client.DownloadCertificate(ctx, order.Certificate)
		if err != nil {
			return err
		}
		notBefore, notAfter, err := validatePublicURLCertificate(certificatePEM, work.CSRDER, work.CertificateIdentifiers, now)
		if err != nil {
			return terminalf("issued certificate is invalid: %v", err)
		}
		work.CertificatePEM = certificatePEM
		work.NotBefore = &notBefore
		work.NotAfter = &notAfter
		renewAt := notBefore.Add(notAfter.Sub(notBefore) * 2 / 3).UTC()
		work.RenewAt = &renewAt
		work.State = "waiting_for_install"
		work.AvailableAt = certificateCleanupAvailableAt(work, now)
		return nil
	default:
		return fmt.Errorf("certificates: unknown public URL order status %q", order.Status)
	}
}

func (w *PublicURLWorker) applyOrderStatus(work *controlstate.ACMEOrderWork, status string, retryAfter, now time.Time) error {
	if work.State != controlstate.ACMEOrderPending && work.State != controlstate.ACMEOrderAuthorizing && work.State != controlstate.ACMEOrderReadyToFinalize {
		return terminalf("cannot apply ACME order status in state %q", work.State)
	}
	stage, availableAt, err := acmeOrderProgress(status, now, retryAfter, w.config.PollInterval)
	if err != nil {
		return err
	}
	work.State, work.AvailableAt = stage, availableAt
	return nil
}

func (w *PublicURLWorker) applyFailure(work *controlstate.ACMEOrderWork, operationErr error, now time.Time) {
	work.LastError = truncateError(operationErr)
	work.AvailableAt = now.Add(5 * time.Second)
	unconfigured := errors.Is(operationErr, dnscontroller.ErrChallengesNotConfigured)
	if unconfigured {
		work.AvailableAt = now.Add(time.Minute)
	}
	// DNS cleanup must continue after installation without changing the
	// availability of an already validated public URL certificate.
	if work.State == "waiting_for_install" || work.State == "installed" {
		return
	}
	var acmeError *acmeclient.Error
	if work.State == "failed" || work.State == "canceled" {
		for index := range work.Authorizations {
			if work.Authorizations[index].State == "cleaning" {
				work.Authorizations[index].LastError = work.LastError
				work.Authorizations[index].AvailableAt = work.AvailableAt
			}
		}
		return
	}
	if errors.As(operationErr, &acmeError) && !acmeError.RetryAfter.IsZero() {
		work.AvailableAt = acmeError.RetryAfter
	}
	if isTerminal(operationErr) {
		work.State = "failed"
		if !unconfigured {
			work.AvailableAt = now
		}
		for index := range work.Authorizations {
			authorization := &work.Authorizations[index]
			if authorization.State != "complete" && authorization.State != "canceled" {
				if authorization.ChallengeType == "dns-01" &&
					(authorization.State == "presenting" || authorization.State == "presented" ||
						authorization.State == "validating" || authorization.State == "cleaning" ||
						authorization.PresentedAt != nil) {
					authorization.State = "cleaning"
				} else {
					authorization.State = "failed"
				}
				authorization.LastError = work.LastError
				authorization.AvailableAt = work.AvailableAt
			}
		}
	}
}

func validateRouteOrder(order acmeclient.Order, identifiers []string) error {
	if order.URL == "" || order.Status == "" || order.Finalize == "" {
		return errors.New("certificates: public URL ACME order is incomplete")
	}
	actual := make([]string, len(order.Identifiers))
	for index, identifier := range order.Identifiers {
		if identifier.Type != "dns" || identifier.Value == "" {
			return terminalf("ACME order contains an unsupported identifier")
		}
		actual[index] = identifier.Value
	}
	expected := slices.Clone(identifiers)
	slices.Sort(actual)
	slices.Sort(expected)
	if !slices.Equal(actual, expected) {
		return terminalf("ACME order identifiers do not match the certificate plan")
	}
	return nil
}

func validatePublicURLCertificate(certificatePEM, csrDER []byte, identifiers []string, now time.Time) (time.Time, time.Time, error) {
	leaf, err := certificateidentity.ValidateIssuedCertificate(certificatePEM, csrDER, identifiers, now)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	return leaf.NotBefore.UTC(), leaf.NotAfter.UTC(), nil
}
