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
			w.observeWork(stage, "save_failed", started)
			w.logWork(work, stage, "save_failed", completedAt)
		}
		return true, saveErr
	}
	if w.config.Observer != nil {
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
	w.observeWork(stage, outcome, started)
	if err != nil || work.State != stage && (work.State == "waiting_for_install" || work.State == "failed") && completedAt.Sub(work.CreatedAt) >= 30*time.Second {
		w.logWork(work, stage, outcome, completedAt)
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
		return w.cleanupFailedOrder(ctx, work, now)
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
		expected := make(map[string]struct{}, len(work.CertificateIdentifiers))
		for _, identifier := range work.CertificateIdentifiers {
			expected[identifier] = struct{}{}
		}
		seen := make(map[string]struct{}, len(order.Authorizations))
		authorizations := make([]controlstate.ACMEAuthorizationWork, 0, len(order.Authorizations))
		for _, authorizationURL := range order.Authorizations {
			authorization, err := client.GetAuthorization(ctx, authorizationURL)
			if err != nil {
				return err
			}
			if authorizationURL == "" || authorization.URL != authorizationURL || authorization.Identifier.Type != "dns" {
				return terminalf("order authorization identity does not match %q", authorizationURL)
			}
			value, err := authorizationWork(client, authorization, work.ChallengeMethod, order.Expires, now)
			if err != nil {
				return err
			}
			if _, exists := expected[value.Identifier]; !exists {
				return terminalf("order authorization identifier %q is not in the certificate plan", value.Identifier)
			}
			if _, exists := seen[value.Identifier]; exists {
				return terminalf("order repeats authorization identifier %q", value.Identifier)
			}
			seen[value.Identifier] = struct{}{}
			authorizations = append(authorizations, value)
		}
		if len(authorizations) != len(expected) || !sameAuthorizationURLs(order.Authorizations, authorizations) {
			return terminalf("pending order authorizations do not match the certificate plan")
		}
		// Discovery is persisted only after every fetch and identity check succeeds.
		work.Authorizations = authorizations
		if allAuthorizationsValid(work.Authorizations) {
			work.State = "ready_to_finalize"
		}
		work.AvailableAt = pollAt(now, w.config.PollInterval, order.RetryAfter)
		return nil
	}
	for _, authorization := range work.Authorizations {
		if authorization.ExpiresAt != nil && !authorization.ExpiresAt.After(now) &&
			authorization.State != "canceled" {
			return terminalf("authorization for %q expired in state %q", authorization.Identifier, authorization.State)
		}
		switch authorization.State {
		case "presenting", "presented", "validating", "valid", "complete":
		case "failed", "canceled", "cleaning":
			return terminalf("authorization for %q is in state %q", authorization.Identifier, authorization.State)
		default:
			return terminalf("unknown persisted authorization state %q", authorization.State)
		}
	}
	// Present all challenges before waiting for any one authorization to
	// validate. Wildcard and exact-name DNS-01 challenges can share a TXT name;
	// the challenge manager publishes and checks their values as one record.
	for _, state := range []string{"presenting", "presented", "validating"} {
		for index := range work.Authorizations {
			authorization := &work.Authorizations[index]
			if authorization.State != state || authorization.AvailableAt.After(now) {
				continue
			}
			switch state {
			case "presenting":
				if authorization.ChallengeType == "dns-01" {
					if err := w.config.DNSChallenges.Present(ctx, work.PublicURLID, authorization.ID); err != nil {
						return err
					}
					authorization.State = "presented"
					authorization.Attempts++
					authorization.PresentedAt = timePointer(now)
					authorization.AvailableAt = now.Add(w.config.PollInterval)
					work.AvailableAt = w.nextAuthorizationAt(work, now)
					return nil
				}
			case "presented":
				if authorization.ChallengeType == "dns-01" {
					verified, err := w.config.DNSChallenges.Verify(ctx, work.PublicURLID, authorization.ID)
					if err != nil {
						return err
					}
					if !verified {
						authorization.AvailableAt = now.Add(w.config.PollInterval)
						work.AvailableAt = w.nextAuthorizationAt(work, now)
						return nil
					}
				}
				if authorization.ChallengeType == "tls-alpn-01" {
					ready, err := w.store.ACMEChallengeRoutingReady(ctx, work.ID, now)
					if err != nil {
						return err
					}
					if !ready {
						authorization.AvailableAt = now.Add(w.config.PollInterval)
						work.AvailableAt = w.nextAuthorizationAt(work, now)
						return nil
					}
				}
				retryAfter, err := client.AcceptChallenge(ctx, authorization.ChallengeURL)
				if err != nil {
					return err
				}
				authorization.State = "validating"
				authorization.Attempts++
				authorization.AvailableAt = pollAt(now, w.config.PollInterval, retryAfter)
				work.AvailableAt = w.nextAuthorizationAt(work, now)
				return nil
			case "validating":
				remote, err := client.GetAuthorization(ctx, authorization.AuthorizationURL)
				if err != nil {
					return err
				}
				if remote.URL != authorization.AuthorizationURL || remote.Identifier.Type != "dns" ||
					authorizationIdentifier(remote) != authorization.Identifier {
					return terminalf("authorization identity changed for %q", authorization.Identifier)
				}
				switch remote.Status {
				case "pending", "processing":
					authorization.AvailableAt = pollAt(now, w.config.PollInterval, remote.RetryAfter)
				case "valid":
					if remote.Expires != nil && !remote.Expires.After(now) {
						return terminalf("authorization for %q expired", authorization.Identifier)
					}
					authorization.State = "valid"
					authorization.ValidatedAt = timePointer(now)
					authorization.AvailableAt = now
				case "invalid", "deactivated", "expired", "revoked":
					authorization.State = "failed"
					if problem := authorizationChallengeProblem(remote, authorization.ChallengeType, authorization.ChallengeURL); problem != "" {
						return terminalf("authorization for %q became %q: %s", authorization.Identifier, remote.Status, problem)
					}
					return terminalf("authorization for %q became %q", authorization.Identifier, remote.Status)
				default:
					return fmt.Errorf("certificates: unknown public URL authorization status %q", remote.Status)
				}
				work.AvailableAt = w.nextAuthorizationAt(work, now)
				return nil
			}
		}
	}
	if allAuthorizationsValid(work.Authorizations) {
		work.State = "ready_to_finalize"
		work.AvailableAt = now
	} else {
		work.AvailableAt = w.nextAuthorizationAt(work, now)
	}
	return nil
}

func (w *PublicURLWorker) nextAuthorizationAt(work *controlstate.ACMEOrderWork, now time.Time) time.Time {
	var next time.Time
	for _, authorization := range work.Authorizations {
		if authorization.State == "valid" || authorization.State == "complete" {
			continue
		}
		if next.IsZero() || authorization.AvailableAt.Before(next) {
			next = authorization.AvailableAt
		}
	}
	if next.IsZero() || next.Before(now) {
		return now
	}
	return next
}

func authorizationChallengeProblem(authorization acmeclient.Authorization, challengeType, challengeURL string) string {
	for _, challenge := range authorization.Challenges {
		if challenge.Type != challengeType || challenge.URL != challengeURL || challenge.Error == nil {
			continue
		}
		problem := challenge.Error
		switch {
		case problem.Type != "" && problem.Detail != "":
			return fmt.Sprintf("%s: %s", problem.Type, problem.Detail)
		case problem.Type != "":
			return problem.Type
		default:
			return problem.Detail
		}
	}
	return ""
}

// An order can become invalid before the next authorization poll. Fetch the
// failed challenge while the original order is still available, so replacement
// issuance retains the CA's reason rather than only "order became invalid".
func (w *PublicURLWorker) invalidOrder(ctx context.Context, client acmeAPI, work *controlstate.ACMEOrderWork) error {
	for _, authorization := range work.Authorizations {
		if authorization.AuthorizationURL == "" || authorization.ChallengeURL == "" {
			continue
		}
		remote, err := client.GetAuthorization(ctx, authorization.AuthorizationURL)
		if err != nil || remote.URL != authorization.AuthorizationURL ||
			remote.Identifier.Type != "dns" || authorizationIdentifier(remote) != authorization.Identifier {
			continue
		}
		if problem := authorizationChallengeProblem(remote, authorization.ChallengeType, authorization.ChallengeURL); problem != "" {
			return terminalf("ACME order became invalid: authorization for %q: %s", authorization.Identifier, problem)
		}
	}
	return terminalf("ACME order became invalid")
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

func certificateCleanupAvailableAt(work *controlstate.ACMEOrderWork, now time.Time) time.Time {
	if hasPendingDNSCleanup(work.Authorizations) {
		return now
	}
	return *work.RenewAt
}

func hasPendingDNSCleanup(authorizations []controlstate.ACMEAuthorizationWork) bool {
	return slices.ContainsFunc(authorizations, func(authorization controlstate.ACMEAuthorizationWork) bool {
		return authorization.ChallengeType == "dns-01" &&
			(authorization.State == "valid" || authorization.State == "cleaning")
	})
}

func (w *PublicURLWorker) applyOrderStatus(work *controlstate.ACMEOrderWork, status string, retryAfter, now time.Time) error {
	switch status {
	case "pending":
		work.State = "authorizing"
	case "ready":
		work.State = "ready_to_finalize"
	case "processing", "valid":
		work.State = "finalizing"
	case "invalid":
		return terminalf("ACME order became invalid")
	default:
		return fmt.Errorf("certificates: unknown public URL order status %q", status)
	}
	work.AvailableAt = pollAt(now, w.config.PollInterval, retryAfter)
	if work.State == "ready_to_finalize" || status == "valid" {
		work.AvailableAt = now
	}
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

func authorizationWork(
	client acmeAPI,
	authorization acmeclient.Authorization,
	challengeMethod string,
	orderExpires *time.Time,
	now time.Time,
) (controlstate.ACMEAuthorizationWork, error) {
	result := controlstate.ACMEAuthorizationWork{
		Identifier: authorizationIdentifier(authorization), AuthorizationURL: authorization.URL,
		AvailableAt: now, CreatedAt: now, UpdatedAt: now,
	}
	if authorization.Status == "valid" && authorization.Expires == nil {
		return result, terminalf("valid authorization for %q has no expiry", result.Identifier)
	}
	expiresAt := authorization.Expires
	if expiresAt == nil {
		expiresAt = orderExpires
	}
	if expiresAt == nil {
		fallback := now.Add(5 * time.Minute)
		expiresAt = &fallback
	}
	result.ExpiresAt = timePointer(expiresAt.UTC())
	if !expiresAt.After(now) {
		return result, terminalf("authorization for %q expired", result.Identifier)
	}
	switch authorization.Status {
	case "valid":
		// Reused authorizations need no new challenge, even if an old method is returned.
		result.State = "complete"
		result.ValidatedAt = timePointer(now)
		result.CleanupCompletedAt = timePointer(now)
		return result, nil
	case "pending":
	case "invalid", "deactivated", "expired", "revoked":
		return result, terminalf("authorization for %q is %q", result.Identifier, authorization.Status)
	default:
		return result, fmt.Errorf("certificates: unknown public URL authorization status %q", authorization.Status)
	}
	for _, challenge := range authorization.Challenges {
		if challenge.Type != challengeMethod {
			continue
		}
		if challenge.URL == "" || challenge.Token == "" {
			return result, terminalf("authorization for %q has an incomplete %s challenge", result.Identifier, challengeMethod)
		}
		keyAuthorization, err := client.KeyAuthorization(challenge.Token)
		if err != nil {
			return result, err
		}
		result.ChallengeType = challenge.Type
		result.ChallengeURL = challenge.URL
		result.ChallengeToken = challenge.Token
		result.ChallengeDigest = sha256.Sum256([]byte(keyAuthorization))
		break
	}
	if result.ChallengeType == "" {
		return result, terminalf("authorization for %q has no %s challenge", result.Identifier, challengeMethod)
	}
	result.State = "presenting"
	return result, nil
}

func (w *PublicURLWorker) continueDNSCleanup(
	ctx context.Context,
	work *controlstate.ACMEOrderWork,
	now time.Time,
) (bool, error) {
	changed := false
	for index := range work.Authorizations {
		authorization := &work.Authorizations[index]
		if authorization.ChallengeType != "dns-01" || authorization.State == "complete" || authorization.State == "canceled" {
			continue
		}
		if authorization.State == "valid" && authorization.PresentedAt == nil {
			authorization.State = "complete"
			authorization.CleanupCompletedAt = timePointer(now)
			authorization.AvailableAt = now
			changed = true
			continue
		}
		if authorization.State == "valid" {
			authorization.State = "cleaning"
			authorization.AvailableAt = now
			changed = true
			continue
		}
		if authorization.State != "cleaning" {
			return false, terminalf("cannot clean DNS authorization for %q in state %q", authorization.Identifier, authorization.State)
		}
	}
	if changed {
		work.AvailableAt = now
		return true, nil
	}
	for index := range work.Authorizations {
		authorization := &work.Authorizations[index]
		if authorization.ChallengeType != "dns-01" || authorization.State != "cleaning" {
			continue
		}
		if err := w.config.DNSChallenges.Cleanup(ctx, work.PublicURLID, authorization.ID); err != nil {
			return false, err
		}
		// All authorizations for this base identifier share one TXT name. The
		// challenge manager reconciles their combined owned values in one write.
		base := strings.TrimPrefix(authorization.Identifier, "*.")
		for otherIndex := range work.Authorizations {
			other := &work.Authorizations[otherIndex]
			if other.ChallengeType != "dns-01" || other.State != "cleaning" ||
				strings.TrimPrefix(other.Identifier, "*.") != base {
				continue
			}
			other.State = "complete"
			other.CleanupCompletedAt = timePointer(now)
			other.AvailableAt = now
		}
		work.AvailableAt = now
		return true, nil
	}
	return false, nil
}

func (w *PublicURLWorker) cleanupFailedOrder(ctx context.Context, work *controlstate.ACMEOrderWork, now time.Time) error {
	_, err := w.continueDNSCleanup(ctx, work, now)
	return err
}

func authorizationIdentifier(authorization acmeclient.Authorization) string {
	if authorization.Wildcard {
		return "*." + authorization.Identifier.Value
	}
	return authorization.Identifier.Value
}

func validateRouteOrder(order acmeclient.Order, identifiers []string) error {
	if order.URL == "" || order.Status == "" || order.Finalize == "" {
		return errors.New("certificates: route ACME order is incomplete")
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

func allAuthorizationsValid(authorizations []controlstate.ACMEAuthorizationWork) bool {
	return len(authorizations) != 0 && !slices.ContainsFunc(authorizations, func(value controlstate.ACMEAuthorizationWork) bool {
		return value.State != "valid" && value.State != "complete"
	})
}

func markAuthorizationsValid(authorizations []controlstate.ACMEAuthorizationWork, now time.Time) {
	for index := range authorizations {
		if authorizations[index].State == "complete" || authorizations[index].State == "canceled" {
			continue
		}
		authorizations[index].State = "valid"
		if authorizations[index].ValidatedAt == nil {
			authorizations[index].ValidatedAt = timePointer(now)
		}
		authorizations[index].AvailableAt = now
	}
}

func sameAuthorizationURLs(urls []string, authorizations []controlstate.ACMEAuthorizationWork) bool {
	expected := slices.Clone(urls)
	actual := make([]string, len(authorizations))
	for index := range authorizations {
		actual[index] = authorizations[index].AuthorizationURL
	}
	slices.Sort(expected)
	slices.Sort(actual)
	return slices.Equal(expected, actual) && len(slices.Compact(expected)) == len(urls)
}

func timePointer(value time.Time) *time.Time {
	return &value
}
