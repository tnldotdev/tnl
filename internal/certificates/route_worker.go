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

type RouteConfig struct {
	WorkerID         string
	Profile          string
	HTTPClient       *http.Client
	Logger           *slog.Logger
	LeaseDuration    time.Duration
	OperationTimeout time.Duration
	PollInterval     time.Duration
	IdleInterval     time.Duration
	DNSChallenges    RouteDNSChallenges
	Observer         RouteWorkObserver
}

// RouteWorkObserver records only fixed worker stages and outcomes.
type RouteWorkObserver interface {
	ObserveCertificateWork(stage, outcome string, elapsed time.Duration)
}

type RouteDNSChallenges interface {
	Present(context.Context, string, string) error
	Verify(context.Context, string, string) (bool, error)
	Cleanup(context.Context, string, string) error
}

// RouteStore is the stored certificate work used by a RouteWorker.
type RouteStore interface {
	ClaimACMEOrderWork(context.Context, string, time.Time, time.Duration) (controlstate.ACMEOrderWork, bool, error)
	SaveACMEOrderWork(context.Context, controlstate.ACMEOrderWork, time.Time) (controlstate.ACMEOrderWork, error)
}

type RouteWorker struct {
	store        RouteStore
	config       RouteConfig
	now          func() time.Time
	client       acmeClientFactory
	clientKey    routeACMEClientKey
	cachedClient acmeAPI
}

type routeACMEClientKey struct {
	directoryURL, accountURL string
	accountKey               [sha256.Size]byte
}

func NewRouteWorker(store RouteStore, config RouteConfig) (*RouteWorker, error) {
	if store == nil || strings.TrimSpace(config.WorkerID) != config.WorkerID || config.WorkerID == "" ||
		strings.TrimSpace(config.Profile) != config.Profile || config.Profile == "" || config.HTTPClient == nil {
		return nil, errors.New("certificates: invalid route worker configuration")
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
		return nil, errors.New("certificates: route worker operation timeout must be shorter than the work lease")
	}
	worker := &RouteWorker{store: store, config: config, now: func() time.Time { return time.Now().UTC() }}
	worker.client = newACMEClientFactory(config.HTTPClient)
	return worker, nil
}

func (w *RouteWorker) Run(ctx context.Context) error {
	return runWorkerLoop(
		ctx, w, w.config.Logger, w.config.OperationTimeout, w.config.IdleInterval,
		"route certificate worker iteration failed",
	)
}

func (w *RouteWorker) processOne(ctx context.Context) (bool, error) {
	now := w.now()
	work, found, err := w.store.ClaimACMEOrderWork(ctx, w.config.WorkerID, now, w.config.LeaseDuration)
	if err != nil || !found {
		return found, err
	}
	stage := work.State
	started := time.Now()
	client, err := w.clientFor(work.Account)
	if err == nil && work.Account.AccountURL == "" {
		err = errors.New("certificates: route worker ACME account is not registered")
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
	if _, saveErr := w.store.SaveACMEOrderWork(ctx, work, completedAt); saveErr != nil {
		if ctx.Err() == nil {
			w.observeWork(stage, "save_failed", started)
			w.logWork(work, stage, "save_failed", completedAt)
		}
		return true, saveErr
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

func (w *RouteWorker) observeWork(stage, outcome string, started time.Time) {
	if w.config.Observer != nil {
		w.config.Observer.ObserveCertificateWork(stage, outcome, time.Since(started))
	}
}

func (w *RouteWorker) logWork(work controlstate.ACMEOrderWork, stage, outcome string, now time.Time) {
	if w.config.Logger == nil {
		return
	}
	w.config.Logger.Info("route certificate work", "route_session_id", work.RouteSessionID, "route_version", work.RouteVersion,
		"issuance_id", work.ID, "stage", stage, "state", work.State, "outcome", outcome,
		"attempts", work.Attempts, "age", now.Sub(work.CreatedAt).Round(time.Second), "next_available_at", work.AvailableAt)
}

func (w *RouteWorker) clientFor(account controlstate.ACMEAccount) (acmeAPI, error) {
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

func (w *RouteWorker) advance(ctx context.Context, client acmeAPI, work *controlstate.ACMEOrderWork, now time.Time) error {
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
	case "failed", "canceled":
		return w.cleanupFailedOrder(ctx, work, now)
	default:
		return terminalf("cannot process order in state %q", work.State)
	}
}

func (w *RouteWorker) createOrder(ctx context.Context, client acmeAPI, work *controlstate.ACMEOrderWork, now time.Time) error {
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

func (w *RouteWorker) authorizeOrder(ctx context.Context, client acmeAPI, work *controlstate.ACMEOrderWork, now time.Time) error {
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
	for index := range work.Authorizations {
		authorization := &work.Authorizations[index]
		if authorization.ExpiresAt != nil && !authorization.ExpiresAt.After(now) &&
			authorization.State != "canceled" {
			return terminalf("authorization for %q expired in state %q", authorization.Identifier, authorization.State)
		}
		switch authorization.State {
		case "presenting":
			if authorization.ChallengeType == "dns-01" {
				if err := w.config.DNSChallenges.Present(ctx, work.RouteID, authorization.ID); err != nil {
					return err
				}
				authorization.State = "presented"
				authorization.Attempts++
				authorization.PresentedAt = timePointer(now)
				authorization.AvailableAt = now.Add(w.config.PollInterval)
				work.AvailableAt = authorization.AvailableAt
				return nil
			}
		case "presented":
			if authorization.ChallengeType == "dns-01" {
				verified, err := w.config.DNSChallenges.Verify(ctx, work.RouteID, authorization.ID)
				if err != nil {
					return err
				}
				if !verified {
					authorization.AvailableAt = now.Add(w.config.PollInterval)
					work.AvailableAt = authorization.AvailableAt
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
			work.AvailableAt = authorization.AvailableAt
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
				return fmt.Errorf("certificates: unknown route authorization status %q", remote.Status)
			}
			work.AvailableAt = authorization.AvailableAt
			return nil
		case "valid", "complete":
			continue
		case "failed", "canceled", "cleaning":
			return terminalf("authorization for %q is in state %q", authorization.Identifier, authorization.State)
		default:
			return terminalf("unknown persisted authorization state %q", authorization.State)
		}
	}
	if allAuthorizationsValid(work.Authorizations) {
		work.State = "ready_to_finalize"
		work.AvailableAt = now
	} else {
		work.AvailableAt = now.Add(w.config.PollInterval)
	}
	return nil
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

func (w *RouteWorker) finalizeOrder(ctx context.Context, client acmeAPI, work *controlstate.ACMEOrderWork, now time.Time) error {
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
		return w.applyOrderStatus(work, order.Status, order.RetryAfter, now)
	case "processing", "valid", "invalid":
		return w.applyOrderStatus(work, order.Status, order.RetryAfter, now)
	default:
		return fmt.Errorf("certificates: unknown route order status %q", order.Status)
	}
}

func (w *RouteWorker) collectCertificate(ctx context.Context, client acmeAPI, work *controlstate.ACMEOrderWork, now time.Time) error {
	if len(work.CertificatePEM) != 0 {
		handled, err := w.continueDNSCleanup(ctx, work, now)
		if err != nil || handled {
			return err
		}
		work.State = "waiting_for_install"
		work.AvailableAt = *work.RenewAt
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
		return terminalf("ACME order became invalid")
	case "valid":
		if order.Certificate == "" {
			return errors.New("certificates: valid route order has no certificate URL")
		}
		certificatePEM, err := client.DownloadCertificate(ctx, order.Certificate)
		if err != nil {
			return err
		}
		notBefore, notAfter, err := validateRouteCertificate(certificatePEM, work.CSRDER, work.CertificateIdentifiers, now)
		if err != nil {
			return terminalf("issued certificate is invalid: %v", err)
		}
		work.CertificatePEM = certificatePEM
		work.NotBefore = &notBefore
		work.NotAfter = &notAfter
		renewAt := notBefore.Add(notAfter.Sub(notBefore) * 2 / 3).UTC()
		work.RenewAt = &renewAt
		if handled, err := w.continueDNSCleanup(ctx, work, now); err != nil || handled {
			return err
		}
		work.State = "waiting_for_install"
		work.AvailableAt = renewAt
		return nil
	default:
		return fmt.Errorf("certificates: unknown route order status %q", order.Status)
	}
}

func (w *RouteWorker) applyOrderStatus(work *controlstate.ACMEOrderWork, status string, retryAfter, now time.Time) error {
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
		return fmt.Errorf("certificates: unknown route order status %q", status)
	}
	work.AvailableAt = pollAt(now, w.config.PollInterval, retryAfter)
	if work.State == "ready_to_finalize" || status == "valid" {
		work.AvailableAt = now
	}
	return nil
}

func (w *RouteWorker) applyFailure(work *controlstate.ACMEOrderWork, operationErr error, now time.Time) {
	work.LastError = truncateError(operationErr)
	work.AvailableAt = now.Add(5 * time.Second)
	unconfigured := errors.Is(operationErr, dnscontroller.ErrChallengesNotConfigured)
	if unconfigured {
		work.AvailableAt = now.Add(time.Minute)
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
		return result, fmt.Errorf("certificates: unknown route authorization status %q", authorization.Status)
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

func (w *RouteWorker) continueDNSCleanup(
	ctx context.Context,
	work *controlstate.ACMEOrderWork,
	now time.Time,
) (bool, error) {
	for index := range work.Authorizations {
		authorization := &work.Authorizations[index]
		if authorization.ChallengeType != "dns-01" || authorization.State == "complete" || authorization.State == "canceled" {
			continue
		}
		if authorization.State == "valid" && authorization.PresentedAt == nil {
			authorization.State = "complete"
			authorization.CleanupCompletedAt = timePointer(now)
			authorization.AvailableAt = now
			continue
		}
		if authorization.State == "valid" {
			authorization.State = "cleaning"
			authorization.AvailableAt = now
			work.AvailableAt = now
			return true, nil
		}
		if authorization.State != "cleaning" {
			return false, terminalf("cannot clean DNS authorization for %q in state %q", authorization.Identifier, authorization.State)
		}
		if err := w.config.DNSChallenges.Cleanup(ctx, work.RouteID, authorization.ID); err != nil {
			return false, err
		}
		authorization.State = "complete"
		authorization.CleanupCompletedAt = timePointer(now)
		authorization.AvailableAt = now
		work.AvailableAt = now
		return true, nil
	}
	return false, nil
}

func (w *RouteWorker) cleanupFailedOrder(ctx context.Context, work *controlstate.ACMEOrderWork, now time.Time) error {
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

func validateRouteCertificate(certificatePEM, csrDER []byte, identifiers []string, now time.Time) (time.Time, time.Time, error) {
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
