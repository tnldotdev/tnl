package certificateworker

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/tnldotdev/tnl/internal/acmeclient"
	"github.com/tnldotdev/tnl/internal/certificateidentity"
	"github.com/tnldotdev/tnl/internal/controlstate"
)

const (
	defaultLeaseDuration    = 2 * time.Minute
	defaultOperationTimeout = 30 * time.Second
	defaultPollInterval     = 2 * time.Second
	defaultIdleInterval     = 500 * time.Millisecond
)

type Config struct {
	WorkerID         string
	Profile          string
	HTTPClient       *http.Client
	Logger           *slog.Logger
	LeaseDuration    time.Duration
	OperationTimeout time.Duration
	PollInterval     time.Duration
	IdleInterval     time.Duration
	DNSChallenges    DNSChallenges
}

type DNSChallenges interface {
	Present(context.Context, string, string) error
	Verify(context.Context, string, string) (bool, error)
	Cleanup(context.Context, string, string) error
}

// Store is the durable certificate work state consumed by a Worker.
type Store interface {
	UpdateACMEAccountRegistration(context.Context, string, string, string, string, time.Time) (controlstate.ACMEAccount, error)
	ClaimACMEOrderWork(context.Context, string, time.Time, time.Duration) (controlstate.ACMEOrderWork, bool, error)
	SaveACMEOrderWork(context.Context, controlstate.ACMEOrderWork, time.Time) (controlstate.ACMEOrderWork, error)
}

type Worker struct {
	store  Store
	config Config
	now    func() time.Time
	client func(controlstate.ACMEAccount) (acmeAPI, error)
}

type acmeAPI interface {
	NewOrder(context.Context, []string, string) (acmeclient.Order, error)
	GetOrder(context.Context, string) (acmeclient.Order, error)
	GetAuthorization(context.Context, string) (acmeclient.Authorization, error)
	AcceptChallenge(context.Context, string) (time.Time, error)
	FinalizeOrder(context.Context, string, string, []byte) (acmeclient.Order, error)
	DownloadCertificate(context.Context, string) ([]byte, error)
	KeyAuthorization(string) (string, error)
}

func New(store Store, config Config) (*Worker, error) {
	if store == nil || strings.TrimSpace(config.WorkerID) != config.WorkerID || config.WorkerID == "" ||
		strings.TrimSpace(config.Profile) != config.Profile || config.Profile == "" || config.HTTPClient == nil {
		return nil, errors.New("certificateworker: invalid configuration")
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	if config.LeaseDuration <= 0 {
		config.LeaseDuration = defaultLeaseDuration
	}
	if config.OperationTimeout <= 0 {
		config.OperationTimeout = defaultOperationTimeout
	}
	if config.PollInterval <= 0 {
		config.PollInterval = defaultPollInterval
	}
	if config.IdleInterval <= 0 {
		config.IdleInterval = defaultIdleInterval
	}
	if config.OperationTimeout >= config.LeaseDuration {
		return nil, errors.New("certificateworker: operation timeout must be shorter than the work lease")
	}
	worker := &Worker{store: store, config: config, now: func() time.Time { return time.Now().UTC() }}
	worker.client = func(account controlstate.ACMEAccount) (acmeAPI, error) {
		key, err := accountKey(account.AccountKeyDER)
		if err != nil {
			return nil, err
		}
		return acmeclient.New(config.HTTPClient, account.DirectoryURL, key, account.AccountURL)
	}
	return worker, nil
}

func ReconcileAccount(
	ctx context.Context,
	store Store,
	httpClient *http.Client,
	account controlstate.ACMEAccount,
	acceptTerms bool,
	now time.Time,
) (controlstate.ACMEAccount, error) {
	key, err := accountKey(account.AccountKeyDER)
	if err != nil {
		return controlstate.ACMEAccount{}, err
	}
	client, err := acmeclient.New(httpClient, account.DirectoryURL, key, account.AccountURL)
	if err != nil {
		return controlstate.ACMEAccount{}, err
	}
	registered, directory, err := client.ReconcileAccount(ctx, account.ContactEmail, acceptTerms)
	if err != nil {
		return controlstate.ACMEAccount{}, fmt.Errorf("certificateworker: reconcile ACME account: %w", err)
	}
	if registered.Status != "valid" {
		return controlstate.ACMEAccount{}, fmt.Errorf("certificateworker: ACME account status is %q", registered.Status)
	}
	acceptedTerms := account.AcceptedTerms
	if acceptTerms {
		acceptedTerms = directory.Meta.TermsOfService
	}
	updated, err := store.UpdateACMEAccountRegistration(
		ctx, account.ID, account.ContactEmail, registered.URL, acceptedTerms, now,
	)
	if err != nil {
		return controlstate.ACMEAccount{}, fmt.Errorf("certificateworker: persist ACME account registration: %w", err)
	}
	return updated, nil
}

func (w *Worker) Run(ctx context.Context) error {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
		}
		operationCtx, cancel := context.WithTimeout(ctx, w.config.OperationTimeout)
		found, err := w.processOne(operationCtx)
		cancel()
		if err != nil && !errors.Is(err, context.Canceled) {
			w.config.Logger.Error("certificate worker iteration failed", "error", err)
		}
		delay := time.Duration(0)
		if !found || err != nil {
			delay = w.config.IdleInterval
		}
		timer.Reset(delay)
	}
}

func (w *Worker) processOne(ctx context.Context) (bool, error) {
	now := w.now()
	work, found, err := w.store.ClaimACMEOrderWork(ctx, w.config.WorkerID, now, w.config.LeaseDuration)
	if err != nil || !found {
		return found, err
	}
	client, err := w.client(work.Account)
	if err == nil && work.Account.AccountURL == "" {
		err = errors.New("certificateworker: ACME account is not registered")
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
		return true, saveErr
	}
	return true, nil
}

func (w *Worker) advance(ctx context.Context, client acmeAPI, work *controlstate.ACMEOrderWork, now time.Time) error {
	work.LastError = ""
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

func (w *Worker) createOrder(ctx context.Context, client acmeAPI, work *controlstate.ACMEOrderWork, now time.Time) error {
	if work.ChallengeMethod != "tls-alpn-01" && work.ChallengeMethod != "dns-01" {
		return terminalf("challenge method %q is not supported", work.ChallengeMethod)
	}
	if work.ChallengeMethod == "dns-01" && w.config.DNSChallenges == nil {
		return terminalf("DNS-01 challenge automation is not configured")
	}
	order, err := client.NewOrder(ctx, work.CertificateIdentifiers, w.config.Profile)
	if err != nil {
		return err
	}
	if err := validateOrder(order, work.CertificateIdentifiers); err != nil {
		return err
	}
	work.OrderURL = order.URL
	work.FinalizeURL = order.Finalize
	work.CertificateURL = order.Certificate
	return w.applyOrderStatus(work, order.Status, order.RetryAfter, now)
}

func (w *Worker) authorizeOrder(ctx context.Context, client acmeAPI, work *controlstate.ACMEOrderWork, now time.Time) error {
	order, err := client.GetOrder(ctx, work.OrderURL)
	if err != nil {
		return err
	}
	if err := validateOrder(order, work.CertificateIdentifiers); err != nil {
		return err
	}
	work.FinalizeURL = order.Finalize
	work.CertificateURL = order.Certificate
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
		for _, authorizationURL := range order.Authorizations {
			authorization, err := client.GetAuthorization(ctx, authorizationURL)
			if err != nil {
				return err
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
			work.Authorizations = append(work.Authorizations, value)
		}
		if len(work.Authorizations) != len(expected) {
			return terminalf("pending order authorizations do not match the certificate plan")
		}
		if allAuthorizationsValid(work.Authorizations) {
			work.State = "ready_to_finalize"
		}
		work.AvailableAt = pollAt(now, w.config.PollInterval, order.RetryAfter)
		return nil
	}
	if !sameAuthorizationURLs(order.Authorizations, work.Authorizations) {
		return terminalf("order authorization URLs changed")
	}
	for index := range work.Authorizations {
		authorization := &work.Authorizations[index]
		if authorization.ExpiresAt != nil && !authorization.ExpiresAt.After(now) &&
			authorization.State != "valid" && authorization.State != "complete" && authorization.State != "canceled" {
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
				authorization.State = "valid"
				authorization.ValidatedAt = timePointer(now)
				authorization.AvailableAt = now
			case "invalid", "deactivated", "expired", "revoked":
				authorization.State = "failed"
				return terminalf("authorization for %q became %q", authorization.Identifier, remote.Status)
			default:
				return fmt.Errorf("certificateworker: unknown authorization status %q", remote.Status)
			}
			work.AvailableAt = authorization.AvailableAt
			return nil
		case "valid":
			continue
		case "failed", "canceled", "complete", "cleaning":
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

func (w *Worker) finalizeOrder(ctx context.Context, client acmeAPI, work *controlstate.ACMEOrderWork, now time.Time) error {
	order, err := client.GetOrder(ctx, work.OrderURL)
	if err != nil {
		return err
	}
	if err := validateOrder(order, work.CertificateIdentifiers); err != nil {
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
		if err := validateOrder(order, work.CertificateIdentifiers); err != nil {
			return err
		}
		work.CertificateURL = order.Certificate
		return w.applyOrderStatus(work, order.Status, order.RetryAfter, now)
	case "processing", "valid", "invalid":
		return w.applyOrderStatus(work, order.Status, order.RetryAfter, now)
	default:
		return fmt.Errorf("certificateworker: unknown order status %q", order.Status)
	}
}

func (w *Worker) collectCertificate(ctx context.Context, client acmeAPI, work *controlstate.ACMEOrderWork, now time.Time) error {
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
	if err := validateOrder(order, work.CertificateIdentifiers); err != nil {
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
			return errors.New("certificateworker: valid order has no certificate URL")
		}
		certificatePEM, err := client.DownloadCertificate(ctx, order.Certificate)
		if err != nil {
			return err
		}
		notBefore, notAfter, err := validateCertificate(certificatePEM, work.CSRDER, work.CertificateIdentifiers, now)
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
		return fmt.Errorf("certificateworker: unknown order status %q", order.Status)
	}
}

func (w *Worker) applyOrderStatus(work *controlstate.ACMEOrderWork, status string, retryAfter, now time.Time) error {
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
		return fmt.Errorf("certificateworker: unknown order status %q", status)
	}
	work.AvailableAt = pollAt(now, w.config.PollInterval, retryAfter)
	if work.State == "ready_to_finalize" || status == "valid" {
		work.AvailableAt = now
	}
	return nil
}

func pollAt(now time.Time, interval time.Duration, retryAfter time.Time) time.Time {
	result := now.Add(interval)
	if retryAfter.After(result) {
		return retryAfter.UTC()
	}
	return result
}

func (w *Worker) applyFailure(work *controlstate.ACMEOrderWork, operationErr error, now time.Time) {
	work.LastError = truncateError(operationErr)
	work.AvailableAt = now.Add(5 * time.Second)
	var acmeError *acmeclient.Error
	var terminal *terminalError
	if work.State == "failed" || work.State == "canceled" {
		for index := range work.Authorizations {
			if work.Authorizations[index].State == "cleaning" {
				work.Authorizations[index].LastError = work.LastError
				work.Authorizations[index].AvailableAt = now.Add(5 * time.Second)
			}
		}
		work.AvailableAt = now.Add(5 * time.Second)
		return
	}
	if errors.As(operationErr, &acmeError) && !acmeError.RetryAfter.IsZero() {
		work.AvailableAt = acmeError.RetryAfter
	}
	if errors.As(operationErr, &terminal) || errors.As(operationErr, &acmeError) && acmeError.Terminal() {
		work.State = "failed"
		work.AvailableAt = now
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
				authorization.AvailableAt = now
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
	expiresAt := authorization.Expires
	if expiresAt == nil {
		expiresAt = orderExpires
	}
	if expiresAt == nil {
		fallback := now.Add(5 * time.Minute)
		expiresAt = &fallback
	}
	result.ExpiresAt = timePointer(expiresAt.UTC())
	for _, challenge := range authorization.Challenges {
		if challenge.Type != challengeMethod {
			continue
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
	switch authorization.Status {
	case "valid":
		result.State = "valid"
		result.ValidatedAt = timePointer(now)
		return result, nil
	case "pending":
	case "invalid", "deactivated", "expired", "revoked":
		return result, terminalf("authorization for %q is %q", result.Identifier, authorization.Status)
	default:
		return result, fmt.Errorf("certificateworker: unknown authorization status %q", authorization.Status)
	}
	result.State = "presenting"
	return result, nil
}

func (w *Worker) continueDNSCleanup(
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

func (w *Worker) cleanupFailedOrder(ctx context.Context, work *controlstate.ACMEOrderWork, now time.Time) error {
	if w.config.DNSChallenges == nil {
		return terminalf("DNS-01 challenge cleanup is not configured")
	}
	_, err := w.continueDNSCleanup(ctx, work, now)
	return err
}

func authorizationIdentifier(authorization acmeclient.Authorization) string {
	if authorization.Wildcard {
		return "*." + authorization.Identifier.Value
	}
	return authorization.Identifier.Value
}

func validateOrder(order acmeclient.Order, identifiers []string) error {
	if order.URL == "" || order.Status == "" || order.Finalize == "" {
		return errors.New("certificateworker: ACME order is incomplete")
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

func validateCertificate(certificatePEM, csrDER []byte, identifiers []string, now time.Time) (time.Time, time.Time, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil || csr.CheckSignature() != nil {
		return time.Time{}, time.Time{}, errors.New("CSR is invalid")
	}
	remaining := certificatePEM
	var certificates []*x509.Certificate
	for len(remaining) != 0 {
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return time.Time{}, time.Time{}, errors.New("certificate chain is not canonical PEM")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("parse certificate: %w", err)
		}
		certificates = append(certificates, certificate)
		remaining = rest
	}
	if len(certificates) == 0 {
		return time.Time{}, time.Time{}, errors.New("certificate chain is empty")
	}
	leaf := certificates[0]
	leafPublicKey, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("encode certificate public key: %w", err)
	}
	csrPublicKey, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil || !bytes.Equal(leafPublicKey, csrPublicKey) {
		return time.Time{}, time.Time{}, errors.New("certificate public key does not match the CSR")
	}
	actualIdentifiers := slices.Clone(leaf.DNSNames)
	expectedIdentifiers := slices.Clone(identifiers)
	slices.Sort(actualIdentifiers)
	slices.Sort(expectedIdentifiers)
	if !slices.Equal(actualIdentifiers, expectedIdentifiers) {
		return time.Time{}, time.Time{}, errors.New("certificate identifiers do not match the certificate plan")
	}
	if len(leaf.EmailAddresses) != 0 || len(leaf.IPAddresses) != 0 || len(leaf.URIs) != 0 || leaf.IsCA ||
		!certificateidentity.DNSNamesOnly(leaf.Extensions, leaf.DNSNames) {
		return time.Time{}, time.Time{}, errors.New("certificate contains an unsupported identity or constraint")
	}
	serverAuth := slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) ||
		slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageAny)
	if !serverAuth {
		return time.Time{}, time.Time{}, errors.New("certificate is not valid for TLS servers")
	}
	if !leaf.NotAfter.After(leaf.NotBefore) || leaf.NotBefore.After(now) || !leaf.NotAfter.After(now) {
		return time.Time{}, time.Time{}, errors.New("certificate validity period is invalid")
	}
	for index := 0; index+1 < len(certificates); index++ {
		if err := certificates[index].CheckSignatureFrom(certificates[index+1]); err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("verify certificate chain: %w", err)
		}
	}
	return leaf.NotBefore.UTC(), leaf.NotAfter.UTC(), nil
}

func accountKey(keyDER []byte) (*ecdsa.PrivateKey, error) {
	keyValue, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return nil, fmt.Errorf("certificateworker: parse ACME account key: %w", err)
	}
	key, ok := keyValue.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("certificateworker: ACME account key is not ECDSA")
	}
	return key, nil
}

func allAuthorizationsValid(authorizations []controlstate.ACMEAuthorizationWork) bool {
	return len(authorizations) != 0 && !slices.ContainsFunc(authorizations, func(value controlstate.ACMEAuthorizationWork) bool {
		return value.State != "valid"
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
	return slices.Equal(expected, actual)
}

type terminalError struct{ message string }

func (e *terminalError) Error() string { return e.message }

func terminalf(format string, arguments ...any) error {
	return &terminalError{message: fmt.Sprintf("certificateworker: "+format, arguments...)}
}

func truncateError(err error) string {
	value := err.Error()
	limit := min(len(value), 1024)
	for !utf8.ValidString(value[:limit]) {
		limit--
	}
	return value[:limit]
}

func timePointer(value time.Time) *time.Time {
	return &value
}
