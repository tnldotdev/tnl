package relaycertificateworker

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
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

const (
	defaultLeaseDuration       = 2 * time.Minute
	defaultOperationTimeout    = 30 * time.Second
	defaultPollInterval        = 2 * time.Second
	defaultIdleInterval        = 500 * time.Millisecond
	defaultRenewBefore         = 30 * 24 * time.Hour
	defaultFailedRetryInterval = time.Hour
)

type Store interface {
	PrepareRelayCertificateOrder(context.Context, string, time.Time, time.Time, time.Duration) (bool, error)
	ClaimRelayCertificateOrderWork(context.Context, string, time.Time, time.Duration) (controlstate.RelayCertificateOrderWork, bool, error)
	SaveRelayCertificateOrderWork(context.Context, controlstate.RelayCertificateOrderWork, time.Time) (controlstate.RelayCertificateOrderWork, error)
}

type DNSChallenges interface {
	Present(context.Context, string) error
	Verify(context.Context, string) (bool, error)
	Cleanup(context.Context, string) error
}

type Config struct {
	WorkerID            string
	AccountID           string
	Profile             string
	HTTPClient          *http.Client
	DNSChallenges       DNSChallenges
	Logger              *slog.Logger
	LeaseDuration       time.Duration
	OperationTimeout    time.Duration
	PollInterval        time.Duration
	IdleInterval        time.Duration
	RenewBefore         time.Duration
	FailedRetryInterval time.Duration
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
	if store == nil || !validText(config.WorkerID) || !validText(config.AccountID) || !validText(config.Profile) ||
		config.HTTPClient == nil || config.DNSChallenges == nil {
		return nil, errors.New("relaycertificateworker: invalid configuration")
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
	if config.RenewBefore <= 0 {
		config.RenewBefore = defaultRenewBefore
	}
	if config.FailedRetryInterval <= 0 {
		config.FailedRetryInterval = defaultFailedRetryInterval
	}
	if config.OperationTimeout >= config.LeaseDuration {
		return nil, errors.New("relaycertificateworker: operation timeout must be shorter than the work lease")
	}
	worker := &Worker{store: store, config: config, now: func() time.Time { return time.Now().UTC() }}
	worker.client = func(account controlstate.ACMEAccount) (acmeAPI, error) {
		value, err := x509.ParsePKCS8PrivateKey(account.AccountKeyDER)
		if err != nil {
			return nil, fmt.Errorf("relaycertificateworker: parse ACME account key: %w", err)
		}
		key, ok := value.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("relaycertificateworker: ACME account key is not ECDSA")
		}
		return acmeclient.New(config.HTTPClient, account.DirectoryURL, key, account.AccountURL)
	}
	return worker, nil
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
			w.config.Logger.Error("relay certificate worker iteration failed", "error", err)
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
	if _, err := w.store.PrepareRelayCertificateOrder(
		ctx, w.config.AccountID, now, now.Add(w.config.RenewBefore), w.config.FailedRetryInterval,
	); err != nil {
		return false, err
	}
	work, found, err := w.store.ClaimRelayCertificateOrderWork(ctx, w.config.WorkerID, now, w.config.LeaseDuration)
	if err != nil || !found {
		return found, err
	}
	client, err := w.client(work.Account)
	if err == nil && work.Account.AccountURL == "" {
		err = errors.New("relaycertificateworker: ACME account is not registered")
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
	if _, saveErr := w.store.SaveRelayCertificateOrderWork(ctx, work, completedAt); saveErr != nil {
		return true, saveErr
	}
	return true, nil
}

func (w *Worker) advance(ctx context.Context, client acmeAPI, work *controlstate.RelayCertificateOrderWork, now time.Time) error {
	work.LastError = ""
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

func (w *Worker) authorize(ctx context.Context, client acmeAPI, work *controlstate.RelayCertificateOrderWork, now time.Time) error {
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
		keyAuthorization, err := client.KeyAuthorization(challenge.Token)
		if err != nil {
			return err
		}
		work.AuthorizationURL = authorization.URL
		work.ChallengeURL = challenge.URL
		work.ChallengeToken = challenge.Token
		work.ChallengeDigest = sha256.Sum256([]byte(keyAuthorization))
		work.PresentationReference, err = opaqueid.New("relay_acme_presentation_")
		if err != nil {
			return err
		}
		work.State = "presenting"
		work.AvailableAt = now
		return nil
	}
	return terminalf("ACME authorization has no DNS-01 challenge")
}

func (w *Worker) validateAuthorization(
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
		return fmt.Errorf("relaycertificateworker: unknown authorization status %q", authorization.Status)
	}
	return nil
}

func (w *Worker) finalize(ctx context.Context, client acmeAPI, work *controlstate.RelayCertificateOrderWork, now time.Time) error {
	order, err := client.GetOrder(ctx, work.OrderURL)
	if err != nil {
		return err
	}
	if err := validateOrder(order, work.TLSServerName); err != nil {
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
		return fmt.Errorf("relaycertificateworker: unknown order status %q", order.Status)
	}
}

func (w *Worker) collect(ctx context.Context, client acmeAPI, work *controlstate.RelayCertificateOrderWork, now time.Time) error {
	order, err := client.GetOrder(ctx, work.OrderURL)
	if err != nil {
		return err
	}
	if err := validateOrder(order, work.TLSServerName); err != nil {
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
			return errors.New("relaycertificateworker: valid order has no certificate URL")
		}
		certificatePEM, err := client.DownloadCertificate(ctx, order.Certificate)
		if err != nil {
			return err
		}
		notBefore, notAfter, err := validateCertificate(certificatePEM, work.CSRDER, work.TLSServerName, now)
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
		return fmt.Errorf("relaycertificateworker: unknown order status %q", order.Status)
	}
	return nil
}

func (w *Worker) applyOrder(work *controlstate.RelayCertificateOrderWork, order acmeclient.Order, now time.Time) error {
	if err := validateOrder(order, work.TLSServerName); err != nil {
		return err
	}
	work.OrderURL, work.FinalizeURL, work.CertificateURL = order.URL, order.Finalize, order.Certificate
	switch order.Status {
	case "pending":
		work.State = "authorizing"
	case "ready":
		work.State = "ready_to_finalize"
	case "processing", "valid":
		work.State = "finalizing"
	case "invalid":
		return terminalf("ACME order became invalid")
	default:
		return fmt.Errorf("relaycertificateworker: unknown order status %q", order.Status)
	}
	work.AvailableAt = pollAt(now, w.config.PollInterval, order.RetryAfter)
	if work.State == "ready_to_finalize" || order.Status == "valid" {
		work.AvailableAt = now
	}
	return nil
}

func (w *Worker) applyFailure(work *controlstate.RelayCertificateOrderWork, operationErr error, now time.Time) {
	work.LastError = truncateError(operationErr)
	work.AvailableAt = now.Add(5 * time.Second)
	if work.State == "failed_cleaning" {
		return
	}
	var acmeError *acmeclient.Error
	var terminal *terminalError
	if errors.As(operationErr, &acmeError) && !acmeError.RetryAfter.IsZero() {
		work.AvailableAt = acmeError.RetryAfter
	}
	if errors.As(operationErr, &terminal) || errors.As(operationErr, &acmeError) && acmeError.Terminal() {
		if work.ChallengeURL != "" {
			work.State = "failed_cleaning"
			work.AvailableAt = now
		} else {
			work.State = "failed"
			work.AvailableAt = now.Add(w.config.FailedRetryInterval)
		}
	}
}

func validateOrder(order acmeclient.Order, hostname string) error {
	if order.URL == "" || order.Status == "" || order.Finalize == "" || len(order.Identifiers) != 1 ||
		order.Identifiers[0].Type != "dns" || order.Identifiers[0].Value != hostname {
		return terminalf("ACME order identity does not match the relay service")
	}
	return nil
}

func validateCertificate(certificatePEM, csrDER []byte, hostname string, now time.Time) (time.Time, time.Time, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil || csr.CheckSignature() != nil {
		return time.Time{}, time.Time{}, errors.New("CSR is invalid")
	}
	remaining := certificatePEM
	certificates := []*x509.Certificate(nil)
	for len(remaining) != 0 {
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return time.Time{}, time.Time{}, errors.New("certificate chain is not canonical PEM")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return time.Time{}, time.Time{}, err
		}
		certificates = append(certificates, certificate)
		remaining = rest
	}
	if len(certificates) == 0 {
		return time.Time{}, time.Time{}, errors.New("certificate chain is empty")
	}
	leaf := certificates[0]
	leafKey, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	csrKey, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil || !bytes.Equal(leafKey, csrKey) || !slices.Equal(leaf.DNSNames, []string{hostname}) ||
		!certificateidentity.DNSNamesOnly(leaf.Extensions, leaf.DNSNames) || len(leaf.EmailAddresses) != 0 ||
		len(leaf.IPAddresses) != 0 || len(leaf.URIs) != 0 || leaf.IsCA || leaf.VerifyHostname(hostname) != nil {
		return time.Time{}, time.Time{}, errors.New("certificate identity is invalid")
	}
	if !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) && !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageAny) {
		return time.Time{}, time.Time{}, errors.New("certificate is not valid for TLS servers")
	}
	if !leaf.NotAfter.After(leaf.NotBefore) || leaf.NotBefore.After(now) || !leaf.NotAfter.After(now) {
		return time.Time{}, time.Time{}, errors.New("certificate validity period is invalid")
	}
	for index := 0; index+1 < len(certificates); index++ {
		if err := certificates[index].CheckSignatureFrom(certificates[index+1]); err != nil {
			return time.Time{}, time.Time{}, err
		}
	}
	return leaf.NotBefore.UTC(), leaf.NotAfter.UTC(), nil
}

func pollAt(now time.Time, interval time.Duration, retryAfter time.Time) time.Time {
	result := now.Add(interval)
	if retryAfter.After(result) {
		return retryAfter.UTC()
	}
	return result
}

type terminalError struct{ message string }

func (e *terminalError) Error() string { return e.message }

func terminalf(format string, arguments ...any) error {
	return &terminalError{message: fmt.Sprintf("relaycertificateworker: "+format, arguments...)}
}

func truncateError(err error) string {
	value := err.Error()
	limit := min(len(value), 1024)
	for !utf8.ValidString(value[:limit]) {
		limit--
	}
	return value[:limit]
}

func validText(value string) bool {
	return value != "" && len(value) <= 256 && strings.TrimSpace(value) == value
}
