package certificates

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	legoacme "github.com/go-acme/lego/v5/acme"
	legoapi "github.com/go-acme/lego/v5/acme/api"
	"github.com/tnldotdev/tnl/internal/naming"
)

type ProbeFunc func(context.Context, Issuance) error

type Config struct {
	DirectoryURL  string
	Email         string
	AcceptTerms   bool
	ACMEProfile   string
	HTTPClient    *http.Client
	Roots         *x509.CertPool
	Probe         ProbeFunc
	HostnameReady func(context.Context, string) error
	Now           func() time.Time

	newACME func(*http.Client, string, string, crypto.Signer) (acmeClient, error)
}

type Service struct {
	store         *store
	client        acmeClient
	acmeProfile   string
	roots         *x509.CertPool
	probe         ProbeFunc
	hostnameReady func(context.Context, string) error
	now           func() time.Time
	locks         [64]sync.Mutex
}

const retryDelay = 5 * time.Second

// New constructs the durable ACME service and reconciles its persisted account.
func New(ctx context.Context, db *sql.DB, config Config) (*Service, error) {
	if strings.TrimSpace(config.DirectoryURL) == "" || strings.TrimSpace(config.Email) == "" ||
		strings.TrimSpace(config.ACMEProfile) == "" || config.Probe == nil {
		return nil, errors.New("certificates: directory, email, acmeProfile, and probe are required")
	}
	directory, err := url.Parse(config.DirectoryURL)
	if err != nil || directory.Scheme != "https" || directory.Host == "" || directory.User != nil {
		return nil, errors.New("certificates: ACME directory must be HTTPS")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.HTTPClient == nil {
		config.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	stored, err := newStore(db, config.Now, config.DirectoryURL, config.ACMEProfile)
	if err != nil {
		return nil, err
	}
	accountState, signer, err := loadOrCreateAccount(ctx, stored, config.DirectoryURL, config.Email)
	if err != nil {
		return nil, err
	}
	newClient := config.newACME
	if newClient == nil {
		newClient = newLegoClient
	}
	client, err := newClient(config.HTTPClient, config.DirectoryURL, accountState.KID, signer)
	if err != nil {
		return nil, fmt.Errorf("certificates: load ACME directory: %w", err)
	}
	directoryMeta := client.Directory()
	terms := directoryMeta.Meta.TermsOfService
	if accountState.AcceptedTOS != terms && terms != "" && !config.AcceptTerms {
		return nil, errors.New("certificates: ACME terms changed; explicit operator acceptance is required")
	}
	if _, ok := directoryMeta.Meta.Profiles[config.ACMEProfile]; !ok {
		return nil, fmt.Errorf("certificates: ACME profile %q is not advertised", config.ACMEProfile)
	}
	if accountState.KID == "" {
		created, err := client.CreateAccount(ctx, legoacme.Account{
			Contact: []string{"mailto:" + config.Email}, TermsOfServiceAgreed: config.AcceptTerms,
		})
		if err != nil {
			return nil, fmt.Errorf("certificates: register ACME account: %w", err)
		}
		if created.Location == "" {
			return nil, errors.New("certificates: ACME account response omitted location")
		}
		accountState.KID = created.Location
	} else {
		accountValue, err := client.GetAccount(ctx, accountState.KID)
		if err != nil {
			return nil, fmt.Errorf("certificates: reconcile ACME account: %w", err)
		}
		if accountValue.Status != "" && accountValue.Status != legoacme.StatusValid {
			return nil, fmt.Errorf("certificates: ACME account status is %q", accountValue.Status)
		}
		desiredContact := []string{"mailto:" + config.Email}
		if !slices.Equal(accountValue.Contact, desiredContact) {
			if _, err := client.UpdateAccount(ctx, accountState.KID, legoacme.Account{Contact: desiredContact}); err != nil {
				return nil, fmt.Errorf("certificates: update ACME account contact: %w", err)
			}
		}
	}
	accountState.Email = config.Email
	accountState.AcceptedTOS = terms
	if err := stored.updateAccount(ctx, accountState); err != nil {
		return nil, err
	}
	return &Service{
		store: stored, client: client, acmeProfile: config.ACMEProfile, roots: config.Roots,
		probe: config.Probe, hostnameReady: config.HostnameReady, now: config.Now,
	}, nil
}

func (s *Service) Create(
	ctx context.Context,
	routeID string,
	version uint64,
	acmeProfile string,
	csrDER []byte,
) (Issuance, error) {
	if strings.TrimSpace(routeID) == "" || version == 0 || acmeProfile != s.acmeProfile {
		return Issuance{}, ErrInvalidArgument
	}
	lock := s.routeLock(routeID)
	lock.Lock()
	defer lock.Unlock()

	hostname, err := s.store.routeHostname(ctx, routeID, version)
	if err != nil {
		return Issuance{}, err
	}
	canonical, err := naming.CanonicalizeHostname(hostname)
	if err != nil || canonical != hostname {
		return Issuance{}, ErrInvalidArgument
	}
	_, csrHash, spkiHash, err := validateCSR(csrDER, hostname)
	if err != nil {
		return Issuance{}, err
	}

	issuance, err := s.store.findBoundIssuance(ctx, routeID, version, csrHash)
	if err == nil {
		return s.drive(ctx, issuance, false)
	}
	if !errors.Is(err, ErrNotFound) {
		return Issuance{}, err
	}

	issuance, err = s.store.findRebindableIssuance(ctx, routeID, csrHash, s.now(), s.now().Add(24*time.Hour))
	if err == nil {
		issuance, err = s.store.rebindIssuance(ctx, issuance, version)
		if err != nil {
			return Issuance{}, err
		}
		return s.drive(ctx, issuance, false)
	}
	if !errors.Is(err, ErrNotFound) {
		return Issuance{}, err
	}
	if err := s.store.allowIssuanceCreation(ctx, routeID, version, csrHash, s.now()); err != nil {
		return Issuance{}, err
	}
	if err := s.requireHostnameReady(ctx, hostname); err != nil {
		return Issuance{}, err
	}
	issuance, _, err = s.store.createIssuance(ctx, routeID, version, hostname, csrDER, csrHash, spkiHash)
	if err != nil {
		return Issuance{}, err
	}
	return s.drive(ctx, issuance, false)
}

func (s *Service) Get(ctx context.Context, id string) (Issuance, error) {
	return s.store.getIssuance(ctx, id)
}

func (s *Service) ChallengeReady(ctx context.Context, id string) (Issuance, error) {
	issuance, err := s.store.getCAIssuance(ctx, id)
	if err != nil {
		return Issuance{}, err
	}
	lock := s.routeLock(issuance.RouteID)
	lock.Lock()
	defer lock.Unlock()
	issuance, err = s.store.getCAIssuance(ctx, id)
	if err != nil {
		return Issuance{}, err
	}
	return s.drive(ctx, issuance, true)
}

func (s *Service) ChallengeRemoved(ctx context.Context, id string) (Issuance, error) {
	issuance, err := s.store.getIssuance(ctx, id)
	if err != nil {
		return Issuance{}, err
	}
	lock := s.routeLock(issuance.RouteID)
	lock.Lock()
	defer lock.Unlock()
	return s.store.removeChallenge(ctx, id)
}

func (s *Service) Installed(ctx context.Context, id, routeID string, version uint64) (Issuance, error) {
	issuance, err := s.store.getIssuance(ctx, id)
	if err != nil {
		return Issuance{}, err
	}
	lock := s.routeLock(issuance.RouteID)
	lock.Lock()
	defer lock.Unlock()
	return s.store.markInstalled(ctx, id, routeID, version)
}

func (s *Service) drive(ctx context.Context, issuance Issuance, challengeReady bool) (Issuance, error) {
	if issuance.DirectoryURL != s.store.directoryURL || issuance.ACMEProfile != s.acmeProfile {
		return Issuance{}, ErrInvalidStatus
	}
	switch issuance.Status {
	case StatusWaitingForInstall, StatusInstalled, StatusFailed:
		return issuance, nil
	case StatusCreatingOrder:
		if !issuance.OrderStartedAt.IsZero() && issuance.OrderURL == "" {
			return s.terminalFailure(ctx, issuance, "ACME order creation outcome is ambiguous; refusing to create a duplicate order")
		}
		if issuance.OrderURL != "" {
			return s.terminalFailure(ctx, issuance, "creating ACME order has inconsistent persisted state")
		}
	case StatusAuthorizing, StatusReadyToFinalize, StatusFinalizing:
		if !issuance.OrderExpires.IsZero() && !issuance.OrderExpires.After(s.now()) {
			return s.terminalFailure(ctx, issuance, "ACME order expired")
		}
	case StatusWaitingChallenge:
		if issuance.ChallengeURL == "" || issuance.ChallengeExpires.IsZero() {
			return Issuance{}, ErrInvalidStatus
		}
		if !issuance.ChallengeExpires.After(s.now()) {
			return s.reconcileExpiredChallenge(ctx, issuance)
		}
	default:
		return Issuance{}, ErrInvalidStatus
	}
	if issuance.RetryAt.After(s.now()) {
		return issuance, nil
	}
	switch issuance.Status {
	case StatusCreatingOrder:
		return s.createOrder(ctx, issuance)
	case StatusAuthorizing:
		return s.authorize(ctx, issuance)
	case StatusWaitingChallenge:
		if !challengeReady {
			return issuance, nil
		}
		return s.completeChallenge(ctx, issuance)
	case StatusReadyToFinalize:
		return s.finalize(ctx, issuance)
	case StatusFinalizing:
		return s.reconcileFinalization(ctx, issuance)
	default:
		return issuance, nil
	}
}

func (s *Service) createOrder(ctx context.Context, issuance Issuance) (Issuance, error) {
	issuance.OrderStartedAt = s.now().UTC()
	issuance.RetryAt = time.Time{}
	issuance.LastError = ""
	if err := s.store.saveIssuance(ctx, issuance); err != nil {
		return Issuance{}, err
	}
	order, err := s.client.CreateOrder(ctx, []string{issuance.Hostname}, &legoapi.OrderOptions{Profile: issuance.ACMEProfile})
	if err != nil {
		return s.recordFailure(ctx, issuance, "create ACME order", err, true)
	}
	if order.Location == "" || order.Finalize == "" || len(order.Authorizations) != 1 || order.Profile != issuance.ACMEProfile {
		return s.terminalFailure(ctx, issuance, "ACME order response is incomplete")
	}
	issuance.OrderURL = order.Location
	issuance.FinalizeURL = order.Finalize
	if order.Expires != "" {
		issuance.OrderExpires, err = time.Parse(time.RFC3339, order.Expires)
		if err != nil {
			return s.terminalFailure(ctx, issuance, "ACME order expiry is invalid")
		}
	}
	issuance.AuthorizationURL = order.Authorizations[0]
	issuance.Status = StatusAuthorizing
	issuance.LastError = ""
	issuance.RetryAt = time.Time{}
	return s.persist(ctx, issuance)
}

func (s *Service) authorize(ctx context.Context, issuance Issuance) (Issuance, error) {
	if issuance.AuthorizationURL == "" {
		return s.terminalFailure(ctx, issuance, "ACME authorization URL is missing")
	}
	authorization, err := s.client.GetAuthorization(ctx, issuance.AuthorizationURL)
	if err != nil {
		return s.recordFailure(ctx, issuance, "read ACME authorization", err, false)
	}
	if err := validateAuthorization(authorization, issuance.Hostname); err != nil {
		return s.terminalFailure(ctx, issuance, err.Error())
	}
	switch authorization.Status {
	case legoacme.StatusValid:
		issuance.Status = StatusReadyToFinalize
		issuance.RetryAt = time.Time{}
		issuance.LastError = ""
		return s.persist(ctx, issuance)
	case legoacme.StatusPending:
		challenge, digest, expires, err := s.challengeMaterial(authorization)
		if err != nil {
			return s.terminalFailure(ctx, issuance, err.Error())
		}
		if !expires.After(s.now()) {
			return s.terminalFailure(ctx, issuance, "ACME authorization is expired")
		}
		issuance.Status = StatusWaitingChallenge
		issuance.ChallengeURL = challenge.URL
		issuance.ChallengeDigest = digest
		issuance.ChallengeExpires = expires
		issuance.RetryAt = time.Time{}
		issuance.LastError = ""
		return s.persist(ctx, issuance)
	default:
		return s.terminalFailure(ctx, issuance, "ACME authorization is not pending or valid")
	}
}

func (s *Service) completeChallenge(ctx context.Context, issuance Issuance) (Issuance, error) {
	if err := s.probe(ctx, issuance); err != nil {
		return s.recordFailure(ctx, issuance, "probe routed TLS-ALPN challenge", err, false)
	}
	authorization, err := s.client.GetAuthorization(ctx, issuance.AuthorizationURL)
	if err != nil {
		return s.recordFailure(ctx, issuance, "reconcile ACME authorization", err, false)
	}
	if err := validateAuthorization(authorization, issuance.Hostname); err != nil {
		return s.terminalFailure(ctx, issuance, err.Error())
	}
	challenge, digest, _, err := s.challengeMaterial(authorization)
	if err != nil {
		return s.terminalFailure(ctx, issuance, err.Error())
	}
	if challenge.URL != issuance.ChallengeURL || digest != issuance.ChallengeDigest {
		return s.terminalFailure(ctx, issuance, "ACME TLS-ALPN-01 challenge changed")
	}
	switch authorization.Status {
	case legoacme.StatusValid:
		issuance.Status = StatusReadyToFinalize
		issuance.RetryAt = time.Time{}
		issuance.LastError = ""
		return s.persist(ctx, issuance)
	case legoacme.StatusProcessing:
		return s.persistRetry(ctx, issuance, retryDelay)
	case legoacme.StatusPending:
		switch challenge.Status {
		case legoacme.StatusPending:
			hostname, err := s.store.routeHostname(ctx, issuance.RouteID, issuance.RouteVersion)
			if err != nil {
				return Issuance{}, err
			}
			if hostname != issuance.Hostname {
				return Issuance{}, ErrInvalidStatus
			}
			accepted, err := s.client.AcceptChallenge(ctx, issuance.ChallengeURL)
			if err != nil {
				return s.recordFailure(ctx, issuance, "accept ACME challenge", err, false)
			}
			delay := accepted.RetryAfter
			if delay <= 0 {
				delay = retryDelay
			}
			return s.persistRetry(ctx, issuance, delay)
		case legoacme.StatusProcessing, legoacme.StatusValid:
			return s.persistRetry(ctx, issuance, retryDelay)
		case legoacme.StatusInvalid:
			return s.terminalFailure(ctx, issuance, "ACME TLS-ALPN-01 challenge became invalid")
		default:
			return s.terminalFailure(ctx, issuance, "ACME TLS-ALPN-01 challenge has an invalid status")
		}
	default:
		return s.terminalFailure(ctx, issuance, "ACME authorization became invalid")
	}
}

func (s *Service) reconcileExpiredChallenge(ctx context.Context, issuance Issuance) (Issuance, error) {
	authorization, err := s.client.GetAuthorization(ctx, issuance.AuthorizationURL)
	if err != nil {
		return s.recordFailure(ctx, issuance, "reconcile expired ACME authorization", err, false)
	}
	if err := validateAuthorization(authorization, issuance.Hostname); err != nil {
		return s.terminalFailure(ctx, issuance, err.Error())
	}
	if authorization.Status != legoacme.StatusValid {
		return s.terminalFailure(ctx, issuance, "ACME authorization challenge expired")
	}
	issuance.Status = StatusReadyToFinalize
	issuance.RetryAt = time.Time{}
	issuance.LastError = ""
	return s.persist(ctx, issuance)
}

func (s *Service) finalize(ctx context.Context, issuance Issuance) (Issuance, error) {
	order, err := s.client.GetOrder(ctx, issuance.OrderURL)
	if err != nil {
		return s.recordFailure(ctx, issuance, "reconcile ACME order", err, false)
	}
	if err := validateOrder(order, issuance.OrderURL, issuance.ACMEProfile); err != nil {
		return s.terminalFailure(ctx, issuance, err.Error())
	}
	switch order.Status {
	case legoacme.StatusPending, legoacme.StatusProcessing:
		return s.persistRetry(ctx, issuance, retryDelay)
	case legoacme.StatusValid:
		return s.downloadOrderCertificate(ctx, issuance, order)
	case legoacme.StatusReady:
		issuance.Status = StatusFinalizing
		issuance.RetryAt = time.Time{}
		issuance.LastError = ""
		var err error
		issuance, err = s.persist(ctx, issuance)
		if err != nil {
			return Issuance{}, err
		}
		order, err = s.client.FinalizeOrder(ctx, issuance.FinalizeURL, issuance.CSRDER)
		if err != nil {
			var limited *legoacme.RateLimitedError
			var problem *legoacme.ProblemDetails
			if errors.As(err, &limited) || errors.As(err, &problem) &&
				(problem.Type == legoacme.BadNonceErrorType || problem.HTTPStatus == http.StatusTooManyRequests) {
				issuance.Status = StatusReadyToFinalize
			}
			return s.recordFailure(ctx, issuance, "finalize ACME order", err, false)
		}
		if err := validateOrder(order, issuance.OrderURL, issuance.ACMEProfile); err != nil {
			return s.terminalFailure(ctx, issuance, err.Error())
		}
		switch order.Status {
		case legoacme.StatusValid:
			return s.downloadOrderCertificate(ctx, issuance, order)
		case legoacme.StatusPending, legoacme.StatusProcessing, legoacme.StatusReady:
			return s.persistRetry(ctx, issuance, retryDelay)
		default:
			return s.terminalFailure(ctx, issuance, "ACME finalization was rejected")
		}
	default:
		return s.terminalFailure(ctx, issuance, "ACME order cannot be finalized")
	}
}

func (s *Service) reconcileFinalization(ctx context.Context, issuance Issuance) (Issuance, error) {
	order, err := s.client.GetOrder(ctx, issuance.OrderURL)
	if err != nil {
		return s.recordFailure(ctx, issuance, "reconcile finalized ACME order", err, false)
	}
	if err := validateOrder(order, issuance.OrderURL, issuance.ACMEProfile); err != nil {
		return s.terminalFailure(ctx, issuance, err.Error())
	}
	switch order.Status {
	case legoacme.StatusValid:
		return s.downloadOrderCertificate(ctx, issuance, order)
	case legoacme.StatusPending, legoacme.StatusProcessing, legoacme.StatusReady:
		return s.persistRetry(ctx, issuance, retryDelay)
	default:
		return s.terminalFailure(ctx, issuance, "ACME finalized order became invalid")
	}
}

func (s *Service) downloadOrderCertificate(
	ctx context.Context,
	issuance Issuance,
	order legoacme.ExtendedOrder,
) (Issuance, error) {
	if order.Certificate == "" {
		return s.terminalFailure(ctx, issuance, "ACME valid order omitted its certificate URL")
	}
	issuance.CertificateURL = order.Certificate
	issuance.RetryAt = time.Time{}
	issuance.LastError = ""
	var err error
	issuance, err = s.persist(ctx, issuance)
	if err != nil {
		return Issuance{}, err
	}
	raw, err := s.client.GetCertificate(ctx, issuance.CertificateURL)
	if err != nil {
		return s.recordFailure(ctx, issuance, "download ACME certificate", err, false)
	}
	if raw == nil {
		return s.terminalFailure(ctx, issuance, "ACME certificate response is empty")
	}
	certificatePEM := raw.Cert
	if len(raw.Issuer) != 0 && !bytes.HasSuffix(certificatePEM, raw.Issuer) {
		certificatePEM = append(bytes.Clone(certificatePEM), raw.Issuer...)
	}
	validated, leaf, err := validateCertificateChain(certificatePEM, issuance.Hostname, issuance.SPKIHash, s.now(), s.roots)
	if err != nil {
		return s.terminalFailure(ctx, issuance, err.Error())
	}
	issuance.Status = StatusWaitingForInstall
	issuance.CertificatePEM = validated
	issuance.NotBefore = leaf.NotBefore.UTC()
	issuance.NotAfter = leaf.NotAfter.UTC()
	issuance.RenewAt = renewalTime(issuance.ID, issuance.NotBefore, issuance.NotAfter)
	issuance.RetryAt = time.Time{}
	issuance.LastError = ""
	return s.persist(ctx, issuance)
}

func (s *Service) challengeMaterial(
	authorization legoacme.Authorization,
) (legoacme.Challenge, [sha256.Size]byte, time.Time, error) {
	challenge, err := tlsALPNChallenge(authorization)
	if err != nil {
		return legoacme.Challenge{}, [sha256.Size]byte{}, time.Time{}, err
	}
	keyAuthorization, err := s.client.KeyAuthorization(challenge.Token)
	if err != nil {
		return legoacme.Challenge{}, [sha256.Size]byte{}, time.Time{}, errors.New("derive ACME key authorization")
	}
	expires := authorization.Expires
	if expires.IsZero() {
		expires = s.now().Add(defaultChallengeTimeout)
	}
	return challenge, sha256.Sum256([]byte(keyAuthorization)), expires.UTC(), nil
}

func tlsALPNChallenge(authorization legoacme.Authorization) (legoacme.Challenge, error) {
	for _, challenge := range authorization.Challenges {
		if challenge.Type == tlsALPNChallengeType {
			if challenge.URL == "" || challenge.Token == "" {
				break
			}
			return challenge, nil
		}
	}
	return legoacme.Challenge{}, errors.New("ACME authorization omitted TLS-ALPN-01")
}

func validateAuthorization(authorization legoacme.Authorization, hostname string) error {
	if authorization.Identifier.Type != "dns" || authorization.Identifier.Value != hostname || authorization.Wildcard {
		return errors.New("ACME authorization changed the identifier")
	}
	return nil
}

func validateOrder(order legoacme.ExtendedOrder, orderURL, acmeProfile string) error {
	if order.Location != "" && order.Location != orderURL {
		return errors.New("ACME order response changed its URL")
	}
	if order.Profile != "" && order.Profile != acmeProfile {
		return errors.New("ACME order response changed its profile")
	}
	return nil
}

func (s *Service) persistRetry(ctx context.Context, issuance Issuance, delay time.Duration) (Issuance, error) {
	issuance.RetryAt = s.now().Add(delay).UTC()
	issuance.LastError = ""
	return s.persist(ctx, issuance)
}

func (s *Service) persist(ctx context.Context, issuance Issuance) (Issuance, error) {
	if err := s.store.saveIssuance(ctx, issuance); err != nil {
		return Issuance{}, err
	}
	return s.store.getIssuance(ctx, issuance.ID)
}

func (s *Service) recordFailure(
	ctx context.Context,
	issuance Issuance,
	operation string,
	cause error,
	orderCreation bool,
) (Issuance, error) {
	if ctx.Err() != nil {
		if context.Cause(ctx) != nil {
			return Issuance{}, context.Cause(ctx)
		}
		return Issuance{}, ctx.Err()
	}
	issuance.LastError = boundedError(fmt.Errorf("%s: %w", operation, cause))

	var limited *legoacme.RateLimitedError
	if errors.As(cause, &limited) {
		if orderCreation {
			issuance.OrderStartedAt = time.Time{}
		}
		delay := limited.RetryAfter
		if delay <= 0 {
			delay = retryDelay
		}
		issuance.RetryAt = s.now().Add(delay).UTC()
		if _, err := s.persist(ctx, issuance); err != nil {
			return Issuance{}, err
		}
		return Issuance{}, &RateLimitError{RetryAt: issuance.RetryAt}
	}

	var problem *legoacme.ProblemDetails
	if errors.As(cause, &problem) {
		if problem.Type == legoacme.BadNonceErrorType {
			if orderCreation {
				issuance.OrderStartedAt = time.Time{}
			}
			issuance.RetryAt = s.now().Add(retryDelay).UTC()
			if _, err := s.persist(ctx, issuance); err != nil {
				return Issuance{}, err
			}
			return Issuance{}, fmt.Errorf("%w: %s", ErrUnavailable, issuance.LastError)
		}
		if problem.HTTPStatus == http.StatusTooManyRequests {
			if orderCreation {
				issuance.OrderStartedAt = time.Time{}
			}
			issuance.RetryAt = s.now().Add(retryDelay).UTC()
			if _, err := s.persist(ctx, issuance); err != nil {
				return Issuance{}, err
			}
			return Issuance{}, &RateLimitError{RetryAt: issuance.RetryAt}
		}
		if problem.HTTPStatus >= http.StatusBadRequest && problem.HTTPStatus < http.StatusInternalServerError {
			return s.terminalFailure(ctx, issuance, issuance.LastError)
		}
	}

	issuance.RetryAt = s.now().Add(retryDelay).UTC()
	if _, err := s.persist(ctx, issuance); err != nil {
		return Issuance{}, err
	}
	return Issuance{}, fmt.Errorf("%w: %s", ErrUnavailable, issuance.LastError)
}

func (s *Service) terminalFailure(ctx context.Context, issuance Issuance, message string) (Issuance, error) {
	issuance.Status = StatusFailed
	issuance.LastError = boundedError(errors.New(message))
	issuance.RetryAt = time.Time{}
	return s.persist(ctx, issuance)
}

func (s *Service) requireHostnameReady(ctx context.Context, hostname string) error {
	if s.hostnameReady == nil {
		return nil
	}
	if err := s.hostnameReady(ctx, hostname); err != nil {
		if ctx.Err() != nil {
			if context.Cause(ctx) != nil {
				return context.Cause(ctx)
			}
			return ctx.Err()
		}
		return fmt.Errorf("%w: hostname DNS is not ready: %v", ErrUnavailable, err)
	}
	return nil
}

func loadOrCreateAccount(
	ctx context.Context,
	store *store,
	directoryURL, email string,
) (account, crypto.Signer, error) {
	value, err := store.loadAccount(ctx, directoryURL)
	if errors.Is(err, ErrNotFound) {
		key, keyErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if keyErr != nil {
			return account{}, nil, keyErr
		}
		keyDER, keyErr := x509.MarshalPKCS8PrivateKey(key)
		if keyErr != nil {
			return account{}, nil, keyErr
		}
		if err := store.insertAccount(ctx, account{DirectoryURL: directoryURL, Email: email, KeyDER: keyDER}); err != nil {
			return account{}, nil, err
		}
		value, err = store.loadAccount(ctx, directoryURL)
	}
	if err != nil {
		return account{}, nil, err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(value.KeyDER)
	if err != nil {
		return account{}, nil, fmt.Errorf("certificates: parse ACME account key: %w", err)
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return account{}, nil, errors.New("certificates: ACME account key is not a signer")
	}
	return value, signer, nil
}

func boundedError(err error) string {
	if err == nil {
		return ""
	}
	message := err.Error()
	if len(message) > 1024 {
		message = message[:1024]
	}
	return message
}

func (s *Service) routeLock(routeID string) *sync.Mutex {
	var hash uint32 = 2166136261
	for index := range len(routeID) {
		hash ^= uint32(routeID[index])
		hash *= 16777619
	}
	return &s.locks[hash%uint32(len(s.locks))]
}
