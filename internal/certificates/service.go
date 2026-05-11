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
	stored, err := newStore(db, config.Now)
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
	lock := s.routeLock(routeID)
	lock.Lock()
	defer lock.Unlock()
	hostname, err := s.store.routeHostname(ctx, routeID, version)
	if err != nil {
		return Issuance{}, err
	}
	canonical, err := naming.CanonicalizeHostname(hostname)
	if err != nil || canonical != hostname || strings.TrimSpace(routeID) == "" || version == 0 || acmeProfile != s.acmeProfile {
		return Issuance{}, ErrInvalidArgument
	}
	if s.hostnameReady != nil {
		if err := s.hostnameReady(ctx, hostname); err != nil {
			return Issuance{}, ErrUnavailable
		}
	}
	_, csrHash, spkiHash, err := validateCSR(csrDER, hostname)
	if err != nil {
		return Issuance{}, err
	}
	// Recover bound or resumable work before allocating another ACME order.
	issuance, err := s.store.findBoundIssuance(ctx, routeID, version, csrHash)
	created := false
	if errors.Is(err, ErrNotFound) {
		resumable, resumeErr := s.store.findResumableIssuance(ctx, routeID, csrHash, s.now())
		if resumeErr == nil {
			issuance, err = s.store.rebindIssuance(ctx, resumable.ID, version)
			if err != nil {
				return Issuance{}, err
			}
			return s.continueIssuance(ctx, issuance)
		}
		if !errors.Is(resumeErr, ErrNotFound) {
			return Issuance{}, resumeErr
		}
		if err := s.store.allowIssuanceCreation(ctx, routeID, version, csrHash, s.now()); err != nil {
			return Issuance{}, err
		}
		issuance, created, err = s.store.createIssuance(
			ctx, routeID, version, hostname, acmeProfile, csrDER, csrHash, spkiHash,
		)
	}
	if err != nil {
		return Issuance{}, err
	}
	if !created {
		return s.continueIssuance(ctx, issuance)
	}
	if created {
		reusable, reuseErr := s.store.findReusableIssuance(ctx, routeID, csrHash, s.now().Add(24*time.Hour))
		if reuseErr == nil && reusable.RenewAt.After(s.now()) {
			issuance.Status = StatusWaitingForInstall
			issuance.CertificateURL = reusable.CertificateURL
			issuance.CertificatePEM = bytes.Clone(reusable.CertificatePEM)
			issuance.NotBefore = reusable.NotBefore
			issuance.NotAfter = reusable.NotAfter
			issuance.RenewAt = reusable.RenewAt
			issuance.ChallengeRemoved = s.now()
			if err := s.store.saveIssuance(ctx, issuance); err != nil {
				return Issuance{}, err
			}
			return s.store.getIssuance(ctx, issuance.ID)
		}
		if reuseErr != nil && !errors.Is(reuseErr, ErrNotFound) {
			return Issuance{}, reuseErr
		}
	}
	return s.createOrder(ctx, issuance)
}

func (s *Service) continueIssuance(ctx context.Context, issuance Issuance) (Issuance, error) {
	if issuance.RetryAt.After(s.now()) {
		return issuance, nil
	}
	switch issuance.Status {
	case StatusCreatingOrder:
		return s.createOrder(ctx, issuance)
	case StatusAuthorizing:
		return s.prepareAuthorization(ctx, issuance)
	case StatusReadyToFinalize, StatusFinalizing, StatusDownloading:
		return s.advance(ctx, issuance)
	default:
		return issuance, nil
	}
}

func (s *Service) Get(ctx context.Context, id string) (Issuance, error) {
	return s.store.getIssuance(ctx, id)
}

func (s *Service) ChallengeReady(ctx context.Context, id string) (Issuance, error) {
	issuance, err := s.store.getIssuance(ctx, id)
	if err != nil {
		return Issuance{}, err
	}
	lock := s.routeLock(issuance.RouteID)
	lock.Lock()
	defer lock.Unlock()
	issuance, err = s.store.getIssuance(ctx, id)
	if err != nil {
		return Issuance{}, err
	}
	if issuance.Status == StatusWaitingForInstall || issuance.Status == StatusInstalled {
		return issuance, nil
	}
	if issuance.RetryAt.After(s.now()) {
		return Issuance{}, ErrUnavailable
	}
	if err := s.ensureCurrent(ctx, issuance); err != nil {
		return Issuance{}, err
	}
	if issuance.ChallengeURL == "" || !issuance.ChallengeExpires.After(s.now()) {
		return Issuance{}, ErrInvalidStatus
	}
	if err := s.probe(ctx, issuance); err != nil {
		issuance.LastError = boundedError(err)
		issuance.RetryAt = s.now().Add(5 * time.Second)
		_ = s.store.saveIssuance(ctx, issuance)
		return Issuance{}, fmt.Errorf("%w: routed TLS-ALPN probe: %v", ErrUnavailable, err)
	}
	// The probe may outlive this route version.
	if err := s.ensureCurrent(ctx, issuance); err != nil {
		return Issuance{}, err
	}
	return s.advance(ctx, issuance)
}

func (s *Service) ChallengeRemoved(ctx context.Context, id string) (Issuance, error) {
	issuance, err := s.store.getIssuance(ctx, id)
	if err != nil {
		return Issuance{}, err
	}
	lock := s.routeLock(issuance.RouteID)
	lock.Lock()
	defer lock.Unlock()
	issuance, err = s.store.getIssuance(ctx, id)
	if err != nil {
		return Issuance{}, err
	}
	if len(issuance.CertificatePEM) == 0 {
		return Issuance{}, ErrInvalidStatus
	}
	if err := s.ensureCurrent(ctx, issuance); err != nil {
		return Issuance{}, err
	}
	issuance.ChallengeRemoved = s.now()
	issuance.LastError = ""
	if err := s.store.saveIssuance(ctx, issuance); err != nil {
		return Issuance{}, err
	}
	return s.store.getIssuance(ctx, id)
}

func (s *Service) Installed(ctx context.Context, id, routeID string, version uint64) (Issuance, error) {
	issuance, err := s.store.getIssuance(ctx, id)
	if err != nil {
		return Issuance{}, err
	}
	lock := s.routeLock(issuance.RouteID)
	lock.Lock()
	defer lock.Unlock()
	issuance, err = s.store.getIssuance(ctx, id)
	if err != nil {
		return Issuance{}, err
	}
	if issuance.RouteID != routeID || issuance.Version != version || len(issuance.CertificatePEM) == 0 ||
		issuance.Status != StatusWaitingForInstall && issuance.Status != StatusInstalled || issuance.ChallengeRemoved.IsZero() {
		return Issuance{}, ErrInvalidStatus
	}
	if err := s.ensureCurrent(ctx, issuance); err != nil {
		return Issuance{}, err
	}
	issuance.Status = StatusInstalled
	issuance.InstalledAt = s.now()
	issuance.LastError = ""
	if err := s.store.saveIssuance(ctx, issuance); err != nil {
		return Issuance{}, err
	}
	return s.store.getIssuance(ctx, id)
}

func (s *Service) createOrder(ctx context.Context, issuance Issuance) (Issuance, error) {
	// A missing response URL makes blind retries risk duplicate orders.
	if issuance.OrderAttempts != 0 {
		issuance.Status = StatusBlocked
		issuance.LastError = "ACME order creation outcome is ambiguous; refusing to create a duplicate order"
		if err := s.store.saveIssuance(ctx, issuance); err != nil {
			return Issuance{}, err
		}
		return Issuance{}, fmt.Errorf("%w: %s", ErrInvalidStatus, issuance.LastError)
	}
	issuance.OrderAttempts++
	issuance.RetryAt = time.Time{}
	if err := s.store.saveIssuance(ctx, issuance); err != nil {
		return Issuance{}, err
	}
	order, err := s.client.CreateOrder(ctx, []string{issuance.Hostname}, &legoapi.OrderOptions{Profile: issuance.ACMEProfile})
	if err != nil {
		return s.createOrderFailure(ctx, issuance, err)
	}
	if order.Location == "" || order.Finalize == "" || len(order.Authorizations) != 1 || order.Profile != issuance.ACMEProfile {
		return s.terminalFailure(ctx, issuance, "ACME order response is incomplete")
	}
	issuance.OrderURL = order.Location
	issuance.ACMEStatus = order.Status
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
	if err := s.store.saveIssuance(ctx, issuance); err != nil {
		return Issuance{}, err
	}
	return s.prepareAuthorization(ctx, issuance)
}

func (s *Service) prepareAuthorization(ctx context.Context, issuance Issuance) (Issuance, error) {
	authorization, err := s.client.GetAuthorization(ctx, issuance.AuthorizationURL)
	if err != nil {
		return s.transientFailure(ctx, issuance, "read ACME authorization", err)
	}
	if authorization.Identifier.Type != "dns" || authorization.Identifier.Value != issuance.Hostname || authorization.Wildcard {
		return s.terminalFailure(ctx, issuance, "ACME authorization changed the identifier")
	}
	if authorization.Status == legoacme.StatusValid {
		issuance.ACMEStatus = authorization.Status
		issuance.Status = StatusReadyToFinalize
		if err := s.store.saveIssuance(ctx, issuance); err != nil {
			return Issuance{}, err
		}
		return s.advance(ctx, issuance)
	}
	if authorization.Status != legoacme.StatusPending {
		return s.terminalFailure(ctx, issuance, "ACME authorization is not pending")
	}
	challenge, err := tlsALPNChallenge(authorization)
	if err != nil {
		return s.terminalFailure(ctx, issuance, err.Error())
	}
	keyAuthorization, err := s.client.KeyAuthorization(challenge.Token)
	if err != nil {
		return s.terminalFailure(ctx, issuance, "derive ACME key authorization")
	}
	issuance.ChallengeURL = challenge.URL
	issuance.ChallengeToken = challenge.Token
	issuance.ChallengeDigest = sha256.Sum256([]byte(keyAuthorization))
	issuance.ChallengeExpires = authorization.Expires
	if issuance.ChallengeExpires.IsZero() {
		issuance.ChallengeExpires = s.now().Add(defaultChallengeTimeout)
	}
	if !issuance.ChallengeExpires.After(s.now()) {
		return s.terminalFailure(ctx, issuance, "ACME authorization is expired")
	}
	issuance.Status = StatusWaitingChallenge
	issuance.ACMEStatus = authorization.Status
	issuance.LastError = ""
	issuance.RetryAt = time.Time{}
	if err := s.store.saveIssuance(ctx, issuance); err != nil {
		return Issuance{}, err
	}
	return s.store.getIssuance(ctx, issuance.ID)
}

func (s *Service) advance(ctx context.Context, issuance Issuance) (Issuance, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if issuance.Status == StatusWaitingChallenge || issuance.Status == StatusValidating {
		issuance.Status = StatusValidating
		issuance.LastError = ""
		if err := s.store.saveIssuance(ctx, issuance); err != nil {
			return Issuance{}, err
		}
		authorization, err := s.client.GetAuthorization(ctx, issuance.AuthorizationURL)
		if err != nil {
			return s.transientFailure(ctx, issuance, "reconcile ACME authorization", err)
		}
		if authorization.Identifier.Type != "dns" || authorization.Identifier.Value != issuance.Hostname || authorization.Wildcard {
			return s.terminalFailure(ctx, issuance, "ACME authorization changed the identifier")
		}
		switch authorization.Status {
		case legoacme.StatusPending:
			challenge, challengeErr := tlsALPNChallenge(authorization)
			if challengeErr != nil {
				return s.terminalFailure(ctx, issuance, challengeErr.Error())
			}
			if challenge.URL != issuance.ChallengeURL || challenge.Token != issuance.ChallengeToken {
				return s.terminalFailure(ctx, issuance, "ACME TLS-ALPN-01 challenge changed")
			}
			switch challenge.Status {
			case legoacme.StatusPending:
				if err := s.ensureCurrent(ctx, issuance); err != nil {
					return Issuance{}, err
				}
				if _, err := s.client.AcceptChallenge(ctx, issuance.ChallengeURL); err != nil {
					return s.transientFailure(ctx, issuance, "accept ACME challenge", err)
				}
			case legoacme.StatusProcessing, legoacme.StatusValid:
				// The previous acceptance reached the CA; reconcile instead of replaying it.
			case legoacme.StatusInvalid:
				return s.terminalFailure(ctx, issuance, "ACME TLS-ALPN-01 challenge became invalid")
			default:
				return s.terminalFailure(ctx, issuance, "ACME TLS-ALPN-01 challenge has an invalid status")
			}
		case legoacme.StatusProcessing, legoacme.StatusValid:
		default:
			return s.terminalFailure(ctx, issuance, "ACME authorization became invalid")
		}
		if authorization.Status != legoacme.StatusValid {
			authorization, err = s.waitAuthorization(ctx, issuance.AuthorizationURL)
			if err != nil {
				return s.transientFailure(ctx, issuance, "wait for ACME authorization", err)
			}
		}
		if authorization.Status != legoacme.StatusValid {
			return s.terminalFailure(ctx, issuance, "ACME authorization became invalid")
		}
		issuance.ACMEStatus = authorization.Status
		issuance.Status = StatusReadyToFinalize
		if err := s.store.saveIssuance(ctx, issuance); err != nil {
			return Issuance{}, err
		}
	}

	order, err := s.client.GetOrder(ctx, issuance.OrderURL)
	if err != nil {
		return s.transientFailure(ctx, issuance, "reconcile ACME order", err)
	}
	if order.Status == legoacme.StatusPending {
		order, err = s.waitOrder(ctx, issuance.OrderURL, legoacme.StatusReady, legoacme.StatusValid)
		if err != nil {
			return s.transientFailure(ctx, issuance, "wait for ready ACME order", err)
		}
	}
	issuance.ACMEStatus = order.Status
	if order.Status == legoacme.StatusReady {
		if err := s.ensureCurrent(ctx, issuance); err != nil {
			return Issuance{}, err
		}
		issuance.Status = StatusFinalizing
		if err := s.store.saveIssuance(ctx, issuance); err != nil {
			return Issuance{}, err
		}
		order, err = s.client.FinalizeOrder(ctx, issuance.FinalizeURL, issuance.CSRDER)
		if err != nil {
			return s.transientFailure(ctx, issuance, "finalize ACME order", err)
		}
	}
	if order.Status == legoacme.StatusProcessing || order.Status == legoacme.StatusReady {
		order, err = s.waitOrder(ctx, issuance.OrderURL, legoacme.StatusValid)
		if err != nil {
			return s.transientFailure(ctx, issuance, "wait for finalized ACME order", err)
		}
	}
	if order.Status != legoacme.StatusValid || order.Certificate == "" {
		return s.terminalFailure(ctx, issuance, "ACME order did not become valid")
	}
	issuance.ACMEStatus = order.Status
	issuance.Status = StatusDownloading
	issuance.CertificateURL = order.Certificate
	if err := s.store.saveIssuance(ctx, issuance); err != nil {
		return Issuance{}, err
	}
	raw, err := s.client.GetCertificate(ctx, issuance.CertificateURL)
	if err != nil {
		return s.transientFailure(ctx, issuance, "download ACME certificate", err)
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
	issuance.LastError = ""
	issuance.RetryAt = time.Time{}
	if err := s.store.saveIssuance(ctx, issuance); err != nil {
		return Issuance{}, err
	}
	return s.store.getIssuance(ctx, issuance.ID)
}

func (s *Service) createOrderFailure(ctx context.Context, issuance Issuance, cause error) (Issuance, error) {
	// Only explicit retryable rejections clear the duplicate-order fence.
	var limited *legoacme.RateLimitedError
	if errors.As(cause, &limited) {
		issuance.OrderAttempts = 0
		delay := limited.RetryAfter
		if delay <= 0 {
			delay = 5 * time.Second
		}
		issuance.LastError = boundedError(fmt.Errorf("create ACME order: %w", cause))
		issuance.RetryAt = s.now().Add(delay)
		if err := s.store.saveIssuance(ctx, issuance); err != nil {
			return Issuance{}, err
		}
		return Issuance{}, &RateLimitError{RetryAt: issuance.RetryAt}
	}
	var problem *legoacme.ProblemDetails
	if !errors.As(cause, &problem) || problem.HTTPStatus >= http.StatusInternalServerError {
		return s.transientFailure(ctx, issuance, "create ACME order", cause)
	}
	if problem.Type == legoacme.BadNonceErrorType {
		issuance.OrderAttempts = 0
		return s.transientFailure(ctx, issuance, "create ACME order", cause)
	}
	return s.terminalFailure(ctx, issuance, boundedError(fmt.Errorf("create ACME order: %w", cause)))
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

func (s *Service) waitAuthorization(ctx context.Context, authorizationURL string) (legoacme.Authorization, error) {
	for {
		authorization, err := s.client.GetAuthorization(ctx, authorizationURL)
		if err != nil {
			return legoacme.Authorization{}, err
		}
		if authorization.Status != legoacme.StatusPending && authorization.Status != legoacme.StatusProcessing {
			return authorization, nil
		}
		if err := waitPoll(ctx); err != nil {
			return legoacme.Authorization{}, err
		}
	}
}

func (s *Service) waitOrder(ctx context.Context, orderURL string, wanted ...string) (legoacme.ExtendedOrder, error) {
	for {
		order, err := s.client.GetOrder(ctx, orderURL)
		if err != nil {
			return legoacme.ExtendedOrder{}, err
		}
		if order.Status == legoacme.StatusInvalid {
			return order, errors.New("ACME order is invalid")
		}
		for _, status := range wanted {
			if order.Status == status {
				return order, nil
			}
		}
		if err := waitPoll(ctx); err != nil {
			return legoacme.ExtendedOrder{}, err
		}
	}
}

func (s *Service) transientFailure(ctx context.Context, issuance Issuance, operation string, cause error) (Issuance, error) {
	issuance.LastError = boundedError(fmt.Errorf("%s: %w", operation, cause))
	issuance.RetryAt = s.now().Add(5 * time.Second)
	_ = s.store.saveIssuance(ctx, issuance)
	return Issuance{}, fmt.Errorf("%w: %s: %v", ErrUnavailable, operation, cause)
}

func (s *Service) terminalFailure(ctx context.Context, issuance Issuance, message string) (Issuance, error) {
	issuance.Status = StatusFailed
	issuance.LastError = boundedError(errors.New(message))
	issuance.RetryAt = time.Time{}
	_ = s.store.saveIssuance(ctx, issuance)
	return Issuance{}, fmt.Errorf("%w: %s", ErrInvalidStatus, message)
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

var pollInterval = time.Second

func waitPoll(ctx context.Context) error {
	timer := time.NewTimer(pollInterval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
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

func (s *Service) ensureCurrent(ctx context.Context, issuance Issuance) error {
	hostname, err := s.store.routeHostname(ctx, issuance.RouteID, issuance.Version)
	if err != nil {
		return err
	}
	if hostname != issuance.Hostname {
		return ErrInvalidStatus
	}
	return nil
}
