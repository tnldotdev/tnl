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

type ProbeFunc func(context.Context, Job) error

type Config struct {
	DirectoryURL  string
	Email         string
	AcceptTerms   bool
	Profile       string
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
	profile       string
	roots         *x509.CertPool
	probe         ProbeFunc
	hostnameReady func(context.Context, string) error
	now           func() time.Time
	locks         [64]sync.Mutex
}

// New constructs the durable ACME service and reconciles its persisted account.
func New(ctx context.Context, db *sql.DB, config Config) (*Service, error) {
	if strings.TrimSpace(config.DirectoryURL) == "" || strings.TrimSpace(config.Email) == "" ||
		strings.TrimSpace(config.Profile) == "" || config.Probe == nil {
		return nil, errors.New("certificates: directory, email, profile, and probe are required")
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
	if _, ok := directoryMeta.Meta.Profiles[config.Profile]; !ok {
		return nil, fmt.Errorf("certificates: ACME profile %q is not advertised", config.Profile)
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
		store: stored, client: client, profile: config.Profile, roots: config.Roots,
		probe: config.Probe, hostnameReady: config.HostnameReady, now: config.Now,
	}, nil
}

func (s *Service) Create(
	ctx context.Context,
	routeID string,
	generation uint64,
	profile string,
	csrDER []byte,
) (Job, error) {
	lock := s.routeLock(routeID)
	lock.Lock()
	defer lock.Unlock()
	hostname, err := s.store.routeHostname(ctx, routeID, generation)
	if err != nil {
		return Job{}, err
	}
	canonical, err := naming.CanonicalizeHostname(hostname)
	if err != nil || canonical != hostname || strings.TrimSpace(routeID) == "" || generation == 0 || profile != s.profile {
		return Job{}, ErrInvalidArgument
	}
	if s.hostnameReady != nil {
		if err := s.hostnameReady(ctx, hostname); err != nil {
			return Job{}, ErrUnavailable
		}
	}
	_, csrHash, spkiHash, err := validateCSR(csrDER, hostname)
	if err != nil {
		return Job{}, err
	}
	// Recover bound or resumable work before allocating another ACME order.
	job, err := s.store.findBoundJob(ctx, routeID, generation, csrHash)
	created := false
	if errors.Is(err, ErrNotFound) {
		resumable, resumeErr := s.store.findResumableJob(ctx, routeID, csrHash, s.now())
		if resumeErr == nil {
			job, err = s.store.rebindJob(ctx, resumable.ID, generation)
			if err != nil {
				return Job{}, err
			}
			return s.continueJob(ctx, job)
		}
		if !errors.Is(resumeErr, ErrNotFound) {
			return Job{}, resumeErr
		}
		if err := s.store.allowJobCreation(ctx, routeID, generation, csrHash, s.now()); err != nil {
			return Job{}, err
		}
		job, created, err = s.store.createJob(
			ctx, routeID, generation, hostname, profile, csrDER, csrHash, spkiHash,
		)
	}
	if err != nil {
		return Job{}, err
	}
	if !created {
		return s.continueJob(ctx, job)
	}
	if created {
		reusable, reuseErr := s.store.findReusableJob(ctx, routeID, csrHash, s.now().Add(24*time.Hour))
		if reuseErr == nil && reusable.RenewAt.After(s.now()) {
			job.State = StateWaitingForInstall
			job.CertificateURL = reusable.CertificateURL
			job.CertificatePEM = bytes.Clone(reusable.CertificatePEM)
			job.NotBefore = reusable.NotBefore
			job.NotAfter = reusable.NotAfter
			job.RenewAt = reusable.RenewAt
			job.ChallengeRemoved = s.now()
			if err := s.store.saveJob(ctx, job); err != nil {
				return Job{}, err
			}
			return s.store.getJob(ctx, job.ID)
		}
		if reuseErr != nil && !errors.Is(reuseErr, ErrNotFound) {
			return Job{}, reuseErr
		}
	}
	return s.createOrder(ctx, job)
}

func (s *Service) continueJob(ctx context.Context, job Job) (Job, error) {
	if job.RetryAt.After(s.now()) {
		return job, nil
	}
	switch job.State {
	case StateCreatingOrder:
		return s.createOrder(ctx, job)
	case StateAuthorizing:
		return s.prepareAuthorization(ctx, job)
	case StateReadyToFinalize, StateFinalizing, StateDownloading:
		return s.advance(ctx, job)
	default:
		return job, nil
	}
}

func (s *Service) Get(ctx context.Context, id string) (Job, error) {
	return s.store.getJob(ctx, id)
}

func (s *Service) ChallengeReady(ctx context.Context, id string) (Job, error) {
	job, err := s.store.getJob(ctx, id)
	if err != nil {
		return Job{}, err
	}
	lock := s.routeLock(job.RouteID)
	lock.Lock()
	defer lock.Unlock()
	job, err = s.store.getJob(ctx, id)
	if err != nil {
		return Job{}, err
	}
	if job.State == StateWaitingForInstall || job.State == StateSucceeded {
		return job, nil
	}
	if job.RetryAt.After(s.now()) {
		return Job{}, ErrUnavailable
	}
	if err := s.ensureCurrent(ctx, job); err != nil {
		return Job{}, err
	}
	if job.ChallengeURL == "" || !job.ChallengeExpires.After(s.now()) {
		return Job{}, ErrInvalidState
	}
	if err := s.probe(ctx, job); err != nil {
		job.LastError = boundedError(err)
		job.RetryAt = s.now().Add(5 * time.Second)
		_ = s.store.saveJob(ctx, job)
		return Job{}, fmt.Errorf("%w: routed TLS-ALPN probe: %v", ErrUnavailable, err)
	}
	// The probe may outlive this route generation.
	if err := s.ensureCurrent(ctx, job); err != nil {
		return Job{}, err
	}
	return s.advance(ctx, job)
}

func (s *Service) ChallengeRemoved(ctx context.Context, id string) (Job, error) {
	job, err := s.store.getJob(ctx, id)
	if err != nil {
		return Job{}, err
	}
	lock := s.routeLock(job.RouteID)
	lock.Lock()
	defer lock.Unlock()
	job, err = s.store.getJob(ctx, id)
	if err != nil {
		return Job{}, err
	}
	if len(job.CertificatePEM) == 0 {
		return Job{}, ErrInvalidState
	}
	job.ChallengeRemoved = s.now()
	job.LastError = ""
	if err := s.store.saveJob(ctx, job); err != nil {
		return Job{}, err
	}
	return s.store.getJob(ctx, id)
}

func (s *Service) Installed(ctx context.Context, id, routeID string, generation uint64) (Job, error) {
	job, err := s.store.getJob(ctx, id)
	if err != nil {
		return Job{}, err
	}
	lock := s.routeLock(job.RouteID)
	lock.Lock()
	defer lock.Unlock()
	job, err = s.store.getJob(ctx, id)
	if err != nil {
		return Job{}, err
	}
	if job.RouteID != routeID || job.Generation != generation || len(job.CertificatePEM) == 0 ||
		job.State != StateWaitingForInstall && job.State != StateSucceeded || job.ChallengeRemoved.IsZero() {
		return Job{}, ErrInvalidState
	}
	if err := s.ensureCurrent(ctx, job); err != nil {
		return Job{}, err
	}
	job.State = StateSucceeded
	job.InstalledAt = s.now()
	job.LastError = ""
	if err := s.store.saveJob(ctx, job); err != nil {
		return Job{}, err
	}
	return s.store.getJob(ctx, id)
}

func (s *Service) createOrder(ctx context.Context, job Job) (Job, error) {
	// A missing response URL makes blind retries risk duplicate orders.
	if job.OrderAttempts != 0 {
		job.State = StateBlocked
		job.LastError = "ACME order creation outcome is ambiguous; refusing to create a duplicate order"
		if err := s.store.saveJob(ctx, job); err != nil {
			return Job{}, err
		}
		return Job{}, fmt.Errorf("%w: %s", ErrInvalidState, job.LastError)
	}
	job.OrderAttempts++
	job.RetryAt = time.Time{}
	if err := s.store.saveJob(ctx, job); err != nil {
		return Job{}, err
	}
	order, err := s.client.CreateOrder(ctx, []string{job.Hostname}, &legoapi.OrderOptions{Profile: job.Profile})
	if err != nil {
		return s.createOrderFailure(ctx, job, err)
	}
	if order.Location == "" || order.Finalize == "" || len(order.Authorizations) != 1 || order.Profile != job.Profile {
		return s.terminalFailure(ctx, job, "ACME order response is incomplete")
	}
	job.OrderURL = order.Location
	job.ACMEStatus = order.Status
	job.FinalizeURL = order.Finalize
	if order.Expires != "" {
		job.OrderExpires, err = time.Parse(time.RFC3339, order.Expires)
		if err != nil {
			return s.terminalFailure(ctx, job, "ACME order expiry is invalid")
		}
	}
	job.AuthorizationURL = order.Authorizations[0]
	job.State = StateAuthorizing
	job.LastError = ""
	job.RetryAt = time.Time{}
	if err := s.store.saveJob(ctx, job); err != nil {
		return Job{}, err
	}
	return s.prepareAuthorization(ctx, job)
}

func (s *Service) prepareAuthorization(ctx context.Context, job Job) (Job, error) {
	authorization, err := s.client.GetAuthorization(ctx, job.AuthorizationURL)
	if err != nil {
		return s.transientFailure(ctx, job, "read ACME authorization", err)
	}
	if authorization.Identifier.Type != "dns" || authorization.Identifier.Value != job.Hostname || authorization.Wildcard {
		return s.terminalFailure(ctx, job, "ACME authorization changed the identifier")
	}
	if authorization.Status == legoacme.StatusValid {
		job.ACMEStatus = authorization.Status
		job.State = StateReadyToFinalize
		if err := s.store.saveJob(ctx, job); err != nil {
			return Job{}, err
		}
		return s.advance(ctx, job)
	}
	if authorization.Status != legoacme.StatusPending {
		return s.terminalFailure(ctx, job, "ACME authorization is not pending")
	}
	challenge, err := tlsALPNChallenge(authorization)
	if err != nil {
		return s.terminalFailure(ctx, job, err.Error())
	}
	keyAuthorization, err := s.client.KeyAuthorization(challenge.Token)
	if err != nil {
		return s.terminalFailure(ctx, job, "derive ACME key authorization")
	}
	job.ChallengeURL = challenge.URL
	job.ChallengeToken = challenge.Token
	job.ChallengeDigest = sha256.Sum256([]byte(keyAuthorization))
	job.ChallengeExpires = authorization.Expires
	if job.ChallengeExpires.IsZero() {
		job.ChallengeExpires = s.now().Add(defaultChallengeTimeout)
	}
	if !job.ChallengeExpires.After(s.now()) {
		return s.terminalFailure(ctx, job, "ACME authorization is expired")
	}
	job.State = StateWaitingChallenge
	job.ACMEStatus = authorization.Status
	job.LastError = ""
	job.RetryAt = time.Time{}
	if err := s.store.saveJob(ctx, job); err != nil {
		return Job{}, err
	}
	return s.store.getJob(ctx, job.ID)
}

func (s *Service) advance(ctx context.Context, job Job) (Job, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if job.State == StateWaitingChallenge || job.State == StateValidating {
		job.State = StateValidating
		job.LastError = ""
		if err := s.store.saveJob(ctx, job); err != nil {
			return Job{}, err
		}
		authorization, err := s.client.GetAuthorization(ctx, job.AuthorizationURL)
		if err != nil {
			return s.transientFailure(ctx, job, "reconcile ACME authorization", err)
		}
		if authorization.Identifier.Type != "dns" || authorization.Identifier.Value != job.Hostname || authorization.Wildcard {
			return s.terminalFailure(ctx, job, "ACME authorization changed the identifier")
		}
		switch authorization.Status {
		case legoacme.StatusPending:
			challenge, challengeErr := tlsALPNChallenge(authorization)
			if challengeErr != nil {
				return s.terminalFailure(ctx, job, challengeErr.Error())
			}
			if challenge.URL != job.ChallengeURL || challenge.Token != job.ChallengeToken {
				return s.terminalFailure(ctx, job, "ACME TLS-ALPN-01 challenge changed")
			}
			switch challenge.Status {
			case legoacme.StatusPending:
				if err := s.ensureCurrent(ctx, job); err != nil {
					return Job{}, err
				}
				if _, err := s.client.AcceptChallenge(ctx, job.ChallengeURL); err != nil {
					return s.transientFailure(ctx, job, "accept ACME challenge", err)
				}
			case legoacme.StatusProcessing, legoacme.StatusValid:
				// The previous acceptance reached the CA; reconcile instead of replaying it.
			case legoacme.StatusInvalid:
				return s.terminalFailure(ctx, job, "ACME TLS-ALPN-01 challenge became invalid")
			default:
				return s.terminalFailure(ctx, job, "ACME TLS-ALPN-01 challenge has an invalid status")
			}
		case legoacme.StatusProcessing, legoacme.StatusValid:
		default:
			return s.terminalFailure(ctx, job, "ACME authorization became invalid")
		}
		if authorization.Status != legoacme.StatusValid {
			authorization, err = s.waitAuthorization(ctx, job.AuthorizationURL)
			if err != nil {
				return s.transientFailure(ctx, job, "wait for ACME authorization", err)
			}
		}
		if authorization.Status != legoacme.StatusValid {
			return s.terminalFailure(ctx, job, "ACME authorization became invalid")
		}
		job.ACMEStatus = authorization.Status
		job.State = StateReadyToFinalize
		if err := s.store.saveJob(ctx, job); err != nil {
			return Job{}, err
		}
	}

	order, err := s.client.GetOrder(ctx, job.OrderURL)
	if err != nil {
		return s.transientFailure(ctx, job, "reconcile ACME order", err)
	}
	if order.Status == legoacme.StatusPending {
		order, err = s.waitOrder(ctx, job.OrderURL, legoacme.StatusReady, legoacme.StatusValid)
		if err != nil {
			return s.transientFailure(ctx, job, "wait for ready ACME order", err)
		}
	}
	job.ACMEStatus = order.Status
	if order.Status == legoacme.StatusReady {
		if err := s.ensureCurrent(ctx, job); err != nil {
			return Job{}, err
		}
		job.State = StateFinalizing
		if err := s.store.saveJob(ctx, job); err != nil {
			return Job{}, err
		}
		order, err = s.client.FinalizeOrder(ctx, job.FinalizeURL, job.CSRDER)
		if err != nil {
			return s.transientFailure(ctx, job, "finalize ACME order", err)
		}
	}
	if order.Status == legoacme.StatusProcessing || order.Status == legoacme.StatusReady {
		order, err = s.waitOrder(ctx, job.OrderURL, legoacme.StatusValid)
		if err != nil {
			return s.transientFailure(ctx, job, "wait for finalized ACME order", err)
		}
	}
	if order.Status != legoacme.StatusValid || order.Certificate == "" {
		return s.terminalFailure(ctx, job, "ACME order did not become valid")
	}
	job.ACMEStatus = order.Status
	job.State = StateDownloading
	job.CertificateURL = order.Certificate
	if err := s.store.saveJob(ctx, job); err != nil {
		return Job{}, err
	}
	raw, err := s.client.GetCertificate(ctx, job.CertificateURL)
	if err != nil {
		return s.transientFailure(ctx, job, "download ACME certificate", err)
	}
	certificatePEM := raw.Cert
	if len(raw.Issuer) != 0 && !bytes.HasSuffix(certificatePEM, raw.Issuer) {
		certificatePEM = append(bytes.Clone(certificatePEM), raw.Issuer...)
	}
	validated, leaf, err := validateCertificateChain(certificatePEM, job.Hostname, job.SPKIHash, s.now(), s.roots)
	if err != nil {
		return s.terminalFailure(ctx, job, err.Error())
	}
	job.State = StateWaitingForInstall
	job.CertificatePEM = validated
	job.NotBefore = leaf.NotBefore.UTC()
	job.NotAfter = leaf.NotAfter.UTC()
	job.RenewAt = renewalTime(job.ID, job.NotBefore, job.NotAfter)
	job.LastError = ""
	job.RetryAt = time.Time{}
	if err := s.store.saveJob(ctx, job); err != nil {
		return Job{}, err
	}
	return s.store.getJob(ctx, job.ID)
}

func (s *Service) createOrderFailure(ctx context.Context, job Job, cause error) (Job, error) {
	// Only explicit retryable rejections clear the duplicate-order fence.
	var limited *legoacme.RateLimitedError
	if errors.As(cause, &limited) {
		job.OrderAttempts = 0
		delay := limited.RetryAfter
		if delay <= 0 {
			delay = 5 * time.Second
		}
		job.LastError = boundedError(fmt.Errorf("create ACME order: %w", cause))
		job.RetryAt = s.now().Add(delay)
		if err := s.store.saveJob(ctx, job); err != nil {
			return Job{}, err
		}
		return Job{}, &RateLimitError{RetryAt: job.RetryAt}
	}
	var problem *legoacme.ProblemDetails
	if !errors.As(cause, &problem) || problem.HTTPStatus >= http.StatusInternalServerError {
		return s.transientFailure(ctx, job, "create ACME order", cause)
	}
	if problem.Type == legoacme.BadNonceErrorType {
		job.OrderAttempts = 0
		return s.transientFailure(ctx, job, "create ACME order", cause)
	}
	return s.terminalFailure(ctx, job, boundedError(fmt.Errorf("create ACME order: %w", cause)))
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

func (s *Service) transientFailure(ctx context.Context, job Job, operation string, cause error) (Job, error) {
	job.LastError = boundedError(fmt.Errorf("%s: %w", operation, cause))
	job.RetryAt = s.now().Add(5 * time.Second)
	_ = s.store.saveJob(ctx, job)
	return Job{}, fmt.Errorf("%w: %s: %v", ErrUnavailable, operation, cause)
}

func (s *Service) terminalFailure(ctx context.Context, job Job, message string) (Job, error) {
	job.State = StateInvalid
	job.LastError = boundedError(errors.New(message))
	job.RetryAt = time.Time{}
	_ = s.store.saveJob(ctx, job)
	return Job{}, fmt.Errorf("%w: %s", ErrInvalidState, message)
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

func (s *Service) ensureCurrent(ctx context.Context, job Job) error {
	hostname, err := s.store.routeHostname(ctx, job.RouteID, job.Generation)
	if err != nil {
		return err
	}
	if hostname != job.Hostname {
		return ErrInvalidState
	}
	return nil
}
