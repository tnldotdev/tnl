package certificates

import (
	"crypto/sha256"
	"errors"
	"time"
)

const (
	StatusCreatingOrder     = "creating_order"
	StatusAuthorizing       = "authorizing"
	StatusWaitingChallenge  = "waiting_for_challenge"
	StatusReadyToFinalize   = "ready_to_finalize"
	StatusFinalizing        = "finalizing"
	StatusWaitingForInstall = "waiting_for_install"
	StatusInstalled         = "installed"
	StatusFailed            = "failed"
	tlsALPNChallengeType    = "tls-alpn-01"
	defaultChallengeTimeout = 10 * time.Minute
)

var (
	ErrNotFound        = errors.New("certificates: not found")
	ErrInvalidArgument = errors.New("certificates: invalid argument")
	ErrInvalidStatus   = errors.New("certificates: invalid status")
	ErrRateLimited     = errors.New("certificates: rate limited")
	ErrUnavailable     = errors.New("certificates: temporarily unavailable")
)

type RateLimitError struct{ RetryAt time.Time }

func (e *RateLimitError) Error() string { return "certificates: issuance rate limited" }
func (e *RateLimitError) Unwrap() error { return ErrRateLimited }

type Challenge struct {
	ID        string
	Hostname  string
	Digest    [sha256.Size]byte
	ExpiresAt time.Time
}

type Issuance struct {
	ID           string
	RouteID      string
	RouteVersion uint64
	Hostname     string
	DirectoryURL string
	ACMEProfile  string
	Status       string

	CSRDER   []byte
	CSRHash  [sha256.Size]byte
	SPKIHash [sha256.Size]byte

	OrderStartedAt   time.Time
	OrderURL         string
	OrderExpires     time.Time
	RetryAt          time.Time
	AuthorizationURL string
	FinalizeURL      string
	ChallengeURL     string
	ChallengeDigest  [sha256.Size]byte
	ChallengeExpires time.Time
	CertificateURL   string
	CertificatePEM   []byte
	NotBefore        time.Time
	NotAfter         time.Time
	RenewAt          time.Time
	LastError        string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

func (j Issuance) Challenge() *Challenge {
	if j.ChallengeURL == "" || j.ChallengeExpires.IsZero() {
		return nil
	}
	return &Challenge{ID: j.ChallengeURL, Hostname: j.Hostname, Digest: j.ChallengeDigest, ExpiresAt: j.ChallengeExpires}
}

type account struct {
	DirectoryURL string
	Email        string
	KeyDER       []byte
	KID          string
	AcceptedTOS  string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}
