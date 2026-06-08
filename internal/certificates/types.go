package certificates

import (
	"crypto/sha256"
	"errors"
	"time"
)

const (
	StateCreatingOrder      = "creating_order"
	StateAuthorizing        = "authorizing"
	StateWaitingChallenge   = "waiting_for_challenge"
	StateValidating         = "validating"
	StateReadyToFinalize    = "ready_to_finalize"
	StateFinalizing         = "finalizing"
	StateDownloading        = "downloading"
	StateWaitingForInstall  = "waiting_for_install"
	StateSucceeded          = "succeeded"
	StateInvalid            = "invalid"
	StateBlocked            = "blocked"
	StateCanceled           = "canceled"
	tlsALPNChallengeType    = "tls-alpn-01"
	defaultChallengeTimeout = 10 * time.Minute
)

var (
	ErrNotFound        = errors.New("certificates: not found")
	ErrInvalidArgument = errors.New("certificates: invalid argument")
	ErrInvalidState    = errors.New("certificates: invalid state")
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

type Job struct {
	ID         string
	RouteID    string
	Generation uint64
	Hostname   string
	Profile    string
	State      string

	CSRDER   []byte
	CSRHash  [sha256.Size]byte
	SPKIHash [sha256.Size]byte

	OrderURL         string
	ACMEStatus       string
	OrderAttempts    int
	OrderExpires     time.Time
	RetryAt          time.Time
	AuthorizationURL string
	FinalizeURL      string
	ChallengeURL     string
	ChallengeToken   string
	ChallengeDigest  [sha256.Size]byte
	ChallengeExpires time.Time
	CertificateURL   string
	CertificatePEM   []byte
	NotBefore        time.Time
	NotAfter         time.Time
	RenewAt          time.Time
	InstalledAt      time.Time
	ChallengeRemoved time.Time
	LastError        string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

func (j Job) Challenge() *Challenge {
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
