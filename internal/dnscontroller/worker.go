// Package dnscontroller applies persistent DNS changes requested by control.
package dnscontroller

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/workerloop"
)

const (
	defaultLeaseDuration    = 2 * time.Minute
	defaultOperationTimeout = 30 * time.Second
	defaultPollInterval     = 5 * time.Second
	defaultRetryInterval    = time.Second
)

type Zone struct {
	ID          string
	Nameservers []string
	ChangeID    string
}

type PublicURLRecord struct {
	ZoneID               string
	ZoneDomain           string
	ClaimedZone          bool
	AuthorityReference   string
	TeamID               string
	DomainID             string
	PublicURLID          string
	CanonicalHostname    string
	WildcardHostname     string
	IngressIPv4Addresses []string
	IngressIPv6Addresses []string
}

type Provider interface {
	EnsureClaimedZone(context.Context, controlstate.DNSAuthorityWork) (Zone, error)
	ReleaseClaimedZone(context.Context, controlstate.DNSAuthorityWork) error
	PublishPublicURL(context.Context, PublicURLRecord) (Zone, error)
	RemovePublicURL(context.Context, PublicURLRecord) (Zone, error)
}

type DNSVerifier interface {
	Verify(context.Context, string, []string) (bool, error)
	VerifyPublicURL(context.Context, string, []string, []string, []string) (bool, error)
}

type Store interface {
	ClaimDNSAuthorityWork(context.Context, string, time.Time, time.Duration) (controlstate.DNSAuthorityWork, bool, error)
	SaveDNSAuthorityWork(context.Context, controlstate.DNSAuthorityWork, time.Time) (controlstate.DNSAuthorityWork, error)
	DNSAuthorityReleaseReady(context.Context, string, time.Time) (bool, error)
	GetDNSAuthority(context.Context, string) (controlstate.DNSAuthority, error)
	ClaimDNSPublicURLWork(context.Context, string, time.Time, time.Duration) (controlstate.DNSPublicURLWork, bool, error)
	SaveDNSPublicURLWork(context.Context, controlstate.DNSPublicURLWork, time.Time) (controlstate.DNSPublicURLWork, error)
}

type Config struct {
	WorkerID             string
	Observer             DNSObserver
	Logger               *slog.Logger
	LeaseDuration        time.Duration
	OperationTimeout     time.Duration
	PollInterval         time.Duration
	RetryInterval        time.Duration
	ManagedDomain        string
	ManagedZoneID        string
	IngressIPv4Addresses []string
	IngressIPv6Addresses []string
}

type DNSObserver interface {
	ObserveDNSWork(kind, phase string, outcome observability.DNSWorkOutcome, elapsed time.Duration)
	ObserveDNSTransition(kind, state string)
}

func observeDNS(observer DNSObserver, kind, phase string, started time.Time, ready bool, err error) {
	if observer == nil {
		return
	}
	outcome := observability.DNSWorkSuccess
	if err != nil {
		outcome = observability.DNSWorkError
	} else if !ready {
		outcome = observability.DNSWorkPending
	}
	observer.ObserveDNSWork(kind, phase, outcome, time.Since(started))
}

type Worker struct {
	store         Store
	provider      Provider
	verifier      DNSVerifier
	config        Config
	now           func() time.Time
	publicURLNext bool
}

func New(store Store, provider Provider, verifier DNSVerifier, config Config) (*Worker, error) {
	if store == nil || provider == nil || verifier == nil || strings.TrimSpace(config.WorkerID) != config.WorkerID || config.WorkerID == "" {
		return nil, errors.New("dnscontroller: invalid configuration")
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
	if config.RetryInterval <= 0 {
		config.RetryInterval = defaultRetryInterval
	}
	if config.OperationTimeout >= config.LeaseDuration {
		return nil, errors.New("dnscontroller: operation timeout must be shorter than the work lease")
	}
	return &Worker{
		store: store, provider: provider, verifier: verifier, config: config,
		now: func() time.Time { return time.Now().UTC() },
	}, nil
}

func (w *Worker) Run(ctx context.Context) error {
	return workerloop.Run(ctx, workerloop.Config{
		OperationTimeout: w.config.OperationTimeout,
		IdleInterval:     w.config.PollInterval,
		Process:          w.processOne,
		OnError: func(err error) {
			if ctx.Err() == nil {
				w.config.Logger.Error("DNS controller iteration failed", "error", err)
			}
		},
	})
}

func (w *Worker) processOne(ctx context.Context) (bool, error) {
	now := w.now()
	if w.publicURLNext {
		found, err := w.processPublicURL(ctx, now)
		if found || err != nil {
			w.publicURLNext = false
			return found, err
		}
		found, err = w.processAuthority(ctx, now)
		if found || err != nil {
			w.publicURLNext = true
		}
		return found, err
	}
	found, err := w.processAuthority(ctx, now)
	if found || err != nil {
		w.publicURLNext = true
		return found, err
	}
	found, err = w.processPublicURL(ctx, now)
	if found || err != nil {
		w.publicURLNext = false
	}
	return found, err
}

func (w *Worker) retryAvailableAt(attempts uint64, now time.Time) time.Time {
	delay := w.config.RetryInterval
	for attempt := uint64(1); attempt < attempts && delay < time.Minute; attempt++ {
		delay = min(delay*2, time.Minute)
	}
	return now.Add(delay)
}

type terminalError struct{ message string }

func (e *terminalError) Error() string { return e.message }

func (e *terminalError) Terminal() bool { return true }

func terminalf(format string, arguments ...any) error {
	return &terminalError{message: fmt.Sprintf("dnscontroller: "+format, arguments...)}
}

func truncateError(err error) string {
	value := err.Error()
	limit := min(len(value), 1024)
	for !utf8.ValidString(value[:limit]) {
		limit--
	}
	return value[:limit]
}
