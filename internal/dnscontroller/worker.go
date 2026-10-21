// Package dnscontroller applies persistent DNS changes requested by control.
package dnscontroller

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/operatorlog"
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

type AddressRecord struct {
	ZoneID               string
	ZoneDomain           string
	CustomZone           bool
	AuthorityReference   string
	TeamID               string
	DomainID             string
	Owner                AddressOwner
	CanonicalHostname    string
	Namespace            string
	WildcardHostname     string
	IngressIPv4Addresses []string
	IngressIPv6Addresses []string
}

type Provider interface {
	EnsureCustomZone(context.Context, controlstate.DNSAuthorityWork) (Zone, error)
	ReleaseCustomZone(context.Context, controlstate.DNSAuthorityWork) error
	PublishAddress(context.Context, AddressRecord) (Zone, error)
	RemoveAddress(context.Context, AddressRecord) (Zone, error)
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
	GetIngressPool(context.Context, string) (controlstate.IngressPool, error)
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
	ObserveDNSWorkContext(context.Context, string, string, observability.DNSWorkOutcome, time.Duration)
	ObserveDNSTransition(kind, state string)
}

func observeDNS(ctx context.Context, observer DNSObserver, kind, phase string, started time.Time, ready bool, err error) {
	if observer == nil {
		return
	}
	outcome := observability.DNSWorkSuccess
	if err != nil {
		outcome = observability.DNSWorkError
	} else if !ready {
		outcome = observability.DNSWorkPending
	}
	observer.ObserveDNSWorkContext(ctx, kind, phase, outcome, time.Since(started))
}

type Worker struct {
	store         Store
	provider      Provider
	verifier      DNSVerifier
	config        Config
	now           func() time.Time
	publicURLNext bool
	managedNext   bool
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
	})
}

func finishDNSAttempt(ctx context.Context, finish func(error), err error) {
	canceled := errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
	if err != nil && (!canceled || !workerloop.LifetimeEnded(ctx)) {
		err = failure.Wrap("advance DNS work", dnsFailureReason(err), err)
		operatorlog.ReportContext(ctx, "advance DNS work", dnsFailureReason(err), "", err)
	}
	finish(err)
}

func (w *Worker) processOne(ctx context.Context) (bool, error) {
	now := w.now()
	if w.managedNext {
		w.managedNext = false
		if found, err := w.processManagedEndpoint(ctx, now); found || err != nil {
			return found, err
		}
	}
	w.managedNext = true
	return w.processExisting(ctx, now)
}

func (w *Worker) processExisting(ctx context.Context, now time.Time) (bool, error) {
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
	if found || err != nil {
		return found, err
	}
	return w.processManagedEndpoint(ctx, now)
}

func (w *Worker) retryAvailableAt(attempts uint64, now time.Time) time.Time {
	delay := w.config.RetryInterval
	for attempt := uint64(1); attempt < attempts && delay < time.Minute; attempt++ {
		delay = min(delay*2, time.Minute)
	}
	return now.Add(delay)
}

type terminalError struct {
	message string
	reason  failure.Reason
}

func (e *terminalError) Error() string { return e.message }

func (e *terminalError) Terminal() bool                { return true }
func (e *terminalError) FailureReason() failure.Reason { return e.reason }

func terminalf(format string, arguments ...any) error {
	return terminalReasonf(failure.ServerDNSConflict, format, arguments...)
}

func terminalReasonf(reason failure.Reason, format string, arguments ...any) error {
	return &terminalError{message: fmt.Sprintf("dnscontroller: "+format, arguments...), reason: reason}
}

func storedFailureReason(err error) string {
	return string(dnsFailureReason(err))
}

func dnsFailureReason(err error) failure.Reason {
	if reason, ok := failure.ReasonOf(err); ok {
		return reason
	}
	return failure.ServerDNSFailed
}
