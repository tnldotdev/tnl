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

type Worker struct {
	store    Store
	provider Provider
	verifier DNSVerifier
	config   Config
	now      func() time.Time
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
		if err != nil && ctx.Err() == nil {
			w.config.Logger.Error("DNS controller iteration failed", "error", err)
		}
		delay := time.Duration(0)
		if !found || err != nil {
			delay = w.config.PollInterval
		}
		timer.Reset(delay)
	}
}

func (w *Worker) processOne(ctx context.Context) (bool, error) {
	now := w.now()
	work, found, err := w.store.ClaimDNSAuthorityWork(ctx, w.config.WorkerID, now, w.config.LeaseDuration)
	if err != nil {
		return false, err
	}
	if found {
		if err := w.advance(ctx, &work, now); err != nil {
			if ctx.Err() != nil {
				return true, ctx.Err()
			}
			w.applyFailure(&work, err, w.now())
		}
		if _, err := w.store.SaveDNSAuthorityWork(ctx, work, w.now()); err != nil {
			return true, err
		}
		return true, nil
	}
	route, found, err := w.store.ClaimDNSPublicURLWork(ctx, w.config.WorkerID, now, w.config.LeaseDuration)
	if err != nil || !found {
		return found, err
	}
	if err := w.advancePublicURL(ctx, &route, now); err != nil {
		if ctx.Err() != nil {
			return true, ctx.Err()
		}
		w.applyRouteFailure(&route, err, w.now())
	}
	if _, err := w.store.SaveDNSPublicURLWork(ctx, route, w.now()); err != nil {
		return true, err
	}
	return true, nil
}

func (w *Worker) advancePublicURL(ctx context.Context, work *controlstate.DNSPublicURLWork, now time.Time) error {
	work.LastError = ""
	record, nameservers, ready, err := w.publicURLRecord(ctx, *work)
	if err != nil {
		return err
	}
	if !ready {
		work.AvailableAt = now.Add(w.config.PollInterval)
		return nil
	}
	switch work.State {
	case controlstate.PublicURLDNSPending:
		zone, err := w.provider.PublishPublicURL(ctx, record)
		if err != nil {
			return err
		}
		if len(zone.Nameservers) != 0 {
			nameservers = zone.Nameservers
		}
		verified, err := w.verifier.VerifyPublicURL(
			ctx, work.CanonicalHostname, record.IngressIPv4Addresses, record.IngressIPv6Addresses, nameservers,
		)
		if err != nil {
			return err
		}
		if verified {
			work.State = controlstate.PublicURLDNSPublished
			work.AvailableAt = time.Time{}
		} else {
			work.AvailableAt = now.Add(w.config.PollInterval)
		}
		return nil
	case controlstate.PublicURLDNSRemoving:
		zone, err := w.provider.RemovePublicURL(ctx, record)
		if err != nil {
			return err
		}
		if len(zone.Nameservers) != 0 {
			nameservers = zone.Nameservers
		}
		verified, err := w.verifier.VerifyPublicURL(ctx, work.CanonicalHostname, nil, nil, nameservers)
		if err != nil {
			return err
		}
		if verified {
			work.State = controlstate.PublicURLDNSRemoved
			work.AvailableAt = time.Time{}
		} else {
			work.AvailableAt = now.Add(w.config.PollInterval)
		}
		return nil
	default:
		return terminalf("cannot process public URL DNS in state %q", work.State)
	}
}

func (w *Worker) publicURLRecord(
	ctx context.Context,
	work controlstate.DNSPublicURLWork,
) (PublicURLRecord, []string, bool, error) {
	record := PublicURLRecord{
		PublicURLID: work.PublicURLID, DomainID: work.DomainID, CanonicalHostname: work.CanonicalHostname,
		IngressIPv4Addresses: append([]string(nil), w.config.IngressIPv4Addresses...),
		IngressIPv6Addresses: append([]string(nil), w.config.IngressIPv6Addresses...),
	}
	if work.CanonicalHostname == w.config.ManagedDomain || strings.HasSuffix(work.CanonicalHostname, "."+w.config.ManagedDomain) {
		record.ZoneID, record.ZoneDomain = w.config.ManagedZoneID, w.config.ManagedDomain
		if record.ZoneID == "" {
			return PublicURLRecord{}, nil, false, terminalf("managed Route 53 zone is not configured")
		}
		return record, nil, true, nil
	}
	if work.DNSAuthorityReference == "" {
		return PublicURLRecord{}, nil, false, terminalf("claimed route has no DNS authority reference")
	}
	authority, err := w.store.GetDNSAuthority(ctx, work.DNSAuthorityReference)
	if err != nil {
		return PublicURLRecord{}, nil, false, err
	}
	if authority.DomainID != work.DomainID ||
		work.CanonicalHostname != authority.CanonicalDomain && !strings.HasSuffix(work.CanonicalHostname, "."+authority.CanonicalDomain) {
		return PublicURLRecord{}, nil, false, terminalf("public URL does not match its DNS authority")
	}
	if authority.State == "pending" {
		return PublicURLRecord{}, nil, false, nil
	}
	if authority.State != "ready" && authority.State != "releasing" || authority.ProviderZoneID == "" {
		return PublicURLRecord{}, nil, false, terminalf("DNS authority is not available")
	}
	record.ZoneID, record.ZoneDomain, record.ClaimedZone = authority.ProviderZoneID, authority.CanonicalDomain, true
	record.AuthorityReference, record.TeamID = authority.Reference, authority.TeamID
	return record, authority.Nameservers, true, nil
}

func (w *Worker) advance(ctx context.Context, work *controlstate.DNSAuthorityWork, now time.Time) error {
	work.LastError = ""
	switch work.State {
	case "pending":
		if work.ProviderZoneID == "" {
			zone, err := w.provider.EnsureClaimedZone(ctx, *work)
			if err != nil {
				return err
			}
			if zone.ID == "" || len(zone.Nameservers) < 2 {
				return terminalf("provider returned incomplete claimed-zone state")
			}
			work.ProviderZoneID = zone.ID
			work.Nameservers = append([]string(nil), zone.Nameservers...)
			work.AvailableAt = now.Add(w.config.PollInterval)
			return nil
		}
		verified, err := w.verifier.Verify(ctx, work.CanonicalDomain, work.Nameservers)
		if err != nil {
			return err
		}
		if verified {
			work.State = "ready"
			work.AvailableAt = now
		} else {
			work.AvailableAt = now.Add(w.config.PollInterval)
		}
		return nil
	case "releasing":
		ready, err := w.store.DNSAuthorityReleaseReady(ctx, work.DomainID, now)
		if err != nil {
			return err
		}
		if !ready {
			work.AvailableAt = now.Add(w.config.PollInterval)
			return nil
		}
		if err := w.provider.ReleaseClaimedZone(ctx, *work); err != nil {
			return err
		}
		work.State = "released"
		work.AvailableAt = now
		return nil
	default:
		return terminalf("cannot process DNS authority in state %q", work.State)
	}
}

func (w *Worker) applyFailure(work *controlstate.DNSAuthorityWork, operationErr error, now time.Time) {
	work.LastError = truncateError(operationErr)
	delay := w.config.RetryInterval
	for attempt := uint64(1); attempt < work.Attempts && delay < time.Minute; attempt++ {
		delay = min(delay*2, time.Minute)
	}
	work.AvailableAt = now.Add(delay)
	var terminal *terminalError
	if errors.As(operationErr, &terminal) {
		work.State = "failed"
		work.AvailableAt = now
	}
}

func (w *Worker) applyRouteFailure(work *controlstate.DNSPublicURLWork, operationErr error, now time.Time) {
	work.LastError = truncateError(operationErr)
	delay := w.config.RetryInterval
	for attempt := uint64(1); attempt < work.Attempts && delay < time.Minute; attempt++ {
		delay = min(delay*2, time.Minute)
	}
	work.AvailableAt = now.Add(delay)
	var terminal *terminalError
	if errors.As(operationErr, &terminal) {
		work.State = controlstate.PublicURLDNSFailed
		work.AvailableAt = time.Time{}
	}
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
