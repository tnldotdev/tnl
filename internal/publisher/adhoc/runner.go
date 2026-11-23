// package adhoc owns temporary HTTP service allocation, publication, and cleanup.
package adhoc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	clienttelemetry "github.com/tnldotdev/tnl/internal/client/telemetry"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/policy/applicationlimits"
	"github.com/tnldotdev/tnl/internal/policy/authorization"
	targetsyntax "github.com/tnldotdev/tnl/internal/policy/target"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type Options struct {
	SuppliedCertificate func(context.Context) (publisherservice.CertificateMaterial, error)
	CertificateExport   *publisherservice.CertificateExport
	Telemetry           *clienttelemetry.Collector
	RequirePostQuantum  bool
	ControlURL          string
	HTTPClient          *http.Client
	State               *clientstate.Store
	EnrollmentKey       string
	PublisherIdentityID string
	Publisher           *publisheridentity.Native
	InvocationID        string
	ExpiresAt           *time.Time
	Public              *bool
	Target              string
	TargetTLS           *controlv1.ProjectTargetTLS
	AccessMode          controlv1.VisitorAccessMode
	IP                  []string
	Limits              applicationlimits.Limits
	OnAllocated         func(controlv1.Service) error
	Ready               func() error
	// shutdown deadline belongs to the caller's whole publication, including
	// its local listener. nil lets this operation own a ten-second budget.
	ShutdownDeadline func() time.Time
}

// Run allocates one ordinary ephemeral service, publishes it, and deletes that
// exact allocation. ambiguous retries keep the original invocation and declaration.
func Run(ctx context.Context, options Options) (result error) {
	deadline := options.ShutdownDeadline
	if deadline == nil {
		deadline = sync.OnceValue(func() time.Time { return time.Now().Add(10 * time.Second) })
	}
	options.ShutdownDeadline = deadline
	prepared, err := Prepare(ctx, options)
	if prepared != nil {
		defer func() {
			cleanup, cancel := context.WithDeadline(context.WithoutCancel(ctx), deadline())
			defer cancel()
			result = errors.Join(result, prepared.Cleanup(cleanup))
		}()
	}
	if err != nil {
		return err
	}
	if options.OnAllocated != nil {
		if err := options.OnAllocated(prepared.Service); err != nil {
			return err
		}
	}
	return publisherservice.Publish(ctx, prepared.Config)
}

func allocationRequest(options Options) (controlv1.AllocateServiceRequest, string, *targettrust.Snapshot, error) {
	var body controlv1.AllocateServiceRequest
	if err := options.Limits.Validate(); err != nil {
		return body, "", nil, err
	}
	target, err := targetsyntax.ParseCanonicalTarget(options.Target)
	if err != nil {
		return body, "", nil, err
	}
	mode := options.AccessMode
	if mode == "" {
		mode = controlv1.Restricted
	}
	if mode != controlv1.Restricted && mode != controlv1.Anonymous {
		return body, "", nil, errors.New("HTTP access must be restricted or anonymous")
	}
	ips, err := authorization.CanonicalizeVisitorIPPrefixes(options.IP)
	if err != nil {
		return body, "", nil, err
	}
	body.InvocationId = options.InvocationID
	public := options.Public == nil || *options.Public
	body.Configuration = controlv1.ProjectServiceConfiguration{
		Protocol: new(controlv1.ServiceProtocolHTTP), Target: target.Host,
		Public: new(public), Ephemeral: new(true), RequirePostQuantum: new(options.RequirePostQuantum),
		Http: &controlv1.ProjectServiceHTTP{Access: &controlv1.ProjectHTTPAccess{Mode: &mode}},
	}
	if len(ips) != 0 {
		body.Configuration.Http.Access.Ip = &ips
	}
	if options.ExpiresAt != nil {
		until := options.ExpiresAt.UTC()
		if !until.After(time.Now()) {
			return body, "", nil, errors.New("service expiration must be in the future")
		}
		body.ExpiresAt = &until
	}
	var trust *targettrust.Snapshot
	if target.Scheme == "https" {
		hostname, ca := target.Hostname(), ""
		if options.TargetTLS != nil {
			hostname = options.TargetTLS.Hostname
			if options.TargetTLS.CaPem != nil {
				ca = *options.TargetTLS.CaPem
			}
		}
		declaration, err := targettrust.NewDeclaration(hostname, []byte(ca))
		if err != nil {
			return body, "", nil, err
		}
		declaration.HostnameFromTarget = options.TargetTLS == nil || options.TargetTLS.HostnameFromTarget
		if options.TargetTLS != nil && options.TargetTLS.Digest != "" && options.TargetTLS.Digest != declaration.Digest {
			return body, "", nil, errors.New("target TLS digest does not match its captured trust")
		}
		trust, err = declaration.Snapshot()
		if err != nil {
			return body, "", nil, err
		}
		body.Configuration.TargetTls = &controlv1.ProjectTargetTLS{Hostname: declaration.Hostname, Digest: declaration.Digest, HostnameFromTarget: declaration.HostnameFromTarget}
		if ca != "" {
			body.Configuration.TargetTls.CaPem = new(ca)
		}
	} else if options.TargetTLS != nil {
		return body, "", nil, errors.New("target TLS requires an HTTPS target")
	}
	limits := options.Limits
	if limits.Requests != 0 || limits.Concurrency != 0 || limits.RateRequests != 0 {
		http := &controlv1.ProjectHTTPApplicationLimits{}
		if limits.Requests != 0 {
			http.Total = new(limits.Requests)
		}
		if limits.Concurrency != 0 {
			http.Concurrency = new(limits.Concurrency)
		}
		if limits.RateRequests != 0 {
			http.Rate = &controlv1.ProjectApplicationRate{Count: limits.RateRequests, Per: limits.RatePer.String()}
			if limits.RateBurst != 0 {
				http.Rate.Burst = new(limits.RateBurst)
			}
		}
		body.Configuration.Http.Limits = http
	}
	return body, target.Host, trust, nil
}

func allocateService(ctx context.Context, native *publisheridentity.Native, body controlv1.AllocateServiceRequest) (controlv1.Service, error) {
	if body.ExpiresAt != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, *body.ExpiresAt)
		defer cancel()
	}
	delay := 100 * time.Millisecond
	var last error
	for {
		if err := context.Cause(ctx); err != nil {
			return controlv1.Service{}, errors.Join(last, err)
		}
		saved, err := native.AllocateService(ctx, body)
		if err == nil || saved.Id != "" || !retryAllocation(err) {
			return saved, err
		}
		last = err
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return controlv1.Service{}, errors.Join(err, context.Cause(ctx))
		case <-timer.C:
		}
		delay = min(2*delay, 2*time.Second)
	}
}

func cleanupAllocation(ctx context.Context, native *publisheridentity.Native, body controlv1.AllocateServiceRequest) error {
	delay := 100 * time.Millisecond
	for {
		err := native.CleanupServiceAllocation(ctx, body)
		if err == nil {
			return nil
		}
		if !retryAllocation(err) || ctx.Err() != nil {
			return fmt.Errorf("clean up ad-hoc service invocation %s: %w", body.InvocationId, err)
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return errors.Join(fmt.Errorf("clean up ad-hoc service invocation %s: %w", body.InvocationId, err), context.Cause(ctx))
		case <-timer.C:
		}
		delay = min(2*delay, 2*time.Second)
	}
}

func retryAllocation(err error) bool {
	if err == context.Canceled || err == context.DeadlineExceeded {
		return false
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, cause := range joined.Unwrap() {
			if !retryAllocation(cause) {
				return false
			}
		}
		return len(joined.Unwrap()) != 0
	}
	if typed, ok := err.(*failure.Error); ok {
		return typed.Reason() == failure.ServerUnavailable || typed.Reason() == failure.ServerRateLimited
	}
	if wrapped := errors.Unwrap(err); wrapped != nil {
		return retryAllocation(wrapped)
	}
	reason, _ := failure.ReasonOf(err)
	var network net.Error
	return reason == failure.ServerUnavailable || reason == failure.ServerRateLimited ||
		errors.Is(err, clientcontrol.ErrUnavailable) || errors.Is(err, clientcontrol.ErrRateLimited) ||
		errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.As(err, &network)
}
