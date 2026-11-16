package ingress

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/observability/operatorlog"
	"github.com/tnldotdev/tnl/internal/policy/controloutage"
	serverhttp "github.com/tnldotdev/tnl/internal/serverhttp"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
)

// ErrIngressLeaseLost ends this process run. its lease identity cannot be
// reused after expiry; the process supervisor must start a new run.
var ErrIngressLeaseLost = errors.New("ingress: lease lost; restart the process with a new run ID")

type ControlClient interface {
	RegisterIngress(context.Context, ingressv1.IngressRegistration) (ingressv1.IngressLease, error)
	RenewIngress(context.Context, ingressv1.IngressID, ingressv1.IngressRenewal) (ingressv1.IngressLease, error)
	DrainIngress(context.Context, ingressv1.IngressID, ingressv1.IngressDrainRequest) (ingressv1.IngressLease, error)
	ObserveServiceRecovery(context.Context, ingressv1.IngressID, int64, ingressv1.ServiceRecoveryObservationRequest) (ingressv1.ServiceRecoveryObservation, error)
}

type IngressLoadFunc func() int64

type OperationObserver interface {
	ObserveOperationContext(context.Context, observability.ServerOperation, error, time.Duration)
}

type ControllerConfig struct {
	// lease established runs before the first lease becomes visible to visitors.
	// renewal never replaces a process run's lease or audit identity.
	LeaseEstablished func(ingressv1.IngressLease) error
	Client           ControlClient
	Registration     ingressv1.IngressRegistration
	RenewalInterval  time.Duration
	RetryInterval    time.Duration
	Load             IngressLoadFunc
	Now              func() time.Time
	Report           func(error)
	Observer         OperationObserver
}

// Controller maintains one exact ingress lease.
type Controller struct {
	confirmationMu   sync.Mutex
	confirmation     controloutage.Confirmation
	client           ControlClient
	registration     ingressv1.IngressRegistration
	renewalInterval  time.Duration
	retryInterval    time.Duration
	load             IngressLoadFunc
	now              func() time.Time
	report           func(error)
	observer         OperationObserver
	leaseEstablished func(ingressv1.IngressLease) error
	mu               sync.RWMutex
	lease            ingressv1.IngressLease
	leaseLost        bool
	leaseUpdated     chan struct{}
}

func NewController(config ControllerConfig) (*Controller, error) {
	if config.Client == nil {
		return nil, errors.New("ingress: control client is required")
	}
	if err := validateIngressRegistration(config.Registration); err != nil {
		return nil, err
	}
	if config.RenewalInterval <= 0 || config.RetryInterval <= 0 {
		return nil, errors.New("ingress: control renewal and retry intervals must be positive")
	}
	if config.Load == nil {
		config.Load = func() int64 { return 0 }
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Report == nil {
		config.Report = func(err error) {
			operatorlog.Report("renew ingress lease", failure.ServerControlConnectionFailed, "", err)
		}
	}
	config.Registration.ServicePorts = slices.Clone(config.Registration.ServicePorts)
	c := &Controller{
		client: config.Client, registration: config.Registration,
		renewalInterval: config.RenewalInterval, retryInterval: config.RetryInterval,
		load: config.Load, now: config.Now, report: config.Report,
		observer: config.Observer, leaseEstablished: config.LeaseEstablished,
		leaseUpdated: make(chan struct{}),
	}
	return c, nil
}

func (c *Controller) Run(ctx context.Context) error {
	err := runUntilEitherStops(ctx, c.run, c.watchLease)
	c.clearLease()
	return err
}

// runUntilEitherStops cancels the sibling when one controller loop exits and
// joins both before returning. caller cancellation is a normal shutdown.
func runUntilEitherStops(ctx context.Context, first, second func(context.Context) error) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan error, 2)
	go func() { results <- first(runCtx) }()
	go func() { results <- second(runCtx) }()
	err := <-results
	cancel()
	err = errors.Join(err, <-results)
	if ctx.Err() != nil && failure.Only(err, ctx.Err()) {
		return nil
	}
	return err
}

func (c *Controller) watchLease(ctx context.Context) error {
	for {
		c.mu.Lock()
		delay := c.retryInterval
		if c.lease.IngressLeaseRevision != 0 {
			delay = c.lease.ServingUntil.Sub(c.now())
			if delay <= 0 {
				c.leaseLost = true
			}
		}
		lost := c.leaseLost
		updated := c.leaseUpdated
		c.mu.Unlock()
		if lost {
			return ErrIngressLeaseLost
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-updated:
			timer.Stop()
		case <-timer.C:
		}
	}
}

func (c *Controller) run(ctx context.Context) error {
	for {
		err := c.runOnce(ctx)
		if ctx.Err() != nil {
			if failure.Only(err, ctx.Err()) {
				return nil
			}
			return err
		}
		if err == nil {
			return nil
		}
		if !isRetryableIngressControlError(err) {
			c.clearLease()
			return err
		}
		c.report(err)
		timer := time.NewTimer(c.retryInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

func (c *Controller) runOnce(ctx context.Context) error {
	if err := c.register(ctx); err != nil {
		return err
	}
	return c.renewLoop(ctx)
}

func (c *Controller) register(ctx context.Context) (retErr error) {
	started := time.Now()
	requestStarted := c.now()
	defer func() { c.observeOperation(ctx, observability.OpIngressRegister, retErr, started) }()
	if lease := c.Lease(); lease.IngressLeaseRevision != 0 && !lease.ServingUntil.After(c.now()) {
		return ErrIngressLeaseLost
	}
	lease, err := c.client.RegisterIngress(ctx, c.registration)
	if err != nil {
		return c.responseError("register ingress", err)
	}
	return c.confirmLease(requestStarted, lease)
}

func (c *Controller) renewLoop(ctx context.Context) error {
	periodic := time.NewTimer(c.renewalInterval)
	defer periodic.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-periodic.C:
		}
		lease := c.Lease()
		connections := c.load()
		if connections < 0 {
			return errors.New("ingress: reported connection count cannot be negative")
		}
		started := time.Now()
		requestStarted := c.now()
		lease, err := c.client.RenewIngress(ctx, c.registration.IngressId, ingressv1.IngressRenewal{
			IngressId: c.registration.IngressId, IngressRunId: c.registration.IngressRunId,
			IngressLeaseRevision: lease.IngressLeaseRevision, ReportedConnections: connections,
		})
		c.observeOperation(ctx, observability.OpIngressRenewLease, err, started)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return c.responseError("renew ingress", err)
		}
		if err := c.confirmLease(requestStarted, lease); err != nil {
			return err
		}
		periodic.Reset(c.renewalInterval)
	}
}

func (c *Controller) observeOperation(ctx context.Context, operation observability.ServerOperation, err error, started time.Time) {
	if c.observer != nil {
		c.observer.ObserveOperationContext(ctx, operation, err, time.Since(started))
	}
}

func (c *Controller) Ready(now time.Time) bool {
	c.mu.RLock()
	lease := c.lease
	lost := c.leaseLost
	c.mu.RUnlock()
	return !lost && lease.IngressLeaseRevision > 0 && !lease.Draining && lease.ServingUntil.After(now)
}

func (c *Controller) Lease() ingressv1.IngressLease {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return cloneIngressLease(c.lease)
}

func (c *Controller) Drain(ctx context.Context, deadline time.Time) error {
	started := c.now()
	lease := c.Lease()
	if lease.IngressLeaseRevision <= 0 || !deadline.After(c.now()) {
		return errors.New("ingress: active lease and future drain deadline are required")
	}
	c.mu.Lock()
	c.lease.Draining = true
	c.mu.Unlock()
	updated, err := c.client.DrainIngress(ctx, c.registration.IngressId, ingressv1.IngressDrainRequest{
		IngressId: c.registration.IngressId, IngressRunId: c.registration.IngressRunId,
		IngressLeaseRevision: lease.IngressLeaseRevision, Deadline: deadline,
	})
	if err != nil {
		return c.responseError("drain ingress", err)
	}
	return c.confirmLease(started, updated)
}

func (c *Controller) ObserveRecovery(
	ctx context.Context,
	run ingressv1.ServiceRunReference,
	visitor string,
	recoveryEpisodeID uint64,
	observedAt time.Time,
	sourceEvidence []byte,
) (ingressv1.ServiceRecoveryObservation, error) {
	if run.ServiceId == "" || run.ServiceRunId == "" || run.RunNumber <= 0 || visitor == "" || recoveryEpisodeID == 0 ||
		recoveryEpisodeID > math.MaxInt64 || observedAt.IsZero() || len(sourceEvidence) > 2048 {
		return ingressv1.ServiceRecoveryObservation{}, errors.New("ingress: service recovery observation is invalid")
	}
	lease := c.Lease()
	if lease.IngressLeaseRevision <= 0 || !lease.ServingUntil.After(c.now()) {
		return ingressv1.ServiceRecoveryObservation{}, errors.New("ingress: control lease is unavailable")
	}
	observation, err := c.client.ObserveServiceRecovery(
		ctx, c.registration.IngressId, int64(recoveryEpisodeID), ingressv1.ServiceRecoveryObservationRequest{
			IngressId: c.registration.IngressId, IngressRunId: c.registration.IngressRunId,
			IngressLeaseRevision: lease.IngressLeaseRevision, ServiceId: run.ServiceId, ServiceRunId: run.ServiceRunId,
			RunNumber: run.RunNumber, VisitorConnectionId: visitor, ObservedAt: observedAt, SourceEvidence: sourceEvidence,
		},
	)
	if err != nil {
		return ingressv1.ServiceRecoveryObservation{}, ingressControlError("observe service recovery", err)
	}
	if observation.RecoveryEpisodeId != int64(recoveryEpisodeID) || observation.ServiceId != run.ServiceId || observation.ServiceRunId != run.ServiceRunId ||
		observation.RunNumber != run.RunNumber || observation.OpenedAt.IsZero() ||
		observation.ObservedAt.IsZero() || observation.ObservedSeconds < 0 {
		return ingressv1.ServiceRecoveryObservation{}, errors.New("ingress: control returned an invalid service recovery observation")
	}
	return observation, nil
}

func (c *Controller) confirmLease(started time.Time, lease ingressv1.IngressLease) error {
	c.confirmationMu.Lock()
	defer c.confirmationMu.Unlock()
	next, err := c.confirmation.Confirm(started, lease.RenewedAt, lease.ServingUntil, c.now())
	if err != nil {
		return ErrIngressLeaseLost
	}
	lease.ServingUntil = next.Deadline
	if err := c.setLease(lease); err != nil {
		return err
	}
	c.confirmation = next
	return nil
}

func (c *Controller) setLease(lease ingressv1.IngressLease) error {
	now := c.now()
	if !lease.ServingUntil.After(now) {
		return ErrIngressLeaseLost
	}
	if err := validateIngressLease(c.registration, lease, now); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now = c.now()
	if c.leaseLost || !lease.ServingUntil.After(now) || c.lease.IngressLeaseRevision != 0 && !c.lease.ServingUntil.After(now) {
		c.leaseLost = true
		return ErrIngressLeaseLost
	}
	if c.lease.IngressLeaseRevision != 0 && c.lease.IngressLeaseRevision != lease.IngressLeaseRevision {
		c.leaseLost = true
		return ErrIngressLeaseLost
	}
	if c.lease.IngressLeaseRevision == lease.IngressLeaseRevision && c.lease.IngressLeaseRevision != 0 &&
		(lease.RenewedAt.Before(c.lease.RenewedAt) || c.lease.Draining && !lease.Draining) {
		return nil
	}
	if c.lease.IngressLeaseRevision == 0 && c.leaseEstablished != nil {
		if err := c.leaseEstablished(cloneIngressLease(lease)); err != nil {
			return err
		}
	}
	c.lease = cloneIngressLease(lease)
	if c.leaseUpdated != nil {
		close(c.leaseUpdated)
	}
	c.leaseUpdated = make(chan struct{})
	return nil
}

func (c *Controller) clearLease() {
	c.mu.Lock()
	c.lease = ingressv1.IngressLease{}
	c.mu.Unlock()
}

// ControlProblemError is a non-success response from the private ingress API.
type ControlProblemError struct {
	Operation string
	Status    int
	Problem   *ingressv1.Problem
}

func (e *ControlProblemError) Error() string {
	if e.Problem != nil {
		return fmt.Sprintf("ingress: %s: control returned %d (%s): %s", e.Operation, e.Status, e.Problem.Type, e.Problem.Detail)
	}
	return fmt.Sprintf("ingress: %s: control returned HTTP %d", e.Operation, e.Status)
}

type temporaryIngressControlError struct {
	operation string
	err       error
}

func (e *temporaryIngressControlError) Error() string {
	return fmt.Sprintf("ingress: %s: %v", e.operation, e.err)
}
func (e *temporaryIngressControlError) Unwrap() error { return e.err }

func retryableIngressControlError(operation string, err error) error {
	return &temporaryIngressControlError{operation: operation, err: err}
}

func ingressControlError(operation string, err error) error {
	var problem *serverhttp.ProblemError
	if !errors.As(err, &problem) {
		return retryableIngressControlError(operation, err)
	}
	var body *ingressv1.Problem
	if problem.Type != "" {
		body = &ingressv1.Problem{
			Status: problem.Status, Type: problem.Type, Title: problem.Title, Detail: problem.Detail,
			Code: ingressv1.ProblemCode(problem.Code), RequestId: problem.RequestID,
		}
	}
	return &ControlProblemError{Operation: operation, Status: problem.Status, Problem: body}
}

func (c *Controller) responseError(operation string, err error) error {
	err = ingressControlError(operation, err)
	var problem *ControlProblemError
	if errors.As(err, &problem) && problem.Problem != nil &&
		problem.Problem.Code == ingressv1.IngressLeaseStale {
		c.mu.Lock()
		c.leaseLost = true
		c.mu.Unlock()
		c.clearLease()
		return ErrIngressLeaseLost
	}
	return err
}

func isRetryableIngressControlError(err error) bool {
	if errors.Is(err, ErrIngressLeaseLost) {
		return false
	}
	var temporary *temporaryIngressControlError
	if errors.As(err, &temporary) {
		return true
	}
	var problem *ControlProblemError
	return errors.As(err, &problem) &&
		(problem.Status == http.StatusConflict || problem.Status == http.StatusTooManyRequests || problem.Status >= 500)
}

func validateIngressRegistration(registration ingressv1.IngressRegistration) error {
	for _, value := range []string{registration.IngressId, registration.IngressRunId} {
		if value == "" || len(value) > 256 || strings.TrimSpace(value) != value {
			return errors.New("ingress: registration identifiers are required")
		}
	}
	if registration.ProtocolVersion <= 0 || registration.ConnectionCapacity <= 0 {
		return errors.New("ingress: registration protocol and connection capacity must be positive")
	}
	return nil
}

func validateIngressLease(
	registration ingressv1.IngressRegistration,
	lease ingressv1.IngressLease,
	now time.Time,
) error {
	if lease.Region != registration.Region || lease.IngressId != registration.IngressId || lease.IngressRunId != registration.IngressRunId ||
		lease.ProtocolVersion != registration.ProtocolVersion || lease.ConnectionCapacity != registration.ConnectionCapacity {
		return errors.New("ingress: control lease does not match registration")
	}
	if lease.IngressLeaseRevision <= 0 || lease.RegisteredAt.IsZero() ||
		lease.RenewedAt.Before(lease.RegisteredAt) || !lease.ServingUntil.After(now) ||
		lease.Draining != (lease.DrainDeadline != nil) {
		return errors.New("ingress: control returned an invalid ingress lease")
	}
	return nil
}

func cloneIngressLease(source ingressv1.IngressLease) ingressv1.IngressLease {
	result := source
	if source.DrainDeadline != nil {
		value := *source.DrainDeadline
		result.DrainDeadline = &value
	}
	return result
}
