package ingress

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
)

const routingTablePageSize = 1000

// ErrIngressLeaseLost ends this process run. Its accounting identity cannot be
// reused after expiry; the process supervisor must start a new run.
var ErrIngressLeaseLost = errors.New("ingress: lease lost; restart the process with a new run ID")

type ControlClient interface {
	RegisterIngress(context.Context, ingressv1.IngressRegistration) (ingressv1.IngressLease, error)
	RenewIngress(context.Context, ingressv1.IngressID, ingressv1.IngressRenewal) (ingressv1.IngressLease, error)
	DrainIngress(context.Context, ingressv1.IngressID, ingressv1.IngressDrainRequest) (ingressv1.IngressLease, error)
	GetIngressRoutingTableSnapshot(context.Context, ingressv1.IngressID, ingressv1.GetIngressRoutingTableSnapshotParams) (ingressv1.IngressRoutingTableSnapshot, error)
	GetIngressRoutingTableEvents(context.Context, ingressv1.IngressID, ingressv1.GetIngressRoutingTableEventsParams) (ingressv1.IngressRoutingTablePage, error)
	ReportIngressUsage(context.Context, ingressv1.IngressID, ingressv1.IngressUsageReportBatch) error
	ObserveRouteRecovery(context.Context, ingressv1.IngressID, int64, ingressv1.RouteRecoveryObservationRequest) (ingressv1.RouteRecoveryObservation, error)
}

type IngressLoadFunc func() int64

type OperationObserver interface {
	ObserveOperation(operation string, err error, elapsed time.Duration)
}

type ControllerConfig struct {
	Client          ControlClient
	RoutingTable    *RoutingTable
	Registration    ingressv1.IngressRegistration
	RenewalInterval time.Duration
	RetryInterval   time.Duration
	RoutingWait     time.Duration
	Load            IngressLoadFunc
	Now             func() time.Time
	Report          func(error)
	Observer        OperationObserver
}

// Controller maintains one exact ingress lease and its routing table.
type Controller struct {
	client          ControlClient
	routingTable    *RoutingTable
	registration    ingressv1.IngressRegistration
	renewalInterval time.Duration
	retryInterval   time.Duration
	routingWait     string
	load            IngressLoadFunc
	now             func() time.Time
	report          func(error)
	observer        OperationObserver

	mu                  sync.RWMutex
	lease               ingressv1.IngressLease
	routingTableCurrent bool
	leaseLost           bool
	routingStatus       observability.IngressRoutingSnapshot
}

func NewController(config ControllerConfig) (*Controller, error) {
	if config.Client == nil || config.RoutingTable == nil {
		return nil, errors.New("ingress: control client and routing table are required")
	}
	if err := validateIngressRegistration(config.Registration); err != nil {
		return nil, err
	}
	if config.RenewalInterval <= 0 || config.RetryInterval <= 0 {
		return nil, errors.New("ingress: control renewal and retry intervals must be positive")
	}
	if config.RoutingWait <= 0 || config.RoutingWait > 25*time.Second || config.RoutingWait%time.Second != 0 {
		return nil, errors.New("ingress: routing wait must be a whole-second duration between 1s and 25s")
	}
	if config.Load == nil {
		config.Load = func() int64 { return 0 }
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Report == nil {
		config.Report = func(err error) { log.Printf("ingress control: %v", err) }
	}
	return &Controller{
		client: config.Client, routingTable: config.RoutingTable, registration: config.Registration,
		renewalInterval: config.RenewalInterval, retryInterval: config.RetryInterval,
		routingWait: config.RoutingWait.String(), load: config.Load, now: config.Now, report: config.Report,
		observer: config.Observer,
	}, nil
}

func (c *Controller) Run(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan error, 2)
	go func() { results <- c.run(runCtx) }()
	go func() { results <- c.watchLease(runCtx) }()
	err := <-results
	cancel()
	other := <-results
	c.clearLease()
	if ctx.Err() != nil {
		return nil
	}
	return errors.Join(err, other)
}

func (c *Controller) watchLease(ctx context.Context) error {
	for {
		c.mu.Lock()
		delay := c.retryInterval
		if c.lease.IngressLeaseRevision != 0 {
			delay = c.lease.LeaseExpiresAt.Sub(c.now())
			if delay <= 0 {
				c.leaseLost = true
			}
		}
		lost := c.leaseLost
		c.mu.Unlock()
		if lost {
			return ErrIngressLeaseLost
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

func (c *Controller) run(ctx context.Context) error {
	for {
		err := c.runOnce(ctx)
		if ctx.Err() != nil {
			return nil
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
	acknowledge := make(chan struct{}, 1)
	if err := c.loadSnapshot(ctx, acknowledge); err != nil {
		return err
	}
	cycleCtx, cancel := context.WithCancel(ctx)
	results := make(chan error, 2)
	go func() { results <- c.renewLoop(cycleCtx, acknowledge) }()
	go func() { results <- c.routingLoop(cycleCtx, acknowledge) }()
	err := <-results
	cancel()
	err = errors.Join(err, <-results)
	if ctx.Err() != nil {
		return nil
	}
	return err
}

func (c *Controller) register(ctx context.Context) error {
	if lease := c.Lease(); lease.IngressLeaseRevision != 0 && !lease.LeaseExpiresAt.After(c.now()) {
		return ErrIngressLeaseLost
	}
	lease, err := c.client.RegisterIngress(ctx, c.registration)
	if err != nil {
		return c.responseError("register ingress", err)
	}
	return c.setLease(lease)
}

func (c *Controller) renewLoop(ctx context.Context, acknowledge <-chan struct{}) error {
	periodic := time.NewTimer(c.renewalInterval)
	defer periodic.Stop()
	acknowledged := c.Lease().RoutingTableRevision
	for {
		urgent := false
		select {
		case <-ctx.Done():
			return nil
		case <-acknowledge:
			// Combine challenge bursts without delaying a periodic renewal.
			// Routing keeps applying pages while this one renewal path waits.
			batch := time.NewTimer(min(100*time.Millisecond, c.renewalInterval))
			select {
			case <-ctx.Done():
				batch.Stop()
				return nil
			case <-batch.C:
				urgent = true
			case <-periodic.C:
			}
			batch.Stop()
		case <-periodic.C:
		}
		select {
		case <-acknowledge:
		default:
		}
		lease := c.Lease()
		revision, initialized := c.routingTable.Revision()
		if !initialized {
			return ErrRoutingTableNotInitialized
		}
		if urgent && revision <= acknowledged {
			continue
		}
		connections := c.load()
		if connections < 0 {
			return errors.New("ingress: reported connection count cannot be negative")
		}
		started := time.Now()
		lease, err := c.client.RenewIngress(ctx, c.registration.IngressId, ingressv1.IngressRenewal{
			IngressId: c.registration.IngressId, IngressRunId: c.registration.IngressRunId,
			IngressLeaseRevision: lease.IngressLeaseRevision, ReportedConnections: connections,
			RoutingTableRevision: revision,
		})
		c.observeOperation("IngressRenewLease", err, started)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return c.responseError("renew ingress", err)
		}
		if err := c.setLease(lease); err != nil {
			return err
		}
		acknowledged = revision
		periodic.Reset(c.renewalInterval)
	}
}

func (c *Controller) routingLoop(ctx context.Context, acknowledge chan<- struct{}) error {
	for {
		revision, initialized := c.routingTable.Revision()
		if !initialized {
			return ErrRoutingTableNotInitialized
		}
		limit, wait := routingTablePageSize, c.routingWait
		lease := c.Lease()
		started := time.Now()
		page, err := c.client.GetIngressRoutingTableEvents(
			ctx,
			c.registration.IngressId,
			ingressv1.GetIngressRoutingTableEventsParams{
				IngressRunId: c.registration.IngressRunId, IngressLeaseRevision: lease.IngressLeaseRevision,
				After: revision, Limit: &limit, Wait: &wait,
			},
		)
		c.observeOperation("IngressFetchEvents", err, started)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var problem *serviceapi.ProblemError
			if errors.As(err, &problem) && problem.Status == http.StatusConflict &&
				problem.Type == "https://tnl.dev/problems/routing_table_resnapshot_required" {
				c.mu.Lock()
				c.routingStatus.Resnapshots++
				c.routingStatus.CaughtUp = false
				c.mu.Unlock()
				c.markRoutingTableCurrent(false)
				if err := c.loadSnapshot(ctx, acknowledge); err != nil {
					return err
				}
				continue
			}
			c.routingUpdateFailed()
			return c.responseError("read ingress routing table", err)
		}
		started = time.Now()
		err = c.routingTable.ApplyPage(revision, page)
		c.observeOperation("IngressApplyEvents", err, started)
		if err != nil {
			c.routingUpdateFailed()
			return fmt.Errorf("ingress: apply routing-table page: %w", err)
		}
		c.routingChecked(page.ThroughRevision, page.NextRevision, !page.More)
		requestChallengeAcknowledgment(page.Events, acknowledge)
	}
}

func requestChallengeAcknowledgment(events []ingressv1.IngressRoutingTableEvent, acknowledge chan<- struct{}) {
	if slices.ContainsFunc(events, func(event ingressv1.IngressRoutingTableEvent) bool { return event.Kind == ingressv1.ChallengeUpsert }) {
		select {
		case acknowledge <- struct{}{}:
		default:
		}
	}
}

func (c *Controller) loadSnapshot(ctx context.Context, acknowledge chan<- struct{}) error {
	lease := c.Lease()
	started := time.Now()
	snapshot, err := c.client.GetIngressRoutingTableSnapshot(
		ctx,
		c.registration.IngressId,
		ingressv1.GetIngressRoutingTableSnapshotParams{
			IngressRunId: c.registration.IngressRunId, IngressLeaseRevision: lease.IngressLeaseRevision,
		},
	)
	c.observeOperation("IngressFetchSnapshot", err, started)
	if err != nil {
		if ctx.Err() == nil {
			c.routingUpdateFailed()
		}
		return c.responseError("read ingress routing-table snapshot", err)
	}
	started = time.Now()
	err = c.routingTable.ApplySnapshot(snapshot)
	c.observeOperation("IngressApplySnapshot", err, started)
	if err != nil {
		c.routingUpdateFailed()
		return fmt.Errorf("ingress: apply routing-table snapshot: %w", err)
	}
	requestChallengeAcknowledgment(snapshot.Entries, acknowledge)
	c.routingChecked(snapshot.ThroughRevision, snapshot.ThroughRevision, false)
	c.markRoutingTableCurrent(true)
	return nil
}

func (c *Controller) observeOperation(operation string, err error, started time.Time) {
	if c.observer != nil {
		c.observer.ObserveOperation(operation, err, time.Since(started))
	}
}

func (c *Controller) routingChecked(latest, applied int64, caughtUp bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.routingStatus.Initialized = true
	c.routingStatus.LastSuccessfulCheck = c.now()
	c.routingStatus.LatestRevision = max(c.routingStatus.LatestRevision, latest)
	c.routingStatus.AppliedRevision = applied
	c.routingStatus.CaughtUp = caughtUp && applied == c.routingStatus.LatestRevision
	if c.routingStatus.CaughtUp {
		c.routingStatus.LastCaughtUp = c.routingStatus.LastSuccessfulCheck
	}
}

func (c *Controller) routingUpdateFailed() {
	c.mu.Lock()
	c.routingStatus.UpdateFailures++
	c.routingStatus.CaughtUp = false
	c.mu.Unlock()
}

// RoutingStatus reads only local controller state, even during a blocked fetch.
// Lease renewal never advances routing freshness or the observed revision.
func (c *Controller) RoutingStatus() observability.IngressRoutingSnapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.routingStatus
}

func (c *Controller) Ready(now time.Time) bool {
	c.mu.RLock()
	lease := c.lease
	routingTableCurrent := c.routingTableCurrent
	lost := c.leaseLost
	c.mu.RUnlock()
	return !lost && routingTableCurrent && lease.IngressLeaseRevision > 0 && !lease.Draining &&
		lease.LeaseExpiresAt.After(now)
}

func (c *Controller) Lookup(canonicalHostname string, now time.Time) (ingressv1.IngressRoutingTableEntry, bool) {
	if !c.Ready(now) {
		return ingressv1.IngressRoutingTableEntry{}, false
	}
	return c.routingTable.Lookup(canonicalHostname, now)
}

func (c *Controller) LookupChallenge(canonicalHostname string, now time.Time) (ingressv1.IngressRoutingTableEntry, bool) {
	if !c.Ready(now) {
		return ingressv1.IngressRoutingTableEntry{}, false
	}
	return c.routingTable.LookupChallenge(canonicalHostname, now)
}

func (c *Controller) Lease() ingressv1.IngressLease {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return cloneIngressLease(c.lease)
}

func (c *Controller) VisitorNetworkHashKey(at time.Time) ([32]byte, bool) {
	day := at.UTC().Truncate(24 * time.Hour)
	lease := c.Lease()
	for _, candidate := range lease.VisitorNetworkHashKeys {
		if candidate.UtcDate.Time.Equal(day) && len(candidate.Key) == 32 {
			return [32]byte(candidate.Key), true
		}
	}
	return [32]byte{}, false
}

func (c *Controller) Drain(ctx context.Context, deadline time.Time) error {
	lease := c.Lease()
	if lease.IngressLeaseRevision <= 0 || !deadline.After(c.now()) {
		return errors.New("ingress: active lease and future drain deadline are required")
	}
	updated, err := c.client.DrainIngress(ctx, c.registration.IngressId, ingressv1.IngressDrainRequest{
		IngressId: c.registration.IngressId, IngressRunId: c.registration.IngressRunId,
		IngressLeaseRevision: lease.IngressLeaseRevision, Deadline: deadline,
	})
	if err != nil {
		return c.responseError("drain ingress", err)
	}
	return c.setLease(updated)
}

func (c *Controller) ReportUsage(ctx context.Context, batch usageReportBatch) error {
	lease := c.Lease()
	if lease.IngressLeaseRevision <= 0 || !lease.LeaseExpiresAt.After(c.now()) {
		return errors.New("ingress: control lease is unavailable")
	}
	err := c.client.ReportIngressUsage(ctx, c.registration.IngressId, ingressv1.IngressUsageReportBatch{
		IngressId: c.registration.IngressId, IngressRunId: c.registration.IngressRunId,
		IngressLeaseRevision: lease.IngressLeaseRevision, Reports: batch.reports,
		ObservedThrough: batch.observedThrough, Complete: batch.complete,
	})
	if err != nil {
		return ingressControlError("report ingress usage", err)
	}
	return nil
}

func (c *Controller) ObserveRecovery(
	ctx context.Context,
	routeID string,
	routeVersion, recoveryEpisodeID uint64,
	observedAt time.Time,
) (ingressv1.RouteRecoveryObservation, error) {
	if routeID == "" || routeVersion == 0 || routeVersion > math.MaxInt64 || recoveryEpisodeID == 0 ||
		recoveryEpisodeID > math.MaxInt64 || observedAt.IsZero() {
		return ingressv1.RouteRecoveryObservation{}, errors.New("ingress: route recovery observation is invalid")
	}
	lease := c.Lease()
	if lease.IngressLeaseRevision <= 0 || !lease.LeaseExpiresAt.After(c.now()) {
		return ingressv1.RouteRecoveryObservation{}, errors.New("ingress: control lease is unavailable")
	}
	observation, err := c.client.ObserveRouteRecovery(
		ctx, c.registration.IngressId, int64(recoveryEpisodeID), ingressv1.RouteRecoveryObservationRequest{
			IngressId: c.registration.IngressId, IngressRunId: c.registration.IngressRunId,
			IngressLeaseRevision: lease.IngressLeaseRevision, RouteId: routeID,
			RouteVersion: int64(routeVersion), ObservedAt: observedAt,
		},
	)
	if err != nil {
		return ingressv1.RouteRecoveryObservation{}, ingressControlError("observe route recovery", err)
	}
	if observation.RecoveryEpisodeId != int64(recoveryEpisodeID) || observation.RouteId != routeID ||
		observation.RouteVersion != int64(routeVersion) || observation.OpenedAt.IsZero() ||
		observation.ObservedAt.IsZero() || observation.ObservedSeconds < 0 {
		return ingressv1.RouteRecoveryObservation{}, errors.New("ingress: control returned an invalid route recovery observation")
	}
	return observation, nil
}

func (c *Controller) setLease(lease ingressv1.IngressLease) error {
	now := c.now()
	if !lease.LeaseExpiresAt.After(now) {
		return ErrIngressLeaseLost
	}
	if err := validateIngressLease(c.registration, lease, now); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now = c.now()
	if c.leaseLost || !lease.LeaseExpiresAt.After(now) || c.lease.IngressLeaseRevision != 0 && !c.lease.LeaseExpiresAt.After(now) {
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
	c.lease = cloneIngressLease(lease)
	return nil
}

func (c *Controller) clearLease() {
	c.mu.Lock()
	c.lease = ingressv1.IngressLease{}
	c.routingTableCurrent = false
	c.routingStatus.CaughtUp = false
	c.mu.Unlock()
}

func (c *Controller) markRoutingTableCurrent(current bool) {
	c.mu.Lock()
	c.routingTableCurrent = current
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
	var problem *serviceapi.ProblemError
	if !errors.As(err, &problem) {
		return retryableIngressControlError(operation, err)
	}
	var body *ingressv1.Problem
	if problem.Type != "" {
		body = &ingressv1.Problem{
			Status: problem.Status, Type: problem.Type, Title: problem.Title, Detail: problem.Detail,
		}
	}
	return &ControlProblemError{Operation: operation, Status: problem.Status, Problem: body}
}

func (c *Controller) responseError(operation string, err error) error {
	err = ingressControlError(operation, err)
	var problem *ControlProblemError
	if errors.As(err, &problem) && problem.Problem != nil &&
		problem.Problem.Type == "https://tnl.dev/problems/ingress_lease_stale" {
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
	if lease.IngressId != registration.IngressId || lease.IngressRunId != registration.IngressRunId ||
		lease.ProtocolVersion != registration.ProtocolVersion || lease.ConnectionCapacity != registration.ConnectionCapacity {
		return errors.New("ingress: control lease does not match registration")
	}
	if lease.IngressLeaseRevision <= 0 || lease.RoutingTableRevision < 0 || lease.RegisteredAt.IsZero() ||
		lease.RenewedAt.Before(lease.RegisteredAt) || !lease.LeaseExpiresAt.After(now) ||
		lease.Draining != (lease.DrainDeadline != nil) || len(lease.VisitorNetworkHashKeys) != 2 {
		return errors.New("ingress: control returned an invalid ingress lease")
	}
	day := now.UTC().Truncate(24 * time.Hour)
	for index, key := range lease.VisitorNetworkHashKeys {
		if len(key.Key) != 32 || !key.UtcDate.Time.Equal(day.AddDate(0, 0, index)) {
			return errors.New("ingress: control returned invalid visitor network hash keys")
		}
	}
	return nil
}

func cloneIngressLease(source ingressv1.IngressLease) ingressv1.IngressLease {
	result := source
	if source.DrainDeadline != nil {
		value := *source.DrainDeadline
		result.DrainDeadline = &value
	}
	result.VisitorNetworkHashKeys = make([]ingressv1.VisitorNetworkHashKey, len(source.VisitorNetworkHashKeys))
	for index, key := range source.VisitorNetworkHashKeys {
		result.VisitorNetworkHashKeys[index] = key
		result.VisitorNetworkHashKeys[index].Key = slices.Clone(key.Key)
	}
	return result
}
