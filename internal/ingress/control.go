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

	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
)

const routingTablePageSize = 1000

type ControlClient interface {
	RegisterIngressWithResponse(context.Context, ingressv1.RegisterIngressJSONRequestBody, ...ingressv1.RequestEditorFn) (*ingressv1.RegisterIngressResponse, error)
	RenewIngressWithResponse(context.Context, ingressv1.IngressID, ingressv1.RenewIngressJSONRequestBody, ...ingressv1.RequestEditorFn) (*ingressv1.RenewIngressResponse, error)
	DrainIngressWithResponse(context.Context, ingressv1.IngressID, ingressv1.DrainIngressJSONRequestBody, ...ingressv1.RequestEditorFn) (*ingressv1.DrainIngressResponse, error)
	GetIngressRoutingTableSnapshotWithResponse(context.Context, ingressv1.IngressID, *ingressv1.GetIngressRoutingTableSnapshotParams, ...ingressv1.RequestEditorFn) (*ingressv1.GetIngressRoutingTableSnapshotResponse, error)
	GetIngressRoutingTableEventsWithResponse(context.Context, ingressv1.IngressID, *ingressv1.GetIngressRoutingTableEventsParams, ...ingressv1.RequestEditorFn) (*ingressv1.GetIngressRoutingTableEventsResponse, error)
	ReportIngressUsageWithResponse(context.Context, ingressv1.IngressID, ingressv1.ReportIngressUsageJSONRequestBody, ...ingressv1.RequestEditorFn) (*ingressv1.ReportIngressUsageResponse, error)
	ObserveRouteRecoveryWithResponse(context.Context, ingressv1.IngressID, int64, ingressv1.ObserveRouteRecoveryJSONRequestBody, ...ingressv1.RequestEditorFn) (*ingressv1.ObserveRouteRecoveryResponse, error)
}

type IngressLoadFunc func() int64

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

	mu                  sync.RWMutex
	lease               ingressv1.IngressLease
	routingTableCurrent bool
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
	}, nil
}

func (c *Controller) Run(ctx context.Context) error {
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
		var problem *ControlProblemError
		if errors.As(err, &problem) && problem.Status == http.StatusConflict {
			c.clearLease()
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
	if err := c.loadSnapshot(ctx); err != nil {
		return err
	}
	cycleCtx, cancel := context.WithCancel(ctx)
	results := make(chan error, 2)
	go func() { results <- c.renewLoop(cycleCtx) }()
	go func() { results <- c.routingLoop(cycleCtx) }()
	err := <-results
	cancel()
	<-results
	if ctx.Err() != nil {
		return nil
	}
	return err
}

func (c *Controller) register(ctx context.Context) error {
	response, err := c.client.RegisterIngressWithResponse(ctx, c.registration)
	if err != nil {
		return retryableIngressControlError("register ingress", err)
	}
	if response == nil {
		return ingressResponseError("register ingress", 0, nil)
	}
	if response.JSON200 == nil {
		return ingressResponseError("register ingress", response.StatusCode(), response.ApplicationproblemJSONDefault)
	}
	return c.setLease(*response.JSON200)
}

func (c *Controller) renewLoop(ctx context.Context) error {
	ticker := time.NewTicker(c.renewalInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
		lease := c.Lease()
		revision, initialized := c.routingTable.Revision()
		if !initialized {
			return ErrRoutingTableNotInitialized
		}
		connections := c.load()
		if connections < 0 {
			return errors.New("ingress: reported connection count cannot be negative")
		}
		response, err := c.client.RenewIngressWithResponse(ctx, c.registration.IngressId, ingressv1.IngressRenewal{
			IngressId: c.registration.IngressId, IngressRunId: c.registration.IngressRunId,
			IngressLeaseRevision: lease.IngressLeaseRevision, ReportedConnections: connections,
			RoutingTableRevision: revision,
		})
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return retryableIngressControlError("renew ingress", err)
		}
		if response == nil {
			return c.responseError("renew ingress", 0, nil)
		}
		if response.JSON200 == nil {
			return c.responseError("renew ingress", response.StatusCode(), response.ApplicationproblemJSONDefault)
		}
		if err := c.setLease(*response.JSON200); err != nil {
			return err
		}
	}
}

func (c *Controller) routingLoop(ctx context.Context) error {
	for {
		revision, initialized := c.routingTable.Revision()
		if !initialized {
			return ErrRoutingTableNotInitialized
		}
		limit, wait := routingTablePageSize, c.routingWait
		lease := c.Lease()
		response, err := c.client.GetIngressRoutingTableEventsWithResponse(
			ctx,
			c.registration.IngressId,
			&ingressv1.GetIngressRoutingTableEventsParams{
				IngressRunId: c.registration.IngressRunId, IngressLeaseRevision: lease.IngressLeaseRevision,
				After: revision, Limit: &limit, Wait: &wait,
			},
		)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return retryableIngressControlError("read ingress routing table", err)
		}
		if response != nil && response.JSON200 != nil {
			if err := c.routingTable.ApplyPage(revision, *response.JSON200); err != nil {
				return fmt.Errorf("ingress: apply routing-table page: %w", err)
			}
			continue
		}
		if response != nil && response.StatusCode() == http.StatusConflict &&
			response.ApplicationproblemJSON409 != nil &&
			response.ApplicationproblemJSON409.Type == "https://tnl.dev/problems/routing_table_resnapshot_required" {
			c.markRoutingTableCurrent(false)
			if err := c.loadSnapshot(ctx); err != nil {
				return err
			}
			continue
		}
		if response == nil {
			return ingressResponseError("read ingress routing table", 0, nil)
		}
		problem := response.ApplicationproblemJSONDefault
		if response.ApplicationproblemJSON409 != nil {
			problem = response.ApplicationproblemJSON409
		}
		return ingressResponseError("read ingress routing table", response.StatusCode(), problem)
	}
}

func (c *Controller) loadSnapshot(ctx context.Context) error {
	lease := c.Lease()
	response, err := c.client.GetIngressRoutingTableSnapshotWithResponse(
		ctx,
		c.registration.IngressId,
		&ingressv1.GetIngressRoutingTableSnapshotParams{
			IngressRunId: c.registration.IngressRunId, IngressLeaseRevision: lease.IngressLeaseRevision,
		},
	)
	if err != nil {
		return retryableIngressControlError("read ingress routing-table snapshot", err)
	}
	if response == nil {
		return ingressResponseError("read ingress routing-table snapshot", 0, nil)
	}
	if response.JSON200 == nil {
		return ingressResponseError(
			"read ingress routing-table snapshot", response.StatusCode(), response.ApplicationproblemJSONDefault,
		)
	}
	if err := c.routingTable.ApplySnapshot(*response.JSON200); err != nil {
		return fmt.Errorf("ingress: apply routing-table snapshot: %w", err)
	}
	c.markRoutingTableCurrent(true)
	return nil
}

func (c *Controller) Ready(now time.Time) bool {
	c.mu.RLock()
	lease := c.lease
	routingTableCurrent := c.routingTableCurrent
	c.mu.RUnlock()
	return routingTableCurrent && lease.IngressLeaseRevision > 0 && !lease.Draining &&
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
	response, err := c.client.DrainIngressWithResponse(ctx, c.registration.IngressId, ingressv1.IngressDrainRequest{
		IngressId: c.registration.IngressId, IngressRunId: c.registration.IngressRunId,
		IngressLeaseRevision: lease.IngressLeaseRevision, Deadline: deadline,
	})
	if err != nil {
		return retryableIngressControlError("drain ingress", err)
	}
	if response == nil {
		return c.responseError("drain ingress", 0, nil)
	}
	if response.JSON200 == nil {
		return c.responseError("drain ingress", response.StatusCode(), response.ApplicationproblemJSONDefault)
	}
	return c.setLease(*response.JSON200)
}

func (c *Controller) ReportUsage(ctx context.Context, batch usageReportBatch) error {
	lease := c.Lease()
	if lease.IngressLeaseRevision <= 0 || !lease.LeaseExpiresAt.After(c.now()) {
		return errors.New("ingress: control lease is unavailable")
	}
	response, err := c.client.ReportIngressUsageWithResponse(ctx, c.registration.IngressId, ingressv1.IngressUsageReportBatch{
		IngressId: c.registration.IngressId, IngressRunId: c.registration.IngressRunId,
		IngressLeaseRevision: lease.IngressLeaseRevision, Reports: batch.reports,
		ObservedThrough: batch.observedThrough, Complete: batch.complete,
	})
	if err != nil {
		return retryableIngressControlError("report ingress usage", err)
	}
	if response == nil {
		return ingressResponseError("report ingress usage", 0, nil)
	}
	if response.StatusCode() != http.StatusNoContent {
		return ingressResponseError("report ingress usage", response.StatusCode(), response.ApplicationproblemJSONDefault)
	}
	return nil
}

func (c *Controller) ObserveRecovery(
	ctx context.Context,
	routeID string,
	routeVersion, episodeID uint64,
	observedAt time.Time,
) (ingressv1.RouteRecoveryObservation, error) {
	if routeID == "" || routeVersion == 0 || routeVersion > math.MaxInt64 || episodeID == 0 ||
		episodeID > math.MaxInt64 || observedAt.IsZero() {
		return ingressv1.RouteRecoveryObservation{}, errors.New("ingress: route recovery observation is invalid")
	}
	lease := c.Lease()
	if lease.IngressLeaseRevision <= 0 || !lease.LeaseExpiresAt.After(c.now()) {
		return ingressv1.RouteRecoveryObservation{}, errors.New("ingress: control lease is unavailable")
	}
	response, err := c.client.ObserveRouteRecoveryWithResponse(
		ctx, c.registration.IngressId, int64(episodeID), ingressv1.RouteRecoveryObservationRequest{
			IngressId: c.registration.IngressId, IngressRunId: c.registration.IngressRunId,
			IngressLeaseRevision: lease.IngressLeaseRevision, RouteId: routeID,
			RouteVersion: int64(routeVersion), ObservedAt: observedAt,
		},
	)
	if err != nil {
		return ingressv1.RouteRecoveryObservation{}, retryableIngressControlError("observe route recovery", err)
	}
	if response == nil {
		return ingressv1.RouteRecoveryObservation{}, ingressResponseError("observe route recovery", 0, nil)
	}
	if response.JSON200 == nil {
		return ingressv1.RouteRecoveryObservation{}, ingressResponseError(
			"observe route recovery", response.StatusCode(), response.ApplicationproblemJSONDefault,
		)
	}
	observation := *response.JSON200
	if observation.EpisodeId != int64(episodeID) || observation.RouteId != routeID ||
		observation.RouteVersion != int64(routeVersion) || observation.OpenedAt.IsZero() ||
		observation.ObservedAt.IsZero() || observation.ObservedSeconds < 0 {
		return ingressv1.RouteRecoveryObservation{}, errors.New("ingress: control returned an invalid route recovery observation")
	}
	return observation, nil
}

func (c *Controller) setLease(lease ingressv1.IngressLease) error {
	if err := validateIngressLease(c.registration, lease, c.now()); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lease.IngressLeaseRevision != 0 && c.lease.IngressLeaseRevision != lease.IngressLeaseRevision {
		return errors.New("ingress: control changed the active ingress lease revision")
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

func ingressResponseError(operation string, status int, problem *ingressv1.Problem) error {
	return &ControlProblemError{Operation: operation, Status: status, Problem: problem}
}

func (c *Controller) responseError(operation string, status int, problem *ingressv1.Problem) error {
	err := ingressResponseError(operation, status, problem)
	if problem != nil && problem.Type == "https://tnl.dev/problems/ingress_lease_stale" {
		c.clearLease()
	}
	return err
}

func isRetryableIngressControlError(err error) bool {
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
