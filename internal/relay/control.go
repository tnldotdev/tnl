package relay

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/pkg/api/relayv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type ControlClient interface {
	RegisterRelayWithResponse(context.Context, relayv1.RegisterRelayJSONRequestBody, ...relayv1.RequestEditorFn) (*relayv1.RegisterRelayResponse, error)
	RenewRelayWithResponse(context.Context, relayv1.RelayID, relayv1.RenewRelayJSONRequestBody, ...relayv1.RequestEditorFn) (*relayv1.RenewRelayResponse, error)
	DrainRelayWithResponse(context.Context, relayv1.RelayID, relayv1.DrainRelayJSONRequestBody, ...relayv1.RequestEditorFn) (*relayv1.DrainRelayResponse, error)
	ClaimPublisherConnectionWithResponse(context.Context, relayv1.PublisherConnectionID, relayv1.ClaimPublisherConnectionJSONRequestBody, ...relayv1.RequestEditorFn) (*relayv1.ClaimPublisherConnectionResponse, error)
	MarkPublisherConnectionReadyWithResponse(context.Context, relayv1.PublisherConnectionID, relayv1.MarkPublisherConnectionReadyJSONRequestBody, ...relayv1.RequestEditorFn) (*relayv1.MarkPublisherConnectionReadyResponse, error)
	DisconnectPublisherConnectionWithResponse(context.Context, relayv1.PublisherConnectionID, relayv1.DisconnectPublisherConnectionJSONRequestBody, ...relayv1.RequestEditorFn) (*relayv1.DisconnectPublisherConnectionResponse, error)
}

type LoadFunc func() (reportedConnections, reportedStreams int64)

type ControllerConfig struct {
	Client          ControlClient
	Registration    relayv1.RelayRegistration
	RenewalInterval time.Duration
	RetryInterval   time.Duration
	Load            LoadFunc
	LeaseChanged    func(relayv1.RelayLease, relayv1.RelayLease)
	Now             func() time.Time
	Report          func(error)
}

// Controller maintains one exact relay lease and applies it to publisher
// connection transitions.
type Controller struct {
	client          ControlClient
	registration    relayv1.RelayRegistration
	renewalInterval time.Duration
	retryInterval   time.Duration
	load            LoadFunc
	leaseChanged    func(relayv1.RelayLease, relayv1.RelayLease)
	now             func() time.Time
	report          func(error)

	mu    sync.RWMutex
	lease relayv1.RelayLease
}

func NewController(config ControllerConfig) (*Controller, error) {
	if config.Client == nil {
		return nil, errors.New("relay: control client is required")
	}
	if err := validateRegistration(config.Registration); err != nil {
		return nil, err
	}
	if config.RenewalInterval <= 0 || config.RetryInterval <= 0 {
		return nil, errors.New("relay: control renewal and retry intervals must be positive")
	}
	if config.Load == nil {
		config.Load = func() (int64, int64) { return 0, 0 }
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.LeaseChanged == nil {
		config.LeaseChanged = func(relayv1.RelayLease, relayv1.RelayLease) {}
	}
	if config.Report == nil {
		config.Report = func(err error) { log.Printf("relay control: %v", err) }
	}
	registration := config.Registration
	registration.InternalNetworks = slices.Clone(registration.InternalNetworks)
	return &Controller{
		client: config.Client, registration: registration, renewalInterval: config.RenewalInterval,
		retryInterval: config.RetryInterval, load: config.Load, leaseChanged: config.LeaseChanged,
		now: config.Now, report: config.Report,
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
		if lease := c.Lease(); lease.RelayLeaseRevision > 0 && !lease.LeaseExpiresAt.After(c.now()) {
			c.clearLease()
		}
		if !isRetryableControlError(err) {
			c.clearLease()
			return err
		}
		var problem *ControlProblem
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
	response, err := c.client.RegisterRelayWithResponse(ctx, c.registration)
	if err != nil {
		return retryableControlError("register relay", err)
	}
	if response == nil || response.JSON200 == nil {
		return relayResponseError("register relay", response)
	}
	if err := c.setLease(*response.JSON200); err != nil {
		return err
	}
	ticker := time.NewTicker(c.renewalInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
		lease := c.Lease()
		connections, streams := c.load()
		if connections < 0 || streams < 0 {
			return errors.New("relay: reported load cannot be negative")
		}
		response, err := c.client.RenewRelayWithResponse(ctx, c.registration.RelayId, relayv1.RelayRenewal{
			RelayServiceId: c.registration.RelayServiceId, RelayId: c.registration.RelayId,
			RelayRunId: c.registration.RelayRunId, RelayLeaseRevision: lease.RelayLeaseRevision,
			ReportedConnections: connections, ReportedStreams: streams,
		})
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return retryableControlError("renew relay", err)
		}
		if response == nil || response.JSON200 == nil {
			return c.responseError("renew relay", response)
		}
		if err := c.setLease(*response.JSON200); err != nil {
			return err
		}
	}
}

func (c *Controller) Ready(now time.Time) bool {
	lease := c.Lease()
	return lease.RelayLeaseRevision > 0 && !lease.Draining && lease.LeaseExpiresAt.After(now)
}

func (c *Controller) Lease() relayv1.RelayLease {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return cloneLease(c.lease)
}

func (c *Controller) Drain(ctx context.Context, deadline time.Time) error {
	lease := c.Lease()
	if lease.RelayLeaseRevision <= 0 || !deadline.After(c.now()) {
		return errors.New("relay: active lease and future drain deadline are required")
	}
	response, err := c.client.DrainRelayWithResponse(ctx, c.registration.RelayId, relayv1.RelayDrainRequest{
		RelayServiceId: c.registration.RelayServiceId, RelayId: c.registration.RelayId,
		RelayRunId: c.registration.RelayRunId, RelayLeaseRevision: lease.RelayLeaseRevision,
		Deadline: deadline,
	})
	if err != nil {
		return retryableControlError("drain relay", err)
	}
	if response == nil || response.JSON200 == nil {
		return c.responseError("drain relay", response)
	}
	return c.setLease(*response.JSON200)
}

func (c *Controller) ClaimPublisherConnection(
	ctx context.Context,
	ref tunnelv1.PublisherConnectionRef,
	claimID, credential string,
) (relayv1.ClaimedPublisherConnection, error) {
	lease, err := c.activeLease()
	if err != nil {
		return relayv1.ClaimedPublisherConnection{}, err
	}
	if credential == "" {
		return relayv1.ClaimedPublisherConnection{}, errors.New("relay: publisher connection credential is required")
	}
	transition, err := c.connectionTransition(ref, claimID, lease)
	if err != nil {
		return relayv1.ClaimedPublisherConnection{}, err
	}
	request := relayv1.PublisherConnectionClaim{
		RouteSessionId: transition.RouteSessionId, RouteId: transition.RouteId,
		RouteVersion: transition.RouteVersion, PublisherConnectionId: transition.PublisherConnectionId,
		ConnectionSlot:               transition.ConnectionSlot,
		ConnectionAssignmentRevision: transition.ConnectionAssignmentRevision,
		RelayServiceId:               transition.RelayServiceId, RelayId: transition.RelayId,
		RelayRunId: transition.RelayRunId, RelayLeaseRevision: transition.RelayLeaseRevision,
		ClaimId: transition.ClaimId, PublisherConnectionCredential: credential,
	}
	response, err := c.client.ClaimPublisherConnectionWithResponse(ctx, ref.PublisherConnectionID, request)
	if err != nil {
		return relayv1.ClaimedPublisherConnection{}, retryableControlError("claim publisher connection", err)
	}
	if response == nil || response.JSON200 == nil {
		return relayv1.ClaimedPublisherConnection{}, c.responseError("claim publisher connection", response)
	}
	if err := validateClaimedConnection(transition, *response.JSON200, false); err != nil {
		return relayv1.ClaimedPublisherConnection{}, err
	}
	if response.JSON200.State != relayv1.Connected && response.JSON200.State != relayv1.Ready {
		return relayv1.ClaimedPublisherConnection{}, errors.New("relay: control did not claim the publisher connection")
	}
	return *response.JSON200, nil
}

func (c *Controller) MarkPublisherConnectionReady(
	ctx context.Context,
	claimed relayv1.ClaimedPublisherConnection,
) (relayv1.ClaimedPublisherConnection, error) {
	request, err := c.transitionForClaimedConnection(claimed, false)
	if err != nil {
		return relayv1.ClaimedPublisherConnection{}, err
	}
	response, err := c.client.MarkPublisherConnectionReadyWithResponse(ctx, claimed.PublisherConnectionId, request)
	if err != nil {
		return relayv1.ClaimedPublisherConnection{}, retryableControlError("mark publisher connection ready", err)
	}
	if response == nil || response.JSON200 == nil {
		return relayv1.ClaimedPublisherConnection{}, c.responseError("mark publisher connection ready", response)
	}
	if err := validateClaimedConnection(request, *response.JSON200, true); err != nil {
		return relayv1.ClaimedPublisherConnection{}, err
	}
	return *response.JSON200, nil
}

func (c *Controller) DisconnectPublisherConnection(
	ctx context.Context,
	claimed relayv1.ClaimedPublisherConnection,
	unexpected bool,
) (relayv1.ClaimedPublisherConnection, error) {
	transition, err := c.transitionForClaimedConnection(claimed, true)
	if err != nil {
		return relayv1.ClaimedPublisherConnection{}, err
	}
	request := relayv1.PublisherConnectionDisconnect{
		RouteSessionId: transition.RouteSessionId, RouteId: transition.RouteId,
		RouteVersion: transition.RouteVersion, PublisherConnectionId: transition.PublisherConnectionId,
		ConnectionSlot:               transition.ConnectionSlot,
		ConnectionAssignmentRevision: transition.ConnectionAssignmentRevision,
		RelayServiceId:               transition.RelayServiceId, RelayId: transition.RelayId,
		RelayRunId: transition.RelayRunId, RelayLeaseRevision: transition.RelayLeaseRevision,
		ClaimId: transition.ClaimId, Unexpected: unexpected,
	}
	response, err := c.client.DisconnectPublisherConnectionWithResponse(ctx, claimed.PublisherConnectionId, request)
	if err != nil {
		return relayv1.ClaimedPublisherConnection{}, retryableControlError("disconnect publisher connection", err)
	}
	if response == nil || response.JSON200 == nil {
		return relayv1.ClaimedPublisherConnection{}, c.responseError("disconnect publisher connection", response)
	}
	if err := validateClaimedConnection(transition, *response.JSON200, false); err != nil {
		return relayv1.ClaimedPublisherConnection{}, err
	}
	if response.JSON200.State != relayv1.Closed {
		return relayv1.ClaimedPublisherConnection{}, errors.New("relay: control did not close the publisher connection")
	}
	return *response.JSON200, nil
}

func (c *Controller) activeLease() (relayv1.RelayLease, error) {
	if !c.Ready(c.now()) {
		return relayv1.RelayLease{}, errors.New("relay: control lease is unavailable")
	}
	return c.Lease(), nil
}

func (c *Controller) connectionTransition(
	ref tunnelv1.PublisherConnectionRef,
	claimID string,
	lease relayv1.RelayLease,
) (relayv1.PublisherConnectionTransition, error) {
	if err := ref.Validate(); err != nil || claimID == "" || len(claimID) > 256 || strings.TrimSpace(claimID) != claimID ||
		ref.RouteVersion > math.MaxInt64 || ref.ConnectionAssignmentRevision > math.MaxInt64 {
		return relayv1.PublisherConnectionTransition{}, errors.New("relay: publisher connection assignment is invalid")
	}
	if ref.RelayServiceID != c.registration.RelayServiceId {
		return relayv1.PublisherConnectionTransition{}, errors.New("relay: publisher connection is assigned to another relay service")
	}
	return relayv1.PublisherConnectionTransition{
		RouteSessionId: ref.RouteSessionID, RouteId: ref.RouteID, RouteVersion: int64(ref.RouteVersion),
		PublisherConnectionId: ref.PublisherConnectionID, ConnectionSlot: int(ref.ConnectionSlot),
		ConnectionAssignmentRevision: int64(ref.ConnectionAssignmentRevision),
		RelayServiceId:               c.registration.RelayServiceId, RelayId: c.registration.RelayId,
		RelayRunId: c.registration.RelayRunId, RelayLeaseRevision: lease.RelayLeaseRevision,
		ClaimId: claimID,
	}, nil
}

func (c *Controller) transitionForClaimedConnection(
	claimed relayv1.ClaimedPublisherConnection,
	allowDraining bool,
) (relayv1.PublisherConnectionTransition, error) {
	lease := c.Lease()
	if lease.RelayLeaseRevision <= 0 || !lease.LeaseExpiresAt.After(c.now()) || !allowDraining && lease.Draining ||
		claimed.RelayServiceId != c.registration.RelayServiceId || claimed.RelayId != c.registration.RelayId ||
		claimed.RelayRunId != c.registration.RelayRunId || claimed.RelayLeaseRevision != lease.RelayLeaseRevision {
		return relayv1.PublisherConnectionTransition{}, errors.New("relay: claimed publisher connection is not held by the active relay lease")
	}
	request := relayv1.PublisherConnectionTransition{
		RouteSessionId: claimed.RouteSessionId, RouteId: claimed.RouteId, RouteVersion: claimed.RouteVersion,
		PublisherConnectionId: claimed.PublisherConnectionId, ConnectionSlot: claimed.ConnectionSlot,
		ConnectionAssignmentRevision: claimed.ConnectionAssignmentRevision,
		RelayServiceId:               claimed.RelayServiceId, RelayId: claimed.RelayId,
		RelayRunId: claimed.RelayRunId, RelayLeaseRevision: claimed.RelayLeaseRevision,
		ClaimId: claimed.ClaimId,
	}
	if err := validateClaimedConnection(request, claimed, false); err != nil {
		return relayv1.PublisherConnectionTransition{}, err
	}
	return request, nil
}

func validateClaimedConnection(
	request relayv1.PublisherConnectionTransition,
	claimed relayv1.ClaimedPublisherConnection,
	requireReady bool,
) error {
	if claimed.RouteSessionId != request.RouteSessionId || claimed.RouteId != request.RouteId ||
		claimed.RouteVersion != request.RouteVersion || claimed.PublisherConnectionId != request.PublisherConnectionId ||
		claimed.ConnectionSlot != request.ConnectionSlot ||
		claimed.ConnectionAssignmentRevision != request.ConnectionAssignmentRevision ||
		claimed.RelayServiceId != request.RelayServiceId || claimed.RelayId != request.RelayId ||
		claimed.RelayRunId != request.RelayRunId || claimed.RelayLeaseRevision != request.RelayLeaseRevision ||
		claimed.ClaimId != request.ClaimId || claimed.ConnectionSlot < 0 || claimed.ConnectionSlot > 1 ||
		claimed.RelayAddress == "" || claimed.TlsServerName == "" || !claimed.State.Valid() ||
		claimed.PublisherConnectionCredentialExpiresAt.IsZero() || claimed.ConnectedAt.IsZero() {
		return errors.New("relay: control returned an invalid claimed publisher connection")
	}
	if requireReady && (claimed.State != relayv1.Ready || claimed.ReadyAt == nil) {
		return errors.New("relay: control did not mark the publisher connection ready")
	}
	return nil
}

func (c *Controller) setLease(lease relayv1.RelayLease) error {
	if err := validateLease(c.registration, lease, c.now()); err != nil {
		return err
	}
	c.mu.Lock()
	if c.lease.RelayLeaseRevision != 0 && c.lease.RelayLeaseRevision != lease.RelayLeaseRevision {
		c.mu.Unlock()
		return errors.New("relay: control changed the active relay lease revision")
	}
	if c.lease.RelayLeaseRevision == lease.RelayLeaseRevision && c.lease.RelayLeaseRevision != 0 &&
		(lease.RenewedAt.Before(c.lease.RenewedAt) || c.lease.Draining && !lease.Draining) {
		c.mu.Unlock()
		return nil
	}
	previous := cloneLease(c.lease)
	c.lease = cloneLease(lease)
	current := cloneLease(c.lease)
	c.mu.Unlock()
	c.leaseChanged(previous, current)
	return nil
}

func (c *Controller) clearLease() {
	c.mu.Lock()
	previous := cloneLease(c.lease)
	c.lease = relayv1.RelayLease{}
	c.mu.Unlock()
	if previous.RelayLeaseRevision > 0 {
		c.leaseChanged(previous, relayv1.RelayLease{})
	}
}

// ControlProblem is a non-success response from the private relay API.
type ControlProblem struct {
	Operation string
	Status    int
	Problem   *relayv1.Problem
}

func (e *ControlProblem) Error() string {
	if e.Problem != nil {
		return fmt.Sprintf("relay: %s: control returned %d (%s): %s", e.Operation, e.Status, e.Problem.Type, e.Problem.Detail)
	}
	return fmt.Sprintf("relay: %s: control returned HTTP %d", e.Operation, e.Status)
}

type temporaryControlError struct {
	operation string
	err       error
}

func (e *temporaryControlError) Error() string {
	return fmt.Sprintf("relay: %s: %v", e.operation, e.err)
}
func (e *temporaryControlError) Unwrap() error { return e.err }

func retryableControlError(operation string, err error) error {
	return &temporaryControlError{operation: operation, err: err}
}

type controlResponse interface {
	StatusCode() int
	GetApplicationproblemJSONDefault() *relayv1.Problem
}

func relayResponseError(operation string, response controlResponse) error {
	if response == nil || reflect.ValueOf(response).Kind() == reflect.Pointer && reflect.ValueOf(response).IsNil() {
		return &ControlProblem{Operation: operation}
	}
	return &ControlProblem{
		Operation: operation, Status: response.StatusCode(), Problem: response.GetApplicationproblemJSONDefault(),
	}
}

func (c *Controller) responseError(operation string, response controlResponse) error {
	err := relayResponseError(operation, response)
	var problem *ControlProblem
	if errors.As(err, &problem) && problem.Problem != nil &&
		problem.Problem.Type == "https://tnl.dev/problems/relay_lease_stale" {
		c.clearLease()
	}
	return err
}

func isRetryableControlError(err error) bool {
	var temporary *temporaryControlError
	if errors.As(err, &temporary) {
		return true
	}
	var problem *ControlProblem
	return errors.As(err, &problem) &&
		(problem.Status == http.StatusConflict || problem.Status == http.StatusTooManyRequests || problem.Status >= 500)
}

// ControlErrorCode maps private relay API failures onto the tunnel protocol.
func ControlErrorCode(err error) tunnelv1.ErrorCode {
	var temporary *temporaryControlError
	if errors.As(err, &temporary) {
		return tunnelv1.Unavailable
	}
	var problem *ControlProblem
	if !errors.As(err, &problem) || problem.Problem == nil {
		return tunnelv1.Internal
	}
	switch problem.Problem.Type {
	case "https://tnl.dev/problems/unauthenticated",
		"https://tnl.dev/problems/relay_identity_mismatch",
		"https://tnl.dev/problems/invalid_publisher_connection_credential":
		return tunnelv1.Unauthenticated
	case "https://tnl.dev/problems/stale_connection_assignment",
		"https://tnl.dev/problems/relay_lease_stale":
		return tunnelv1.StaleConnectionAssignment
	case "https://tnl.dev/problems/publisher_connection_already_claimed":
		return tunnelv1.DuplicatePublisherConnection
	case "https://tnl.dev/problems/relay_draining":
		return tunnelv1.DrainingPublisherConnection
	case "https://tnl.dev/problems/relay_connection_capacity_exhausted":
		return tunnelv1.CapacityExceeded
	case "https://tnl.dev/problems/publisher_connection_unavailable":
		return tunnelv1.Unavailable
	default:
		return tunnelv1.Internal
	}
}

func validateRegistration(registration relayv1.RelayRegistration) error {
	for _, value := range []string{
		registration.RelayServiceId, registration.RelayId, registration.RelayRunId,
		registration.RelayAddress, registration.TlsServerName, registration.InternalRelayAddress,
	} {
		if value == "" || len(value) > 256 || strings.TrimSpace(value) != value {
			return errors.New("relay: registration identifiers are required")
		}
	}
	if registration.ProtocolVersion <= 0 || registration.ConnectionCapacity <= 0 || registration.StreamCapacity <= 0 {
		return errors.New("relay: registration protocol and capacities must be positive")
	}
	if registration.InternalNetworks == nil || len(registration.InternalNetworks) > 64 {
		return errors.New("relay: registration internal networks are invalid")
	}
	seen := make(map[netip.Prefix]struct{}, len(registration.InternalNetworks))
	for _, value := range registration.InternalNetworks {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix != prefix.Masked() {
			return errors.New("relay: registration internal network is invalid")
		}
		if _, exists := seen[prefix]; exists {
			return errors.New("relay: registration internal networks contain a duplicate")
		}
		seen[prefix] = struct{}{}
	}
	return nil
}

func validateLease(registration relayv1.RelayRegistration, lease relayv1.RelayLease, now time.Time) error {
	if lease.RelayServiceId != registration.RelayServiceId || lease.RelayId != registration.RelayId ||
		lease.RelayRunId != registration.RelayRunId || lease.ProtocolVersion != registration.ProtocolVersion ||
		lease.RelayAddress != registration.RelayAddress || lease.TlsServerName != registration.TlsServerName ||
		lease.InternalRelayAddress != registration.InternalRelayAddress ||
		!slices.Equal(lease.InternalNetworks, registration.InternalNetworks) ||
		lease.ConnectionCapacity != registration.ConnectionCapacity || lease.StreamCapacity != registration.StreamCapacity {
		return errors.New("relay: control lease does not match registration")
	}
	if lease.RelayLeaseRevision <= 0 || lease.RegisteredAt.IsZero() || lease.RenewedAt.Before(lease.RegisteredAt) ||
		!lease.LeaseExpiresAt.After(now) || lease.Draining != (lease.DrainDeadline != nil) {
		return errors.New("relay: control returned an invalid relay lease")
	}
	return nil
}

func cloneLease(source relayv1.RelayLease) relayv1.RelayLease {
	result := source
	result.InternalNetworks = slices.Clone(source.InternalNetworks)
	if source.ObservedAddress != nil {
		value := *source.ObservedAddress
		result.ObservedAddress = &value
	}
	if source.DrainDeadline != nil {
		value := *source.DrainDeadline
		result.DrainDeadline = &value
	}
	return result
}
