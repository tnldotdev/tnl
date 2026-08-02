package relay

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/pkg/api/relayv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type ControlClient interface {
	RegisterRelay(context.Context, relayv1.RelayRegistration) (relayv1.RelayLease, error)
	RenewRelay(context.Context, relayv1.RelayID, relayv1.RelayRenewal) (relayv1.RelayLease, error)
	DrainRelay(context.Context, relayv1.RelayID, relayv1.RelayDrainRequest) (relayv1.RelayLease, error)
	GetRelayServiceCertificate(context.Context, relayv1.RelayServiceID, relayv1.GetRelayServiceCertificateParams) (relayv1.RelayServiceCertificate, error)
	ClaimPublisherConnection(context.Context, relayv1.PublisherConnectionID, relayv1.PublisherConnectionClaim) (relayv1.ClaimedPublisherConnection, error)
	MarkPublisherConnectionReady(context.Context, relayv1.PublisherConnectionID, relayv1.PublisherConnectionTransition) (relayv1.ClaimedPublisherConnection, error)
	DisconnectPublisherConnection(context.Context, relayv1.PublisherConnectionID, relayv1.PublisherConnectionDisconnect) (relayv1.ClaimedPublisherConnection, error)
}

type LoadFunc func() (reportedConnections, reportedStreams int64)

type ControllerConfig struct {
	Client             ControlClient
	Registration       relayv1.RelayRegistration
	RenewalInterval    time.Duration
	RetryInterval      time.Duration
	Load               LoadFunc
	LeaseChanged       func(relayv1.RelayLease, relayv1.RelayLease)
	CertificateChanged func(relayv1.RelayServiceCertificate) error
	Now                func() time.Time
	Report             func(error)
}

// Controller maintains one exact relay lease and applies it to publisher
// connection transitions.
type Controller struct {
	client             ControlClient
	registration       relayv1.RelayRegistration
	renewalInterval    time.Duration
	retryInterval      time.Duration
	load               LoadFunc
	leaseChanged       func(relayv1.RelayLease, relayv1.RelayLease)
	certificateChanged func(relayv1.RelayServiceCertificate) error
	now                func() time.Time
	report             func(error)

	mu                  sync.RWMutex
	lease               relayv1.RelayLease
	certificateNotAfter time.Time
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
		certificateChanged: config.CertificateChanged, now: config.Now, report: config.Report,
	}, nil
}

func (c *Controller) Run(ctx context.Context) error {
	for {
		err := c.runOnce(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if c.Lease().Draining {
			<-ctx.Done()
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
	if c.Lease().Draining {
		<-ctx.Done()
		return nil
	}
	lease, err := c.client.RegisterRelay(ctx, c.registration)
	if err != nil {
		return relayControlError("register relay", err)
	}
	if err := c.setLease(lease); err != nil {
		return err
	}
	if c.certificateChanged != nil {
		if err := c.refreshCertificate(ctx, lease); err != nil {
			return err
		}
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
		lease, err := c.client.RenewRelay(ctx, c.registration.RelayId, relayv1.RelayRenewal{
			RelayServiceId: c.registration.RelayServiceId, RelayId: c.registration.RelayId,
			RelayRunId: c.registration.RelayRunId, RelayLeaseRevision: lease.RelayLeaseRevision,
			ReportedConnections: connections, ReportedStreams: streams,
		})
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return c.responseError("renew relay", err)
		}
		if err := c.setLease(lease); err != nil {
			return err
		}
		if c.certificateChanged != nil && !c.certificateCurrent(c.now().Add(24*time.Hour)) {
			if err := c.refreshCertificate(ctx, lease); err != nil {
				return err
			}
		}
	}
}

func (c *Controller) Ready(now time.Time) bool {
	lease := c.Lease()
	return lease.RelayLeaseRevision > 0 && !lease.Draining && lease.LeaseExpiresAt.After(now) &&
		(c.certificateChanged == nil || c.certificateCurrent(now))
}

func (c *Controller) refreshCertificate(ctx context.Context, lease relayv1.RelayLease) error {
	certificate, err := c.client.GetRelayServiceCertificate(ctx, lease.RelayServiceId, relayv1.GetRelayServiceCertificateParams{
		RelayId: lease.RelayId, RelayRunId: lease.RelayRunId, RelayLeaseRevision: lease.RelayLeaseRevision,
	})
	if err != nil {
		return c.responseError("get relay transport certificate", err)
	}
	if certificate.RelayServiceId != lease.RelayServiceId || certificate.TlsServerName != lease.TlsServerName ||
		!certificate.NotAfter.After(c.now()) {
		return errors.New("relay: control returned invalid relay transport certificate metadata")
	}
	if err := c.certificateChanged(certificate); err != nil {
		return fmt.Errorf("relay: install relay transport certificate: %w", err)
	}
	c.mu.Lock()
	c.certificateNotAfter = certificate.NotAfter
	c.mu.Unlock()
	return nil
}

func (c *Controller) certificateCurrent(at time.Time) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.certificateNotAfter.After(at)
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
	updated, err := c.client.DrainRelay(ctx, c.registration.RelayId, relayv1.RelayDrainRequest{
		RelayServiceId: c.registration.RelayServiceId, RelayId: c.registration.RelayId,
		RelayRunId: c.registration.RelayRunId, RelayLeaseRevision: lease.RelayLeaseRevision,
		Deadline: deadline,
	})
	if err != nil {
		return c.responseError("drain relay", err)
	}
	return c.setLease(updated)
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
	claimed, err := c.client.ClaimPublisherConnection(ctx, ref.PublisherConnectionID, request)
	if err != nil {
		return relayv1.ClaimedPublisherConnection{}, c.responseError("claim publisher connection", err)
	}
	if err := validateClaimedConnection(transition, claimed, false); err != nil {
		return relayv1.ClaimedPublisherConnection{}, err
	}
	if claimed.State != relayv1.Connected && claimed.State != relayv1.Ready {
		return relayv1.ClaimedPublisherConnection{}, errors.New("relay: control did not claim the publisher connection")
	}
	return claimed, nil
}

func (c *Controller) MarkPublisherConnectionReady(
	ctx context.Context,
	claimed relayv1.ClaimedPublisherConnection,
) (relayv1.ClaimedPublisherConnection, error) {
	request, err := c.transitionForClaimedConnection(claimed, false)
	if err != nil {
		return relayv1.ClaimedPublisherConnection{}, err
	}
	updated, err := c.client.MarkPublisherConnectionReady(ctx, claimed.PublisherConnectionId, request)
	if err != nil {
		return relayv1.ClaimedPublisherConnection{}, c.responseError("mark publisher connection ready", err)
	}
	if err := validateClaimedConnection(request, updated, true); err != nil {
		return relayv1.ClaimedPublisherConnection{}, err
	}
	return updated, nil
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
	updated, err := c.client.DisconnectPublisherConnection(ctx, claimed.PublisherConnectionId, request)
	if err != nil {
		return relayv1.ClaimedPublisherConnection{}, c.responseError("disconnect publisher connection", err)
	}
	if err := validateClaimedConnection(transition, updated, false); err != nil {
		return relayv1.ClaimedPublisherConnection{}, err
	}
	if updated.State != relayv1.Closed {
		return relayv1.ClaimedPublisherConnection{}, errors.New("relay: control did not close the publisher connection")
	}
	return updated, nil
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
	// Drain acknowledgement is terminal for this process run, even after expiry.
	if c.lease.Draining {
		c.mu.Unlock()
		return
	}
	previous := cloneLease(c.lease)
	c.lease = relayv1.RelayLease{}
	c.mu.Unlock()
	if previous.RelayLeaseRevision > 0 {
		c.leaseChanged(previous, relayv1.RelayLease{})
	}
}

// ControlProblemError is a non-success response from the private relay API.
type ControlProblemError struct {
	Operation string
	Status    int
	Problem   *relayv1.Problem
}

func (e *ControlProblemError) Error() string {
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

func relayControlError(operation string, err error) error {
	var problem *serviceapi.ProblemError
	if !errors.As(err, &problem) {
		return retryableControlError(operation, err)
	}
	var body *relayv1.Problem
	if problem.Type != "" {
		body = &relayv1.Problem{
			Status: problem.Status, Type: problem.Type, Title: problem.Title, Detail: problem.Detail,
		}
	}
	return &ControlProblemError{Operation: operation, Status: problem.Status, Problem: body}
}

func (c *Controller) responseError(operation string, err error) error {
	err = relayControlError(operation, err)
	var problem *ControlProblemError
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
	var problem *ControlProblemError
	return errors.As(err, &problem) &&
		(problem.Status == http.StatusConflict || problem.Status == http.StatusTooManyRequests || problem.Status >= 500)
}

// ControlErrorCode maps private relay API failures onto the tunnel protocol.
func ControlErrorCode(err error) tunnelv1.ErrorCode {
	var temporary *temporaryControlError
	if errors.As(err, &temporary) {
		return tunnelv1.Unavailable
	}
	var problem *ControlProblemError
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
