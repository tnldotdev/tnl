package publication

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/0xcadams/tnl/internal/agent"
	"github.com/0xcadams/tnl/internal/clientstate"
	"github.com/0xcadams/tnl/internal/coreclient"
	"github.com/0xcadams/tnl/internal/credentials"
	"github.com/0xcadams/tnl/internal/localproxy"
	"github.com/0xcadams/tnl/internal/naming"
	"github.com/0xcadams/tnl/pkg/protocol/corev1"
	"github.com/0xcadams/tnl/pkg/protocol/transportv1"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

const heartbeatCallTimeout = 10 * time.Second

var (
	heartbeatInterval = 15 * time.Second
	activationRetry   = 2 * time.Second
	renewalRetry      = time.Minute
)

type Core interface {
	CreateRoute(context.Context, corev1.CreateRouteRequest) (corev1.LeaseSetup, error)
	ListRoutes(context.Context) ([]corev1.Route, error)
	AcquireLease(context.Context, string, credentials.RouteToken) (corev1.LeaseSetup, error)
	RegisterTransport(context.Context, string, uint64, credentials.LeaseToken, transportv1.TailcatDescriptor) error
	Ready(context.Context, string, uint64, credentials.LeaseToken) error
	Heartbeat(context.Context, string, uint64, credentials.LeaseToken) (corev1.HeartbeatResponse, error)
	CreateCertificateOrder(context.Context, string, uint64, credentials.LeaseToken, string, []byte) (corev1.CertificateOrder, error)
	CertificateChallengeReady(context.Context, string, credentials.LeaseToken) (corev1.CertificateOrder, error)
	CertificateChallengeRemoved(context.Context, string, credentials.LeaseToken) error
	CertificateInstalled(context.Context, string, uint64, string, credentials.LeaseToken) error
}

type PublicConfig struct {
	Core         Core
	Hostname     string
	Target       string
	Certificate  tls.Certificate
	State        *clientstate.Store
	ACMEProfile  string
	RelayProfile string
	Profiles     map[string]*tailcfg.DERPRegion
	DrainTime    time.Duration
	Logf         logger.Logf
	OnReady      func(string)
}

func RunPublic(ctx context.Context, config PublicConfig) error {
	if config.Core == nil {
		return errors.New("agent: core client is required")
	}
	if config.DrainTime <= 0 {
		config.DrainTime = 30 * time.Second
	}
	hostname, err := naming.CanonicalizeHostname(config.Hostname)
	if err != nil {
		return err
	}
	automaticCertificates := config.ACMEProfile != ""
	if automaticCertificates {
		if config.State == nil {
			return errors.New("agent: client state is required for automatic certificates")
		}
	} else if err := validateCertificate(config.Certificate, hostname, false); err != nil {
		return err
	}
	if err := localproxy.Preflight(ctx, config.Target); err != nil {
		return err
	}
	if config.State != nil {
		hostLock, err := clientstate.LockHostnameContext(ctx, config.State, hostname)
		if err != nil {
			return err
		}
		defer hostLock.Close()
	}
	routeToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		return err
	}
	setup, err := createOrRecover(ctx, config.Core, hostname, config.Target, routeToken)
	if err != nil {
		return err
	}
	routeID := setup.Route.Id
	var routeState *clientstate.Route
	if automaticCertificates {
		routeState, err = clientstate.LockContext(ctx, config.State, routeID)
		if err != nil {
			return err
		}
		defer routeState.Close()
	}
	var announced sync.Once
	for {
		if setup.Route.Id != routeID {
			return errors.New("agent: core changed route ID during lease acquisition")
		}
		err := runLease(ctx, config, setup, routeState, func() {
			announced.Do(func() {
				if config.OnReady != nil {
					config.OnReady("https://" + setup.Route.Hostname)
				}
			})
		})
		if ctx.Err() != nil {
			return nil
		}
		if !errors.Is(err, coreclient.ErrStateConflict) {
			return err
		}
		setup, err = config.Core.AcquireLease(ctx, routeID, routeToken)
		if err != nil {
			return err
		}
	}
}

func createOrRecover(
	ctx context.Context,
	core Core,
	hostname, target string,
	routeToken credentials.RouteToken,
) (corev1.LeaseSetup, error) {
	for {
		setup, err := core.CreateRoute(ctx, corev1.CreateRouteRequest{
			Hostname: hostname, DisplayTarget: target, RouteToken: routeToken.String(),
		})
		if err == nil {
			return setup, nil
		}
		if errors.Is(err, coreclient.ErrStateConflict) || errors.Is(err, coreclient.ErrUnavailable) {
			routes, listErr := core.ListRoutes(ctx)
			if listErr == nil {
				for _, route := range routes {
					if route.Hostname == hostname && route.DisplayTarget == target {
						setup, acquireErr := core.AcquireLease(ctx, route.Id, routeToken)
						if acquireErr == nil {
							return setup, nil
						}
						if !errors.Is(acquireErr, coreclient.ErrUnavailable) &&
							!errors.Is(acquireErr, coreclient.ErrUnauthenticated) {
							return corev1.LeaseSetup{}, acquireErr
						}
					}
				}
			}
			if !errors.Is(err, coreclient.ErrUnavailable) && listErr == nil {
				return corev1.LeaseSetup{}, err
			}
			if listErr != nil && !errors.Is(listErr, coreclient.ErrUnavailable) {
				return corev1.LeaseSetup{}, listErr
			}
			select {
			case <-ctx.Done():
				return corev1.LeaseSetup{}, ctx.Err()
			case <-time.After(activationRetry):
			}
			continue
		}
		return corev1.LeaseSetup{}, err
	}
}

func runLease(
	ctx context.Context,
	config PublicConfig,
	setup corev1.LeaseSetup,
	state *clientstate.Route,
	ready func(),
) error {
	if setup.Route.Id == "" || setup.Lease.Generation <= 0 || setup.LeaseToken == "" || setup.IngressPublicKey == "" {
		return errors.New("agent: core returned incomplete lease setup")
	}
	leaseToken := credentials.LeaseToken(setup.LeaseToken)
	if _, _, err := credentials.ParseLeaseToken(leaseToken); err != nil {
		return errors.New("agent: core returned invalid lease token")
	}
	var ingressKey key.NodePublic
	if err := ingressKey.UnmarshalText([]byte(setup.IngressPublicKey)); err != nil || ingressKey.IsZero() {
		return errors.New("agent: core returned invalid ingress key")
	}
	generation := uint64(setup.Lease.Generation)
	leaseCtx, cancelLease := context.WithCancel(ctx)
	defer cancelLease()
	heartbeatErrors := make(chan error, 1)
	go func() {
		if err := heartbeatLease(
			leaseCtx, config.Core, setup.Route.Id, generation, leaseToken, setup.Lease.ExpiresAt,
		); err != nil {
			heartbeatErrors <- err
		}
	}()
	certificate := config.Certificate
	var err error
	var material clientstate.Material
	var hasMaterial bool
	if state != nil {
		material, hasMaterial, err = state.Current(setup.Route.Hostname)
		if errors.Is(err, clientstate.ErrCertificateExpired) {
			hasMaterial = false
		} else if err != nil {
			return err
		}
		if hasMaterial {
			certificate = material.Certificate
		}
	}
	route, err := NewRoute(RouteConfig{
		Hostname: setup.Route.Hostname, Target: config.Target, Certificate: certificate,
		StrictCertificate: state != nil,
		AllowedClient:     ingressKey, RelayProfile: config.RelayProfile, Profiles: config.Profiles, Logf: config.Logf,
	})
	if err != nil {
		return err
	}
	defer route.Close()
	endpoint, err := route.Start(ctx)
	if err != nil {
		return err
	}

	for {
		err = config.Core.RegisterTransport(ctx, setup.Route.Id, generation, leaseToken, endpoint)
		if err == nil {
			break
		}
		if !errors.Is(err, coreclient.ErrUnavailable) {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(activationRetry):
		case err := <-heartbeatErrors:
			return err
		}
	}
	var nextRenewal time.Time
	if state != nil {
		if !hasMaterial {
			material, err = issueCertificate(
				ctx, config.Core, route, state, setup.Route.Id, generation, leaseToken,
				setup.Route.Hostname, config.ACMEProfile, heartbeatErrors,
			)
			if err != nil {
				return err
			}
			hasMaterial = true
		} else if !material.Installed || !material.RenewAt.After(time.Now()) {
			replacement, refreshErr := refreshCertificate(
				ctx, config.Core, route, state, setup.Route.Id, generation, leaseToken,
				setup.Route.Hostname, config.ACMEProfile, material, heartbeatErrors,
			)
			if !replacement.NotAfter.IsZero() {
				material = replacement
			}
			if refreshErr != nil {
				if errors.Is(refreshErr, coreclient.ErrStateConflict) {
					return refreshErr
				}
				if !material.NotAfter.After(time.Now()) {
					return fmt.Errorf("agent: renew expired certificate: %w", refreshErr)
				}
				logRenewalFailure(config.Logf, refreshErr)
				nextRenewal = time.Now().Add(min(renewalRetry, time.Until(material.NotAfter)))
			} else {
				material = replacement
			}
		}
		if nextRenewal.IsZero() {
			nextRenewal = material.RenewAt
		}
	}
	for {
		err = config.Core.Ready(ctx, setup.Route.Id, generation, leaseToken)
		if err == nil {
			break
		}
		if !errors.Is(err, coreclient.ErrUnavailable) {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(activationRetry):
		case err := <-heartbeatErrors:
			return err
		}
	}
	ready()
	var renewalTimer *time.Timer
	var renewal <-chan time.Time
	if state != nil {
		renewalTimer = time.NewTimer(max(time.Until(nextRenewal), 0))
		renewal = renewalTimer.C
		defer renewalTimer.Stop()
	}
	for {
		select {
		case <-ctx.Done():
			return drainRoute(route, config.DrainTime)
		case err := <-heartbeatErrors:
			return fmt.Errorf("agent: heartbeat: %w", err)
		case <-renewal:
			replacement, renewalErr := refreshCertificate(
				ctx, config.Core, route, state, setup.Route.Id, generation, leaseToken,
				setup.Route.Hostname, config.ACMEProfile, material, heartbeatErrors,
			)
			if renewalErr != nil {
				if errors.Is(renewalErr, coreclient.ErrStateConflict) {
					return renewalErr
				}
				if !replacement.NotAfter.IsZero() {
					material = replacement
				}
				if ctx.Err() != nil {
					return drainRoute(route, config.DrainTime)
				}
				if !material.NotAfter.After(time.Now()) {
					return fmt.Errorf("agent: renew expired certificate: %w", renewalErr)
				}
				logRenewalFailure(config.Logf, renewalErr)
				renewalTimer.Reset(min(renewalRetry, time.Until(material.NotAfter)))
				continue
			}
			material = replacement
			renewalTimer.Reset(max(time.Until(material.RenewAt), 0))
		}
	}
}

func refreshCertificate(
	ctx context.Context,
	core Core,
	route *Route,
	state *clientstate.Route,
	routeID string,
	generation uint64,
	leaseToken credentials.LeaseToken,
	hostname, profile string,
	material clientstate.Material,
	heartbeatErrors <-chan error,
) (clientstate.Material, error) {
	if !material.Installed && material.RenewAt.After(time.Now()) && material.NotAfter.After(time.Now().Add(24*time.Hour)) {
		reconciled, err := reconcileCertificateInstallation(
			ctx, core, route, state, routeID, generation, leaseToken, hostname, profile, material, heartbeatErrors,
		)
		var terminal *terminalCertificateOrderError
		if !errors.As(err, &terminal) {
			return reconciled, err
		}
	}
	return issueCertificate(
		ctx, core, route, state, routeID, generation, leaseToken, hostname, profile, heartbeatErrors,
	)
}

func logRenewalFailure(logf logger.Logf, err error) {
	if logf != nil {
		logf("certificate renewal failed; retrying while the current certificate remains valid: %v", err)
	}
}

func issueCertificate(
	ctx context.Context,
	core Core,
	route *Route,
	state *clientstate.Route,
	routeID string,
	generation uint64,
	leaseToken credentials.LeaseToken,
	hostname, profile string,
	heartbeatErrors <-chan error,
) (clientstate.Material, error) {
	pending, err := state.Pending(hostname)
	if err != nil {
		return clientstate.Material{}, err
	}
	rotatedTerminalOrder := false
	createAndRecord := func() (corev1.CertificateOrder, error) {
		for {
			order, createErr := createCertificateOrder(
				ctx, core, routeID, generation, leaseToken, hostname, profile, pending.CSRDER, heartbeatErrors,
			)
			var terminal *terminalCertificateOrderError
			if errors.As(createErr, &terminal) && !rotatedTerminalOrder {
				pending, createErr = state.NewPending(hostname)
				if createErr != nil {
					return corev1.CertificateOrder{}, createErr
				}
				rotatedTerminalOrder = true
				continue
			}
			if createErr != nil {
				return corev1.CertificateOrder{}, createErr
			}
			pending, createErr = state.RecordOrder(hostname, pending, order.Id, generation)
			return order, createErr
		}
	}
	order, err := createAndRecord()
	if err != nil {
		return clientstate.Material{}, err
	}
orderLoop:
	for {
		if order.CertificatePem != nil {
			if order.Challenge != nil {
				route.RemoveChallenge(order.Challenge.Id)
				if err := acknowledgeChallengeRemoval(ctx, core, order.Id, leaseToken, heartbeatErrors); err != nil {
					return clientstate.Material{}, err
				}
			}
			break
		}
		if order.Challenge == nil {
			if err := waitCertificateRetry(ctx, heartbeatErrors, certificateOrderRetry(order)); err != nil {
				return clientstate.Material{}, err
			}
			order, err = createAndRecord()
			if err != nil {
				return clientstate.Material{}, err
			}
			continue
		}
		digest, err := base64.RawURLEncoding.DecodeString(order.Challenge.Digest)
		if err != nil || len(digest) != 32 || base64.RawURLEncoding.EncodeToString(digest) != order.Challenge.Digest ||
			order.Challenge.Id == "" || order.Challenge.Hostname != hostname || !order.Challenge.ExpiresAt.After(time.Now()) {
			return clientstate.Material{}, errors.New("agent: core returned an invalid TLS-ALPN challenge digest")
		}
		challenge := agent.TLSALPNChallenge{
			ID: order.Challenge.Id, Hostname: order.Challenge.Hostname, ExpiresAt: order.Challenge.ExpiresAt,
		}
		copy(challenge.Digest[:], digest)
		if err := route.InstallChallenge(challenge); err != nil {
			return clientstate.Material{}, err
		}
		defer route.RemoveChallenge(challenge.ID)
		for {
			expectedOrderID := order.Id
			advanced, readyErr := core.CertificateChallengeReady(ctx, expectedOrderID, leaseToken)
			err = readyErr
			if err == nil {
				if err := validateCertificateOrder(advanced, routeID, generation, hostname, profile, expectedOrderID); err != nil {
					var terminal *terminalCertificateOrderError
					if errors.As(err, &terminal) && !rotatedTerminalOrder {
						route.RemoveChallenge(challenge.ID)
						pending, err = state.NewPending(hostname)
						if err != nil {
							return clientstate.Material{}, err
						}
						rotatedTerminalOrder = true
						order, err = createAndRecord()
						if err != nil {
							return clientstate.Material{}, err
						}
						continue orderLoop
					}
					return clientstate.Material{}, err
				}
				order = advanced
				if order.CertificatePem != nil {
					break
				}
				if err := waitCertificateRetry(ctx, heartbeatErrors, certificateOrderRetry(order)); err != nil {
					return clientstate.Material{}, err
				}
				continue
			}
			if !errors.Is(err, coreclient.ErrUnavailable) {
				return clientstate.Material{}, err
			}
			if err := waitCertificateRetry(ctx, heartbeatErrors, activationRetry); err != nil {
				return clientstate.Material{}, err
			}
		}
		route.RemoveChallenge(challenge.ID)
		if err := acknowledgeChallengeRemoval(ctx, core, order.Id, leaseToken, heartbeatErrors); err != nil {
			return clientstate.Material{}, err
		}
	}
	if order.CertificatePem == nil || order.RenewAt == nil || order.Id == "" {
		return clientstate.Material{}, errors.New("agent: core returned incomplete certificate material")
	}
	return installCertificateOrder(
		ctx, core, route, state, routeID, generation, leaseToken, hostname, pending, order, heartbeatErrors,
	)
}

func installCertificateOrder(
	ctx context.Context,
	core Core,
	route *Route,
	state *clientstate.Route,
	routeID string,
	generation uint64,
	leaseToken credentials.LeaseToken,
	hostname string,
	pending clientstate.Pending,
	order corev1.CertificateOrder,
	heartbeatErrors <-chan error,
) (clientstate.Material, error) {
	material, err := state.Commit(
		hostname, pending, []byte(*order.CertificatePem), *order.RenewAt, order.Id, generation,
	)
	if err != nil {
		return material, err
	}
	if err := route.InstallCertificate(material.Certificate); err != nil {
		return material, err
	}
	if err := route.VerifyCertificate(material.Certificate); err != nil {
		return material, err
	}
	if err := acknowledgeCertificate(
		ctx, core, routeID, generation, order.Id, leaseToken, heartbeatErrors,
	); err != nil {
		return material, err
	}
	installed, err := state.MarkInstalled(hostname, order.Id, generation)
	if err != nil {
		return material, err
	}
	return installed, nil
}

func createCertificateOrder(
	ctx context.Context,
	core Core,
	routeID string,
	generation uint64,
	leaseToken credentials.LeaseToken,
	hostname, profile string,
	csrDER []byte,
	heartbeatErrors <-chan error,
) (corev1.CertificateOrder, error) {
	for {
		order, err := core.CreateCertificateOrder(ctx, routeID, generation, leaseToken, profile, csrDER)
		if err == nil {
			if err := validateCertificateOrder(order, routeID, generation, hostname, profile, ""); err != nil {
				return corev1.CertificateOrder{}, err
			}
			return order, nil
		}
		if !errors.Is(err, coreclient.ErrUnavailable) && !errors.Is(err, coreclient.ErrRateLimited) {
			return corev1.CertificateOrder{}, err
		}
		if err := waitCertificateRetry(ctx, heartbeatErrors, certificateRetryDelay(err)); err != nil {
			return corev1.CertificateOrder{}, err
		}
	}
}

func reconcileCertificateInstallation(
	ctx context.Context,
	core Core,
	route *Route,
	state *clientstate.Route,
	routeID string,
	generation uint64,
	leaseToken credentials.LeaseToken,
	hostname, profile string,
	material clientstate.Material,
	heartbeatErrors <-chan error,
) (clientstate.Material, error) {
	order, err := createCertificateOrder(
		ctx, core, routeID, generation, leaseToken, hostname, profile, material.CSRDER, heartbeatErrors,
	)
	if err != nil {
		return material, err
	}
	for order.CertificatePem == nil && order.Challenge == nil {
		if err := waitCertificateRetry(ctx, heartbeatErrors, certificateOrderRetry(order)); err != nil {
			return material, err
		}
		order, err = createCertificateOrder(
			ctx, core, routeID, generation, leaseToken, hostname, profile, material.CSRDER, heartbeatErrors,
		)
		if err != nil {
			return material, err
		}
	}
	if order.CertificatePem == nil {
		return completeReboundCertificateOrder(
			ctx, core, route, state, routeID, generation, leaseToken, hostname, profile, material, order, heartbeatErrors,
		)
	}
	chain, err := decodeCertificateChain([]byte(*order.CertificatePem))
	if err != nil || !equalCertificateChain(chain, material.Certificate.Certificate) || !order.RenewAt.Equal(material.RenewAt) {
		return material, errors.New("agent: reused certificate does not match persisted material")
	}
	updated, err := state.RecordCurrentOrder(hostname, order.Id, generation)
	if err != nil {
		return material, err
	}
	material = updated
	if err := route.VerifyCertificate(material.Certificate); err != nil {
		return material, err
	}
	if err := acknowledgeCertificate(
		ctx, core, routeID, generation, order.Id, leaseToken, heartbeatErrors,
	); err != nil {
		return material, err
	}
	installed, err := state.MarkInstalled(hostname, order.Id, generation)
	if err != nil {
		return material, err
	}
	return installed, nil
}

func completeReboundCertificateOrder(
	ctx context.Context,
	core Core,
	route *Route,
	state *clientstate.Route,
	routeID string,
	generation uint64,
	leaseToken credentials.LeaseToken,
	hostname, profile string,
	current clientstate.Material,
	order corev1.CertificateOrder,
	heartbeatErrors <-chan error,
) (clientstate.Material, error) {
	pending, err := state.CurrentKey(hostname)
	if err != nil {
		return current, err
	}
	digest, err := base64.RawURLEncoding.DecodeString(order.Challenge.Digest)
	if err != nil || len(digest) != 32 || base64.RawURLEncoding.EncodeToString(digest) != order.Challenge.Digest ||
		order.Challenge.Id == "" || order.Challenge.Hostname != hostname || !order.Challenge.ExpiresAt.After(time.Now()) {
		return current, errors.New("agent: core returned an invalid TLS-ALPN challenge digest")
	}
	challenge := agent.TLSALPNChallenge{
		ID: order.Challenge.Id, Hostname: order.Challenge.Hostname, ExpiresAt: order.Challenge.ExpiresAt,
	}
	copy(challenge.Digest[:], digest)
	if err := route.InstallChallenge(challenge); err != nil {
		return current, err
	}
	defer route.RemoveChallenge(challenge.ID)
	for order.CertificatePem == nil {
		expectedOrderID := order.Id
		advanced, readyErr := core.CertificateChallengeReady(ctx, expectedOrderID, leaseToken)
		if readyErr != nil {
			if !errors.Is(readyErr, coreclient.ErrUnavailable) {
				return current, readyErr
			}
			if err := waitCertificateRetry(ctx, heartbeatErrors, activationRetry); err != nil {
				return current, err
			}
			continue
		}
		if err := validateCertificateOrder(advanced, routeID, generation, hostname, profile, expectedOrderID); err != nil {
			return current, err
		}
		order = advanced
		if order.CertificatePem == nil {
			if err := waitCertificateRetry(ctx, heartbeatErrors, certificateOrderRetry(order)); err != nil {
				return current, err
			}
		}
	}
	route.RemoveChallenge(challenge.ID)
	if err := acknowledgeChallengeRemoval(ctx, core, order.Id, leaseToken, heartbeatErrors); err != nil {
		return current, err
	}
	replacement, err := installCertificateOrder(
		ctx, core, route, state, routeID, generation, leaseToken, hostname, pending, order, heartbeatErrors,
	)
	if replacement.NotAfter.IsZero() {
		return current, err
	}
	return replacement, err
}

func acknowledgeCertificate(
	ctx context.Context,
	core Core,
	routeID string,
	generation uint64,
	orderID string,
	leaseToken credentials.LeaseToken,
	heartbeatErrors <-chan error,
) error {
	for {
		err := core.CertificateInstalled(ctx, routeID, generation, orderID, leaseToken)
		if err == nil {
			return nil
		}
		if !errors.Is(err, coreclient.ErrUnavailable) {
			return err
		}
		if err := waitCertificateRetry(ctx, heartbeatErrors, activationRetry); err != nil {
			return err
		}
	}
}

func acknowledgeChallengeRemoval(
	ctx context.Context,
	core Core,
	orderID string,
	leaseToken credentials.LeaseToken,
	heartbeatErrors <-chan error,
) error {
	for {
		err := core.CertificateChallengeRemoved(ctx, orderID, leaseToken)
		if err == nil {
			return nil
		}
		if !errors.Is(err, coreclient.ErrUnavailable) {
			return err
		}
		if err := waitCertificateRetry(ctx, heartbeatErrors, activationRetry); err != nil {
			return err
		}
	}
}

func validateCertificateOrder(
	order corev1.CertificateOrder,
	routeID string,
	generation uint64,
	hostname, profile string,
	expectedID string,
) error {
	if order.Id == "" || order.RouteId != routeID || order.Generation != int(generation) ||
		order.Hostname != hostname || order.Profile != profile || expectedID != "" && order.Id != expectedID {
		return errors.New("agent: core returned a certificate order for a different route lease")
	}
	if !order.State.Valid() {
		return errors.New("agent: core returned an unknown certificate order state")
	}
	switch order.State {
	case corev1.Invalid, corev1.Blocked, corev1.Canceled:
		return &terminalCertificateOrderError{state: order.State}
	}
	if order.CertificatePem != nil {
		if order.State != corev1.WaitingForInstall && order.State != corev1.Succeeded ||
			order.NotBefore == nil || order.NotAfter == nil || order.RenewAt == nil {
			return errors.New("agent: core returned certificate material in an inconsistent order state")
		}
	} else if order.State == corev1.WaitingForInstall || order.State == corev1.Succeeded {
		return errors.New("agent: core returned an installed order without certificate material")
	}
	if order.Challenge != nil && order.CertificatePem == nil {
		switch order.State {
		case corev1.WaitingForChallenge, corev1.Validating, corev1.ReadyToFinalize, corev1.Finalizing, corev1.Downloading:
		default:
			return errors.New("agent: core returned a challenge in an inconsistent order state")
		}
	}
	if order.Challenge == nil && order.State == corev1.WaitingForChallenge {
		return errors.New("agent: core returned a challenge order without challenge material")
	}
	if order.Challenge != nil {
		digest, err := base64.RawURLEncoding.DecodeString(order.Challenge.Digest)
		if err != nil || len(digest) != 32 || base64.RawURLEncoding.EncodeToString(digest) != order.Challenge.Digest ||
			order.Challenge.Id == "" || order.Challenge.Hostname != hostname || order.Challenge.ExpiresAt.IsZero() {
			return errors.New("agent: core returned invalid TLS-ALPN challenge material")
		}
	}
	return nil
}

type terminalCertificateOrderError struct{ state corev1.CertificateOrderState }

func (e *terminalCertificateOrderError) Error() string {
	return fmt.Sprintf("agent: certificate order became %s", e.state)
}

func decodeCertificateChain(certificatePEM []byte) ([][]byte, error) {
	var chain [][]byte
	remaining := bytes.TrimSpace(certificatePEM)
	for len(remaining) != 0 {
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Bytes) == 0 {
			return nil, errors.New("agent: invalid certificate chain")
		}
		chain = append(chain, block.Bytes)
		remaining = bytes.TrimSpace(rest)
	}
	if len(chain) == 0 {
		return nil, errors.New("agent: empty certificate chain")
	}
	return chain, nil
}

func equalCertificateChain(left, right [][]byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !bytes.Equal(left[index], right[index]) {
			return false
		}
	}
	return true
}

func certificateOrderRetry(order corev1.CertificateOrder) time.Duration {
	if order.RetryAt != nil && order.RetryAt.After(time.Now()) {
		return min(time.Until(*order.RetryAt), time.Minute)
	}
	return activationRetry
}

func drainRoute(route *Route, timeout time.Duration) error {
	drainCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return route.Drain(drainCtx)
}

func waitCertificateRetry(ctx context.Context, heartbeatErrors <-chan error, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-heartbeatErrors:
		return fmt.Errorf("agent: heartbeat: %w", err)
	case <-timer.C:
		return nil
	}
}

func certificateRetryDelay(err error) time.Duration {
	var limited *coreclient.RateLimitError
	if errors.As(err, &limited) && limited.RetryAfter > 0 {
		return min(limited.RetryAfter, 24*time.Hour)
	}
	return activationRetry
}

func heartbeatLease(
	ctx context.Context,
	core Core,
	routeID string,
	generation uint64,
	leaseToken credentials.LeaseToken,
	expiresAt time.Time,
) error {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
		callCtx, cancel := context.WithTimeout(ctx, heartbeatCallTimeout)
		response, err := core.Heartbeat(callCtx, routeID, generation, leaseToken)
		cancel()
		if err == nil {
			expiresAt = response.ExpiresAt
			continue
		}
		if ctx.Err() != nil {
			return nil
		}
		if errors.Is(err, coreclient.ErrUnavailable) {
			if time.Now().Before(expiresAt) {
				continue
			}
			return coreclient.ErrStateConflict
		}
		return err
	}
}
