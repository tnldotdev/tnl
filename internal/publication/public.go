package publication

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"sync"
	"time"

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
)

type Core interface {
	CreateRoute(context.Context, corev1.CreateRouteRequest) (corev1.LeaseSetup, error)
	ListRoutes(context.Context) ([]corev1.Route, error)
	AcquireLease(context.Context, string, credentials.RouteToken) (corev1.LeaseSetup, error)
	RegisterTransport(context.Context, string, uint64, credentials.LeaseToken, transportv1.TailcatDescriptor) error
	Ready(context.Context, string, uint64, credentials.LeaseToken) error
	Heartbeat(context.Context, string, uint64, credentials.LeaseToken) (corev1.HeartbeatResponse, error)
}

type PublicConfig struct {
	Core         Core
	Hostname     string
	Target       string
	Certificate  tls.Certificate
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
	if err := validateCertificate(config.Certificate, hostname); err != nil {
		return err
	}
	if err := localproxy.Preflight(ctx, config.Target); err != nil {
		return err
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
	var announced sync.Once
	for {
		if setup.Route.Id != routeID {
			return errors.New("agent: core changed route ID during lease acquisition")
		}
		err := runLease(ctx, config, setup, func() {
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

func runLease(ctx context.Context, config PublicConfig, setup corev1.LeaseSetup, ready func()) error {
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
	route, err := NewRoute(RouteConfig{
		Hostname: setup.Route.Hostname, Target: config.Target, Certificate: config.Certificate,
		AllowedClient: ingressKey, RelayProfile: config.RelayProfile, Profiles: config.Profiles, Logf: config.Logf,
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
	for {
		select {
		case <-ctx.Done():
			drainCtx, cancel := context.WithTimeout(context.Background(), config.DrainTime)
			err := route.Drain(drainCtx)
			cancel()
			return err
		case err := <-heartbeatErrors:
			return fmt.Errorf("agent: heartbeat: %w", err)
		}
	}
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
