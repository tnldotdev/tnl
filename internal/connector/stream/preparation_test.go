package stream

import (
	"context"
	"crypto/tls"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/failure"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type selectionControl struct {
	Control
	calls   atomic.Int64
	resolve func(context.Context) (Run, error)
}

func (c *selectionControl) ResolveService(ctx context.Context, _ string) (Run, error) {
	c.calls.Add(1)
	return c.resolve(ctx)
}

func selectionFixture() (Config, Run) {
	endpoint := &controlv1.ServiceEndpoint{Hostname: "service.example.test", Port: 25443}
	configuration := Config{ServiceID: "svc_" + strings.Repeat("A", 22), Protocol: "tcp", TrustRevision: 1, Endpoint: endpoint,
		ServiceTLS: &tls.Config{MinVersion: tls.VersionTLS13, ServerName: endpoint.Hostname}}
	run := Run{ServiceID: configuration.ServiceID, ServiceRunID: "srun_" + strings.Repeat("B", 22), RunNumber: 1, ValidUntil: time.Now().Add(time.Minute), Protocol: "tcp", TrustRevision: 1, Endpoint: endpoint}
	run.Permission = fixtureVisitorPermission(run)
	return configuration, run
}

func fixtureVisitorPermission(run Run) controlv1.VisitorTokenResponse {
	return controlv1.VisitorTokenResponse{Resource: controlv1.VisitorResourceScope{Kind: "service", Id: run.ServiceID}, Hostname: run.Endpoint.Hostname, Port: run.Endpoint.Port,
		VisitorPolicyRevision: 1, VisitorToken: "prepared-visitor-permission", ExpiresAt: time.Now().Add(5 * time.Minute)}
}

func TestConnectorPreparationSocketReadsMakeNoControlCalls(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		config, run := selectionFixture()
		control := &selectionControl{resolve: func(context.Context) (Run, error) { return run, nil }}
		config.Control = control
		ctx, stop := context.WithCancelCause(t.Context())
		defer stop(nil)
		prepared, err := prepareSelection(ctx, config, stop)
		if err != nil {
			t.Fatal(err)
		}
		defer prepared.Close()
		for range 100 {
			current, err := prepared.current()
			if err != nil || current.ServiceRunID != run.ServiceRunID {
				t.Fatal("prepared socket lost its selected run", err)
			}
			current.Endpoint.Hostname = "changed.example.test"
		}
		current, err := prepared.current()
		if err != nil || current.Endpoint.Hostname != config.Endpoint.Hostname || control.calls.Load() != 1 {
			t.Fatal("socket reads contacted control or mutated prepared metadata", err)
		}
	})
}

func TestConnectorPreparationRetriesTransientStartupWithoutServingUnprepared(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		config, run := selectionFixture()
		var calls atomic.Int64
		control := &selectionControl{resolve: func(context.Context) (Run, error) {
			if controlCalls := calls.Add(1); controlCalls < 3 {
				return Run{}, clientcontrol.ErrUnavailable
			}
			return run, nil
		}}
		config.Control = control
		ctx, stop := context.WithCancelCause(t.Context())
		defer stop(nil)
		prepared, err := prepareSelection(ctx, config, stop)
		if err != nil {
			t.Fatal("transient control failures aborted startup", err)
		}
		defer prepared.Close()
		current, err := prepared.current()
		if err != nil || current.ServiceRunID != run.ServiceRunID || calls.Load() != 3 {
			t.Fatal("startup admitted no current selection or bypassed retry", err)
		}
	})
}

func TestConnectorPreparationOutageCannotExtendItsLastObservation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		config, run := selectionFixture()
		var unavailable atomic.Bool
		control := &selectionControl{resolve: func(context.Context) (Run, error) {
			if unavailable.Load() {
				return Run{}, clientcontrol.ErrUnavailable
			}
			return run, nil
		}}
		config.Control = control
		ctx, stop := context.WithCancelCause(t.Context())
		defer stop(nil)
		prepared, err := prepareSelection(ctx, config, stop)
		if err != nil {
			t.Fatal(err)
		}
		defer prepared.Close()
		time.Sleep(2*time.Second + time.Millisecond)
		synctest.Wait()
		unavailable.Store(true)
		time.Sleep(9 * time.Second)
		synctest.Wait()
		if _, err := prepared.current(); err != nil || ctx.Err() != nil {
			t.Fatal("outage discarded an unexpired prepared observation", err)
		}
		time.Sleep(time.Second)
		synctest.Wait()
		if !errors.Is(context.Cause(ctx), ErrServiceConnection) {
			t.Fatal("outage extended the last confirmed metadata deadline")
		}
		if _, err := prepared.current(); err == nil {
			t.Fatal("expired preparation admitted another socket")
		}
	})
}

func TestConnectorPreparationRejectsUnboundOrExpiredPermission(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*controlv1.VisitorTokenResponse)
	}{
		{"missing token", func(p *controlv1.VisitorTokenResponse) { p.VisitorToken = "" }},
		{"oversized token", func(p *controlv1.VisitorTokenResponse) { p.VisitorToken = strings.Repeat("x", 2049) }},
		{"wrong resource kind", func(p *controlv1.VisitorTokenResponse) { p.Resource.Kind = "public_url" }},
		{"wrong resource", func(p *controlv1.VisitorTokenResponse) { p.Resource.Id = "svc_" + strings.Repeat("C", 22) }},
		{"wrong hostname", func(p *controlv1.VisitorTokenResponse) { p.Hostname = "other.example.test" }},
		{"wrong port", func(p *controlv1.VisitorTokenResponse) { p.Port++ }},
		{"missing policy revision", func(p *controlv1.VisitorTokenResponse) { p.VisitorPolicyRevision = 0 }},
		{"expired", func(p *controlv1.VisitorTokenResponse) { p.ExpiresAt = time.Now() }},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				config, run := selectionFixture()
				test.change(&run.Permission)
				config.Control = &selectionControl{resolve: func(context.Context) (Run, error) { return run, nil }}
				ctx, stop := context.WithCancelCause(t.Context())
				defer stop(nil)
				prepared, err := prepareSelection(ctx, config, stop)
				if err == nil {
					prepared.Close()
					t.Fatal("invalid signed-permission response became prepared socket state")
				}
			})
		})
	}
}

func TestConnectorPreparationCannotOutliveItsToken(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		config, run := selectionFixture()
		run.Permission.ExpiresAt = time.Now().Add(5 * time.Second)
		config.Control = &selectionControl{resolve: func(context.Context) (Run, error) { return run, nil }}
		ctx, stop := context.WithCancelCause(t.Context())
		defer stop(nil)
		prepared, err := prepareSelection(ctx, config, stop)
		if err != nil {
			t.Fatal(err)
		}
		defer prepared.Close()
		time.Sleep(5 * time.Second)
		synctest.Wait()
		if _, err := prepared.current(); err == nil || !errors.Is(context.Cause(ctx), ErrServiceConnection) {
			t.Fatal("metadata refresh extended an expired visitor token")
		}
	})
}

func TestConnectorPreparationMalformedResultIsNotAnOutageFallback(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		config, run := selectionFixture()
		control := &selectionControl{}
		malformed := failure.Wrap("decode service preparation", failure.ServerResponseInvalid, context.DeadlineExceeded)
		control.resolve = func(context.Context) (Run, error) {
			if control.calls.Load() > 1 {
				return Run{}, malformed
			}
			return run, nil
		}
		config.Control = control
		ctx, stop := context.WithCancelCause(t.Context())
		defer stop(nil)
		prepared, err := prepareSelection(ctx, config, stop)
		if err != nil {
			t.Fatal(err)
		}
		defer prepared.Close()
		time.Sleep(2*time.Second + time.Millisecond)
		synctest.Wait()
		if !errors.Is(context.Cause(ctx), malformed) {
			t.Fatal("malformed metadata became an outage fallback")
		}
		if _, err := prepared.current(); err == nil {
			t.Fatal("terminal preparation failure retained its previous snapshot")
		}
	})
}

func TestConnectorPreparationCloseFencesLateResultsAndJoinsCleanup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		config, run := selectionFixture()
		started, cleanup, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
		control := &selectionControl{}
		control.resolve = func(ctx context.Context) (Run, error) {
			if control.calls.Load() == 1 {
				return run, nil
			}
			close(started)
			<-ctx.Done()
			close(cleanup)
			<-release
			return run, nil
		}
		config.Control = control
		ctx, stop := context.WithCancelCause(t.Context())
		defer stop(nil)
		prepared, err := prepareSelection(ctx, config, stop)
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(2*time.Second + time.Millisecond)
		<-started
		closed := make(chan struct{})
		go func() { prepared.Close(); close(closed) }()
		<-cleanup
		synctest.Wait()
		select {
		case <-closed:
			t.Fatal("preparation returned before joining control cleanup")
		default:
		}
		close(release)
		<-closed
		if _, err := prepared.current(); err == nil {
			t.Fatal("late result revived closed preparation")
		}
	})
}
