package service

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type setupSourcePolicyControl struct {
	*lifecycleControl
	reads          atomic.Int32
	invalid        atomic.Bool
	invalidUntil   atomic.Int64
	refreshEntered chan<- struct{}
	refreshRelease <-chan struct{}
}

func (c *setupSourcePolicyControl) ReadPublisherVisitorPolicy(ctx context.Context, request controlv1.PublisherVisitorPolicyRequest, token string) (controlv1.VisitorPolicyUpdate, error) {
	c.reads.Add(1)
	update, err := c.lifecycleControl.ReadPublisherVisitorPolicy(ctx, request, token)
	if err != nil || request.AfterRevision == 0 {
		return update, err
	}
	if c.refreshEntered != nil {
		select {
		case c.refreshEntered <- struct{}{}:
		case <-ctx.Done():
			return controlv1.VisitorPolicyUpdate{}, context.Cause(ctx)
		}
	}
	if c.refreshRelease != nil {
		select {
		case <-c.refreshRelease:
		case <-ctx.Done():
			return controlv1.VisitorPolicyUpdate{}, context.Cause(ctx)
		}
	}
	if c.invalid.Load() {
		other := []byte(update.Policy.Resource.Id)
		if other[len(other)-1] == 'a' {
			other[len(other)-1] = 'b'
		} else {
			other[len(other)-1] = 'a'
		}
		update.Policy.Resource.Id = string(other)
		c.invalidUntil.Store(update.Policy.ValidUntil.UnixNano())
	}
	return update, nil
}

func setupSourceFixture(t *testing.T) (RunConfig, *lifecycleControl, *Prepared) {
	t.Helper()
	cfg, control := lifecycleFixture(t)
	approved, err := control.GetPublisherService(t.Context(), cfg.ServiceID, "")
	if err != nil {
		t.Fatal(err)
	}
	approved.Protocol, approved.Endpoint.Port, approved.Endpoint.Public = controlv1.ServiceProtocolHTTP, 443, true
	control.approved = &approved
	prepared, err := newManagedPrepared(control.prep, approved, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return cfg, control, prepared
}

func TestServiceSetupRejectsMissingShortAndZeroSourceKeysBeforeServing(t *testing.T) {
	for _, test := range []struct {
		name string
		key  []byte
	}{
		{"missing", nil},
		{"short", []byte{1}},
		{"zero", make([]byte, 32)},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg, base, prepared := setupSourceFixture(t)
			control := &setupSourcePolicyControl{lifecycleControl: base}
			var readiness atomic.Int32
			cfg.ReadinessProof = func(run httpaccess.ReadinessRun) *httpaccess.ReadinessProof {
				readiness.Add(1)
				proof, err := httpaccess.NewReadinessProof(run, "/health")
				if err != nil {
					t.Error(err)
				}
				return proof
			}
			setup := base.setup
			setup.VisitorSourceKey = test.key
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			maintain, closeRun, err := configureServiceRun(ctx, cfg, prepared, setup, control, cfg.State, nil)
			if closeRun != nil {
				defer func() {
					cancel()
					if err := closeRun(); err != nil {
						t.Error("join unexpected configured run", err)
					}
				}()
			}
			if !errors.Is(err, ErrPrivateStream) || maintain != nil || closeRun != nil {
				t.Fatal("invalid setup source key acquired a run owner", err)
			}
			if control.reads.Load() != 0 || readiness.Load() != 0 || prepared.policy != nil ||
				prepared.connectorHTTP != nil || prepared.httpProxy != nil || prepared.managedVisitor != nil ||
				prepared.certificateInstalled != nil {
				t.Fatal("invalid source key reached policy, target, or visitor setup", control.reads.Load(), readiness.Load())
			}
			if prepared.sourceKey != [32]byte{} {
				t.Fatal("invalid setup installed source authority")
			}
		})
	}
}

func TestServiceSetupSourceKeyIsCopiedAndImmutableAcrossPolicyRefresh(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg, base, prepared := setupSourceFixture(t)
		setup := base.setup
		var want [32]byte
		for i := range want {
			want[i] = byte(i + 1)
		}
		setup.VisitorSourceKey = append([]byte(nil), want[:]...)
		entered, release := make(chan struct{}, 1), make(chan struct{})
		startReads := make(chan struct{})
		releaseRefresh := sync.OnceFunc(func() { close(release) })
		beginReads := sync.OnceFunc(func() { close(startReads) })
		control := &setupSourcePolicyControl{
			lifecycleControl: base, refreshEntered: entered, refreshRelease: release,
		}
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		var workers sync.WaitGroup
		var closeRun func() error
		closeConfigured := sync.OnceFunc(func() {
			cancel()
			beginReads()
			releaseRefresh()
			workers.Wait()
			if closeRun != nil {
				if err := closeRun(); err != nil {
					t.Error("close configured source owner", err)
				}
			}
		})
		t.Cleanup(closeConfigured)
		_, closeRun, err := configureServiceRun(ctx, cfg, prepared, setup, control, cfg.State, nil)
		if err != nil {
			t.Fatal(err)
		}
		frontend, ok := prepared.connectorHTTP.(HTTP)
		if !ok || frontend.browser == nil || frontend.browser.Policy == nil ||
			prepared.policy != frontend.Policy || prepared.policy != frontend.browser.Policy.Lease() {
			t.Fatal("setup did not retain the actual HTTP policy owner")
		}
		owner := frontend.browser.Policy
		if control.reads.Load() != 1 || prepared.sourceKey != want {
			t.Fatal("setup did not install its actual source key and policy", control.reads.Load())
		}
		clear(setup.VisitorSourceKey)
		if prepared.sourceKey != want {
			t.Fatal("setup source key aliases its caller's slice")
		}

		refreshed := make(chan error, 1)
		workers.Add(1)
		go func() {
			defer workers.Done()
			refreshed <- owner.Refresh(ctx)
		}()
		select {
		case <-entered:
		case err := <-refreshed:
			t.Fatal("policy refresh stopped before the source-read barrier", err)
		case <-ctx.Done():
			t.Fatal("policy refresh did not enter the source-read barrier", context.Cause(ctx))
		}
		var readers sync.WaitGroup
		var mismatches atomic.Int32
		for range 32 {
			workers.Add(1)
			readers.Add(1)
			go func() {
				defer workers.Done()
				defer readers.Done()
				<-startReads
				for range 128 {
					if prepared.sourceKey != want {
						mismatches.Add(1)
					}
				}
			}()
		}
		workers.Add(1)
		readers.Add(1)
		go func() {
			defer workers.Done()
			defer readers.Done()
			<-startReads
			for round := range 64 {
				for i := range setup.VisitorSourceKey {
					setup.VisitorSourceKey[i] = byte(round)
				}
			}
		}()
		beginReads()
		readers.Wait()
		select {
		case err := <-refreshed:
			t.Fatal("policy refresh did not overlap source reads", err)
		default:
		}
		releaseRefresh()
		if err := <-refreshed; err != nil {
			t.Fatal(err)
		}
		if mismatches.Load() != 0 || prepared.sourceKey != want || control.reads.Load() != 2 {
			t.Fatal("caller mutation or concurrent refresh changed the run's source key", mismatches.Load(), control.reads.Load())
		}
		before, enabled, _ := prepared.policy.Current()
		if !enabled {
			t.Fatal("valid setup and refresh did not retain serving policy")
		}
		control.invalid.Store(true)
		time.Sleep(time.Second)
		if err := owner.Refresh(ctx); !errors.Is(err, visitorlease.ErrUpdate) {
			t.Fatal("foreign service policy did not retain its rejection classification", err)
		}
		after, enabled, _ := prepared.policy.Current()
		if control.invalidUntil.Load() <= before.ValidUntil.UnixNano() {
			t.Fatal("invalid refresh did not exercise a later proposed policy deadline")
		}
		if !enabled || after.Scope != before.Scope || after.VisitorPolicyRevision != before.VisitorPolicyRevision ||
			!after.ValidUntil.Equal(before.ValidUntil) || prepared.sourceKey != want {
			t.Fatal("invalid policy changed source authority or extended its original deadline")
		}
		closeConfigured()
		if _, enabled, _ := prepared.policy.Current(); enabled {
			t.Fatal("joined run cleanup retained serving policy")
		}
	})
}
