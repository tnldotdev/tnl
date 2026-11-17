package installed

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// this boundary retains a committed preparation until the exact run is closed.
// it models the same-publisher exclusion in control's PrepareServiceRun without
// waiting for its two-minute preparation deadline.
type restartPreparationControl struct {
	*jobControl
	mu          sync.Mutex
	preparation controlv1.ServiceRunPreparation
	keys        []string
	open        bool
	starts      int
	closes      int
	pending     bool
	access      chan struct{}
}

func (c *restartPreparationControl) PrepareServiceRun(_ context.Context, service, key, access string, declaration controlv1.ServiceRunDeclaration) (controlv1.ServiceRunPreparation, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if service != c.preparation.ServiceId || access != "test-access-never-log" || declaration.Protocol != c.service.Protocol || declaration.TrustRevision != c.service.TrustRevision {
		return controlv1.ServiceRunPreparation{}, publisheridentity.ErrScope
	}
	c.keys = append(c.keys, key)
	if c.open && key != c.preparation.IdempotencyKey {
		return controlv1.ServiceRunPreparation{}, clientcontrol.ErrStatusConflict
	}
	if c.preparation.IdempotencyKey != "" && key != c.preparation.IdempotencyKey {
		id, err := opaqueid.New(opaqueid.ServiceRunPrefix)
		if err != nil {
			return controlv1.ServiceRunPreparation{}, err
		}
		token, _, err := credentials.NewServiceRunToken()
		if err != nil {
			return controlv1.ServiceRunPreparation{}, err
		}
		c.preparation.ServiceRunId, c.preparation.RunToken = id, token.String()
		c.preparation.RunNumber++
	}
	c.open = true
	c.preparation.IdempotencyKey = key
	c.pending = true
	return c.preparation, nil
}

func (c *restartPreparationControl) StartServiceRun(context.Context, string, string, string, int64) (controlv1.ServiceRunSetup, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.starts++
	return controlv1.ServiceRunSetup{}, errors.New("replacement passed the preparation exclusion")
}

func (c *restartPreparationControl) CloseServiceRun(_ context.Context, service, run string, token credentials.ServiceRunToken) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if service != c.preparation.ServiceId || run != c.preparation.ServiceRunId || token.String() != c.preparation.RunToken {
		return publisheridentity.ErrScope
	}
	c.closes++
	c.open = false
	return nil
}

type restartPreparationAuthority struct {
	*jobAuthority
	control *restartPreparationControl
}

func (a *restartPreparationAuthority) ExchangePublisherAssertion(ctx context.Context, client, grant, key string, private ed25519.PrivateKey) (string, error) {
	a.control.mu.Lock()
	pending := a.control.pending
	a.control.pending = false
	a.control.mu.Unlock()
	if pending {
		// preparation has already returned. cancellation now must not abandon
		// its reservation just because acquiring start authority did not finish.
		select {
		case a.control.access <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return "", context.Cause(ctx)
	}
	return a.jobAuthority.ExchangePublisherAssertion(ctx, client, grant, key, private)
}

func TestInstalledReinstallReleasesPreparedRunBeforeReplacement(t *testing.T) {
	registry := testRegistry(t)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	job, identity, private := fixture(t, "web")
	job.Target = target.URL
	base, authority := jobBoundary(job, identity, private)
	newID := func(prefix string) string {
		t.Helper()
		id, err := opaqueid.New(prefix)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	hostname := base.service.Endpoint.Hostname
	control := &restartPreparationControl{
		jobControl: base,
		access:     make(chan struct{}, 1),
		preparation: controlv1.ServiceRunPreparation{
			ServiceId: job.ServiceID, ServiceRunId: newID(opaqueid.ServiceRunPrefix), RunNumber: 1,
			RunToken:            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			PublisherIdentityId: identity.ClientId, PublisherGrantId: identity.GrantId, PublisherKeyId: identity.KeyId,
			TeamId: identity.TeamId, DomainId: newID(opaqueid.DomainPrefix), Hostname: hostname,
			ExpiresAt: time.Now().Add(2 * time.Minute),
			CertificatePlan: &controlv1.CertificatePlan{
				CacheKey: "restart-preparation", Scope: hostname, Identifiers: []string{hostname}, ChallengeMethod: controlv1.Dns01,
			},
			Traffic: controlv1.TrafficLimits{
				Connections: 64, Rate: 64, RatePerNs: int64(time.Second), Burst: 64,
				UploadBytes: 1 << 20, DownloadBytes: 1 << 20,
			},
		},
	}
	access := &restartPreparationAuthority{jobAuthority: authority, control: control}
	if err := registry.Install(t.Context(), job, identity, private); err != nil {
		t.Fatal(err)
	}
	retrying := make(chan struct{}, 1)
	releaseRetry := make(chan struct{})
	release := sync.OnceFunc(func() { close(releaseRetry) })
	engine := Engine{
		Registry: registry, PollInterval: time.Millisecond, RetryMin: time.Millisecond, RetryMax: 2 * time.Millisecond,
		Clients: func(Job) (PublisherClients, publisheridentity.EnrollmentAuthority, error) {
			return PublisherClients{NativeControl: publisheridentity.NativeControl{Services: control, Runtime: base}}, access, nil
		},
		Observe: func(_ Job, status Status) error {
			if status.State == JobRetrying {
				select {
				case retrying <- struct{}{}:
				default:
				}
				<-releaseRetry
			}
			return nil
		},
	}
	cancel, done := startEngine(t, engine)
	joined := false
	defer func() {
		if !joined {
			cancel()
			release()
			joinEngine(t, cancel, done)
		}
	}()
	select {
	case <-control.access:
	case err := <-done:
		joined = true
		t.Fatal("supervisor stopped before the post-preparation boundary", err)
	case <-time.After(3 * time.Second):
		t.Fatal("publisher did not acquire start authority after preparing the run")
	}
	// this is the desired-state write performed by a retried installation.
	// the supervisor must join that revision before starting its replacement.
	if err := registry.Install(t.Context(), job, identity, private); err != nil {
		t.Fatal(err)
	}
	conflict := false
	select {
	case <-control.access:
	case <-retrying:
		conflict = true
	case err := <-done:
		joined = true
		t.Fatal("supervisor stopped during job replacement", err)
	case <-time.After(3 * time.Second):
		t.Fatal("replacement did not reach service preparation")
	}
	cancel()
	release()
	joined = true
	joinEngine(t, cancel, done)
	control.mu.Lock()
	defer control.mu.Unlock()
	if len(control.keys) < 2 || control.keys[0] == control.keys[1] {
		t.Fatal("replacement did not generate its own preparation key")
	}
	if conflict || control.open || control.starts != 0 || control.closes != 2 {
		t.Fatalf("replacement did not settle both exact preparations: starts=%d closes=%d remaining=%s",
			control.starts, control.closes, time.Until(control.preparation.ExpiresAt).Round(time.Second))
	}
}
