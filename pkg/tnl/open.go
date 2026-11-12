// package tnl publishes an application-owned HTTP handler through the native tnl
// publication owner, using an explicit identity source and resource selection.
package tnl

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisher"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type RateLimit struct {
	Requests int
	Per      time.Duration
}

type Limits struct {
	Requests    int
	Rate        RateLimit
	Concurrency int
}

type Options struct {
	ServerURL           string
	OIDCSource          *OIDCSource
	RegisteredKeySource *RegisteredKeySource
	PublisherIdentity   *PublisherIdentity
	ResourceID          string
	Namespace           string
	Directory           string
	StateDir            string
	Binary              string
	RequirePostQuantum  bool
	AccessMode          controlv1.VisitorAccessMode
	IP                  []string
	Limits              Limits
}

// Tunnel owns its HTTP listener and native registration. the native process owns
// the durable publication and original-key cleanup, including failed close.
type Tunnel struct {
	cancel     context.CancelCauseFunc
	done       chan struct{}
	mu         sync.Mutex
	url        string
	err        error
	cleanupErr error
	cleanupMu  sync.Mutex
	cleanup    func() error
}

// Open binds handler and returns after its exact native registration is routable.
// ResourceID selects a saved app URL; Namespace requests a temporary URL.
func Open(ctx context.Context, handler http.Handler, options Options) (*Tunnel, error) {
	return openApplication(ctx, handler, options, startApplicationRuntime)
}

type applicationRuntime func(context.Context, Options, string) (publisherprotocol.Endpoint, error)

func openApplication(ctx context.Context, handler http.Handler, options Options, runtime applicationRuntime) (*Tunnel, error) {
	if handler == nil {
		return nil, errors.New("an HTTP handler is required")
	}
	identity, err := applicationIdentity(ctx, options)
	if err != nil {
		return nil, err
	}
	if (options.ResourceID == "") == (options.Namespace == "") {
		return nil, ErrPublisherSelection
	}
	if options.ResourceID != "" && (!opaqueid.Valid(options.ResourceID, opaqueid.PublicURLPrefix) || options.AccessMode != "" || len(options.IP) != 0 || options.Limits != (Limits{})) {
		return nil, ErrPublisherScope
	}
	if options.Namespace != "" {
		namespace, err := naming.CanonicalizeHostname(options.Namespace)
		if err != nil || namespace != options.Namespace {
			return nil, ErrPublisherScope
		}
	}
	if options.AccessMode != "" && options.AccessMode != controlv1.Anonymous && options.AccessMode != controlv1.Restricted || len(options.IP) > 32 {
		return nil, ErrPublisherScope
	}
	limits := publisher.ApplicationLimits{Requests: options.Limits.Requests, RateRequests: options.Limits.Rate.Requests, RatePer: options.Limits.Rate.Per, Concurrency: options.Limits.Concurrency}
	if err := limits.Validate(); err != nil {
		return nil, err
	}
	invocation, err := opaqueid.New(opaqueid.InvocationPrefix)
	if err != nil {
		return nil, err
	}
	owner, err := publisherprotocol.Random(16)
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	runCtx, cancel := context.WithCancelCause(ctx)
	t := &Tunnel{cancel: cancel, done: make(chan struct{})}
	local := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
	served := make(chan error, 1)
	go func() {
		err := local.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		served <- err
		if err != nil {
			cancel(err)
		}
	}()
	ready := make(chan struct{}, 1)
	go func() {
		result := t.runApplication(runCtx, options, identity, invocation, owner, "http://"+listener.Addr().String(), runtime, ready)
		cancel(nil)
		shutdown, stop := context.WithTimeout(context.Background(), 10*time.Second)
		result = errors.Join(result, shutdownHTTP(shutdown, local, served))
		stop()
		if failure.Only(result, context.Canceled) {
			result = nil
		}
		t.mu.Lock()
		t.err = result
		t.mu.Unlock()
		close(t.done)
	}()
	select {
	case <-ready:
		if context.Cause(ctx) != nil {
			return nil, errors.Join(context.Cause(ctx), t.Close())
		}
		return t, nil
	case <-t.done:
		if err := t.Wait(); err != nil {
			return nil, err
		}
		return nil, errors.Join(context.Cause(ctx), errApplicationStoppedBeforeReady)
	case <-ctx.Done():
		return nil, errors.Join(context.Cause(ctx), t.Close())
	}
}

func (t *Tunnel) runApplication(ctx context.Context, options Options, identity *PublisherIdentity, invocation, owner, target string, runtime applicationRuntime, ready chan<- struct{}) error {
	endpoint, err := runtime(ctx, options, invocation)
	if err != nil {
		return errors.Join(context.Cause(ctx), err)
	}
	request := publisherprotocol.ApplicationPublication{Version: 1, InvocationId: invocation, Owner: owner, Pid: os.Getpid(), Target: target, ServerUrl: identity.server, RequirePostQuantum: new(options.RequirePostQuantum)}
	if options.ResourceID != "" {
		request.ResourceId = new(options.ResourceID)
	} else {
		request.Allocate = &struct {
			Namespace string `json:"namespace"`
		}{Namespace: options.Namespace}
		if options.AccessMode != "" {
			request.AccessMode = new(publisherprotocol.ApplicationPublicationAccessMode(options.AccessMode))
		}
		if len(options.IP) != 0 {
			request.Ip = new(slices.Clone(options.IP))
		}
		if options.Limits != (Limits{}) {
			request.Limits = applicationLimits(options.Limits)
		}
	}
	// install cleanup before requesting source proof or making an uncertain native
	// request. the stable owner/target can abort an intent without a registration ID.
	var accepted publisherprotocol.AcceptedPublication
	requested := false
	t.cleanup = func() error {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		registration := publisherprotocol.Registration{Version: 1, RegistrationID: accepted.Registration.RegistrationID, Owner: owner, Target: target}
		if requested {
			if err := publisherprotocol.Call(cleanup, endpoint, "POST", "/v1/unregister", registration, nil); err != nil {
				return err
			}
		}
		return publisherprotocol.Call(cleanup, endpoint, "DELETE", "/v1/capability", nil, nil)
	}
	defer t.retryCleanup()
	cursor, err := applicationCursor(ctx, endpoint)
	if err != nil {
		return err
	}
	tuple := &applicationNativeTuple{}
	publish := func(ctx context.Context, proof applicationProof) (publisherprotocol.AcceptedPublication, applicationProof, error) {
		response, err := deliverApplicationProof(ctx, endpoint, request, proof)
		if err == nil || !retryApplicationReply(ctx, err) {
			return response, proof, err
		}
		// reacquire only the original invocation capability. native must recover
		// its original key/nonce and accepted descriptor, not select new authority.
		recovered, recoveryErr := runtime(ctx, options, invocation)
		if recoveryErr != nil {
			return publisherprotocol.AcceptedPublication{}, proof, errors.Join(err, recoveryErr)
		}
		endpoint = recovered
		fresh, sourceErr := acquireApplicationSource(ctx, endpoint, request, identity, proof.expiresAt, tuple)
		if sourceErr != nil {
			return publisherprotocol.AcceptedPublication{}, proof, errors.Join(err, sourceErr)
		}
		response, retryErr := deliverApplicationProof(ctx, endpoint, request, fresh)
		return response, fresh, retryErr
	}
	if identity.registered != nil {
		requested = true
	}
	proof, err := acquireApplicationSource(ctx, endpoint, request, identity, time.Time{}, tuple)
	if err != nil {
		return err
	}
	requested = true
	accepted, proof, err = publish(ctx, proof)
	if err != nil {
		return errors.Join(context.Cause(ctx), err)
	}
	if !validAcceptedApplication(accepted, request) {
		return errors.New("native publication returned inconsistent registration facts")
	}
	t.mu.Lock()
	t.url = accepted.PublicUrl
	t.mu.Unlock()
	owned, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	results := make(chan error, 2)
	go func() { results <- observeApplication(owned, endpoint, accepted, invocation, cursor, ready) }()
	go func() {
		for {
			delay := time.Until(proof.expiresAt.Add(-5 * time.Second))
			if delay < 0 {
				delay = 0
			}
			timer := time.NewTimer(delay)
			select {
			case <-owned.Done():
				timer.Stop()
				results <- context.Cause(owned)
				return
			case <-timer.C:
			}
			fresh, err := acquireApplicationSource(owned, endpoint, request, identity, proof.expiresAt, tuple)
			if err != nil {
				results <- err
				return
			}
			updated, next, err := publish(owned, fresh)
			if err == nil && updated.AcceptedPublication != accepted.AcceptedPublication {
				err = errors.New("native refresh replaced accepted publication")
			}
			if err != nil {
				results <- errors.Join(context.Cause(owned), err)
				return
			}
			proof = next
		}
	}()
	first := <-results
	// cancel every sibling before joining either result. a canceled source may
	// return an independent acquisition failure; keep it alongside the cause.
	cancel(first)
	second := <-results
	return errors.Join(first, second, context.Cause(owned))
}

func acquireApplicationProof(ctx context.Context, source OIDCSource, fence time.Time) (OIDCAssertion, error) {
	if err := context.Cause(ctx); err != nil {
		return OIDCAssertion{}, err
	}
	limit := time.Now().Add(30 * time.Second)
	if !fence.IsZero() && fence.Before(limit) {
		limit = fence
	}
	acquire, cancel := context.WithDeadline(ctx, limit)
	defer cancel()
	proof, err := source.Assertion(acquire)
	if err := errors.Join(context.Cause(acquire), err); err != nil {
		return OIDCAssertion{}, err
	}
	if !publisheridentity.ValidApplicationAssertion(proof.Token) || !proof.ExpiresAt.After(time.Now().Add(5*time.Second)) {
		return OIDCAssertion{}, errors.New("identity source returned invalid or expired OIDC proof")
	}
	return proof, nil
}

func retryApplicationReply(ctx context.Context, err error) bool {
	if context.Cause(ctx) != nil || errors.Is(err, publisherprotocol.ErrForbidden) {
		return false
	}
	var response *publisherprotocol.ResponseError
	if errors.As(err, &response) {
		return response.Code == "runtime.credential_unavailable" || response.Code == "runtime.identity_challenge_stale"
	}
	return true
}

func validAcceptedApplication(accepted publisherprotocol.AcceptedPublication, request publisherprotocol.ApplicationPublication) bool {
	registration := accepted.Registration
	hostname, err := naming.CanonicalizeHostname(accepted.Hostname)
	return err == nil && hostname == accepted.Hostname && accepted.PublicUrl == "https://"+hostname && opaqueid.Valid(accepted.PublicUrlId, opaqueid.PublicURLPrefix) && (request.ResourceId == nil || *request.ResourceId == accepted.PublicUrlId) && registration.Version == 1 && registration.RegistrationID != "" && registration.Owner == request.Owner && registration.Target == request.Target
}

func applicationLimits(limits Limits) *controlv1.PublisherApplicationLimits {
	out := &controlv1.PublisherApplicationLimits{}
	if limits.Requests != 0 {
		out.Requests = new(limits.Requests)
	}
	if limits.Concurrency != 0 {
		out.Concurrency = new(limits.Concurrency)
	}
	if limits.Rate.Requests != 0 {
		out.Rate = &struct {
			Per      string `json:"per"`
			Requests int    `json:"requests"`
		}{Per: limits.Rate.Per.String(), Requests: limits.Rate.Requests}
	}
	return out
}

// shutdownHTTP bounds graceful shutdown, closes remaining connections on timeout,
// and joins the serving loop before releasing the SDK-owned listener.
func shutdownHTTP(ctx context.Context, server *http.Server, served <-chan error) error {
	err := server.Shutdown(ctx)
	if err != nil {
		err = errors.Join(err, server.Close())
	}
	return errors.Join(err, <-served)
}

func (t *Tunnel) URL() string { t.mu.Lock(); defer t.mu.Unlock(); return t.url }

func (t *Tunnel) retryCleanup() {
	t.cleanupMu.Lock()
	defer t.cleanupMu.Unlock()
	if t.cleanup == nil {
		return
	}
	err := t.cleanup()
	t.mu.Lock()
	t.cleanupErr = err
	t.mu.Unlock()
	if err == nil {
		t.cleanup = nil
	}
}

// Close cancels and joins owned workers. if native cleanup failed, a later Close
// retries the same original obligation without reacquiring source proof.
func (t *Tunnel) Close() error {
	if t == nil {
		return nil
	}
	completed := false
	select {
	case <-t.done:
		completed = true
	default:
	}
	t.cancel(context.Canceled)
	<-t.done
	if completed {
		t.retryCleanup()
	}
	return t.Wait()
}

// Wait joins the native-registration observers and the SDK-owned HTTP listener.
func (t *Tunnel) Wait() error {
	if t == nil {
		return nil
	}
	<-t.done
	t.mu.Lock()
	defer t.mu.Unlock()
	return errors.Join(t.err, t.cleanupErr)
}
