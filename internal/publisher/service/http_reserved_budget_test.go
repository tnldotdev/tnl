package service

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	"github.com/tnldotdev/tnl/internal/publisher/requestlimit"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type serviceHTTPPreparationControl struct {
	serviceHTTPControl
	work func(context.Context, string) error
}

func (c serviceHTTPPreparationControl) RedeemServiceShare(ctx context.Context, _, _ string, _ controlv1.RedeemServiceShareRequest, _ credentials.ServiceRunToken) (controlv1.ShareRedemption, error) {
	return controlv1.ShareRedemption{}, c.work(ctx, "share")
}

func (c serviceHTTPPreparationControl) CheckServiceBrowserSession(ctx context.Context, _, _ string, _ credentials.ServiceRunToken, _ controlv1.ServiceBrowserRequest) (controlv1.BrowserAccessResponse, error) {
	return controlv1.BrowserAccessResponse{}, c.work(ctx, "team")
}

func TestServiceHTTPPreparationHasOneRunWideBudgetAndJoinsCanceledWork(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		type call struct {
			ctx  context.Context
			kind string
			join chan struct{}
		}
		entered := make(chan call, 17)
		finish := make(chan struct{})
		var workers sync.WaitGroup
		defer func() { close(finish); workers.Wait() }()
		var calls, applications, admissions, connections atomic.Int32
		var applicationToken visitortoken.Token
		key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("p", 32)))
		control := serviceHTTPPreparationControl{work: func(ctx context.Context, kind string) error {
			calls.Add(1)
			current := call{ctx: ctx, kind: kind, join: make(chan struct{})}
			entered <- current
			select {
			case <-current.join:
			case <-finish:
			}
			return errors.New("preparation stopped")
		}}
		control.serviceHTTPControl.HTTPControl = serviceBrowserControl{origin: "https://control.example.test", policy: &visitorfixture.PolicyClient{Key: key},
			tokens: &visitorfixture.TokenClient{Issue: func(context.Context, controlv1.VisitorTokenRequest) (controlv1.VisitorTokenResponse, error) {
				t.Error("ordinary request or blocked preparation requested a visitor permission")
				return controlv1.VisitorTokenResponse{}, errors.New("unexpected permission request")
			}}}
		client, _, _, _ := serviceHTTPConfiguredFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			applications.Add(1)
			w.WriteHeader(http.StatusNoContent)
		}), true, true, func(f *HTTP) {
			f.Token = "run-secret"
			f.Control = control
			prepared, closeHTTP, err := PrepareHTTP(t.Context(), *f)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := closeHTTP(); err != nil {
					t.Error(err)
				}
			})
			*f = prepared
			if cap(f.preparations) != 16 || f.probes.Limits().Concurrency != 4 {
				t.Fatal("prepared run changed its independent preparation/probe bounds", cap(f.preparations), f.probes.Limits().Concurrency)
			}
			view, _, _ := f.Policy.Current()
			applicationToken, err = visitortoken.Sign(view.Issuer, "test-key", key, visitortoken.Permission{
				Scope: f.Subject, Hostname: view.Hostname, Port: view.Port, VisitorPolicyRevision: view.VisitorPolicyRevision,
				Subject:   visitortoken.Browser{IdentityID: "ident_" + strings.Repeat("B", 22), SessionID: "cs_" + strings.Repeat("C", 22)},
				ExpiresAt: time.Now().Add(time.Minute),
			}, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			f.Requests, err = requestlimit.NewHTTP(&controlv1.ProjectHTTPApplicationLimits{
				Total: new(1), Concurrency: new(1), Rate: &controlv1.ProjectApplicationRate{Count: 1, Per: "1h"},
			})
			if err != nil {
				t.Fatal(err)
			}
			f.ReserveCapacity = func(context.Context) error { admissions.Add(1); return nil }
		})
		transport := client.Transport.(*http.Transport)
		dial := transport.DialContext
		transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			connections.Add(1)
			return dial(ctx, network, address)
		}
		transport.MaxConnsPerHost = 1
		client.Timeout = 0
		otherTransport := transport.Clone()
		t.Cleanup(otherTransport.CloseIdleConnections)
		other := &http.Client{Transport: otherTransport}
		share := "/__tnl/share/shr_" + strings.Repeat("S", 22) + "." + base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("s", 32)))
		visit := func(ctx context.Context, client *http.Client, path string, application bool) (int, error) {
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://preview.example.test"+path, nil)
			if err != nil {
				return 0, err
			}
			if application {
				request.Header.Set(httpaccess.VisitorTokenHeader, applicationToken.Reveal())
			} else {
				request.AddCookie(&http.Cookie{Name: httpaccess.BrowserCookieName, Value: base64.RawURLEncoding.EncodeToString(make([]byte, 32))})
			}
			response, err := client.Do(request)
			if err != nil {
				return 0, err
			}
			defer response.Body.Close()
			_, err = io.Copy(io.Discard, response.Body)
			if response.ProtoMajor != 2 {
				return 0, errors.New("preparation fixture did not negotiate HTTP/2")
			}
			return response.StatusCode, err
		}
		var first call
		firstCtx, cancelFirst := context.WithCancel(t.Context())
		defer cancelFirst()
		for i := range 16 {
			path, visitor, ctx := share, client, t.Context()
			if i%2 != 0 {
				path, visitor = "/__tnl/team/session", other
			}
			if i == 0 {
				ctx = firstCtx
			}
			workers.Go(func() { _, _ = visit(ctx, visitor, path, false) })
			current := serviceHTTPAwait(t, entered)
			if current.kind != map[bool]string{false: "share", true: "team"}[i%2 != 0] {
				t.Fatal("preparation workload lost its share/team mix", current.kind)
			}
			if i == 0 {
				first = current
			}
		}
		overflow := func() {
			t.Helper()
			type result struct {
				status int
				err    error
			}
			done := make(chan result, 1)
			workers.Go(func() { status, err := visit(t.Context(), other, share, false); done <- result{status, err} })
			select {
			case <-entered:
				t.Fatal("17th preparation reached control instead of the run-wide bound")
			case got := <-done:
				if got.err != nil || got.status != http.StatusServiceUnavailable {
					t.Fatal("preparation overflow was not rejected", got.status, got.err)
				}
			}
		}
		overflow()
		if calls.Load() != 16 || connections.Load() != 2 || admissions.Load() != 0 || applications.Load() != 0 {
			t.Fatal("preparation did not share one independent run budget", calls.Load(), connections.Load(), admissions.Load(), applications.Load())
		}
		deadline, ok := first.ctx.Deadline()
		if !ok || time.Until(deadline) != 15*time.Second {
			t.Fatal("preparation has no finite 15-second request deadline", time.Until(deadline))
		}
		if status, err := visit(t.Context(), client, "/app", true); err != nil || status != http.StatusNoContent {
			t.Fatal("preparation spent application concurrency, total, rate, or ingress capacity", status, err)
		}
		cancelFirst()
		synctest.Wait()
		if !errors.Is(first.ctx.Err(), context.Canceled) {
			t.Fatal("visitor cancellation did not reach preparation", first.ctx.Err())
		}
		overflow()
		close(first.join)
		synctest.Wait()
		workers.Go(func() { _, _ = visit(t.Context(), client, share, false) })
		replacement := serviceHTTPAwait(t, entered)
		if replacement.ctx.Err() != nil || calls.Load() != 17 || admissions.Load() != 1 || applications.Load() != 1 || connections.Load() != 2 {
			t.Fatal("joined preparation did not release exactly its own slot", calls.Load(), admissions.Load(), applications.Load(), connections.Load())
		}
	})
}

func TestServiceHTTPPreparationDeadlineBoundsWorkWithoutReleasingBeforeJoin(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		started, canceled, join, done := make(chan context.Context, 1), make(chan error, 1), make(chan struct{}), make(chan struct{})
		control := serviceHTTPPreparationControl{work: func(ctx context.Context, _ string) error {
			started <- ctx
			<-ctx.Done()
			canceled <- ctx.Err()
			<-join
			return ctx.Err()
		}}
		f := HTTP{Control: control, preparations: make(chan struct{}, 16), browser: &httpaccess.Browser{Subject: visitorscope.Scope{Kind: visitorscope.Service, ID: "svc_" + strings.Repeat("S", 22)},
			Client: control, RunID: "srun_" + strings.Repeat("R", 22), Number: 1, Token: "run-token"}}
		response := httptest.NewRecorder()
		parent, cancel := context.WithCancel(t.Context())
		finishJoin := sync.OnceFunc(func() { close(join) })
		defer func() { cancel(); finishJoin(); serviceHTTPAwait(t, done) }()
		go func() {
			defer close(done)
			request := httptest.NewRequestWithContext(parent, http.MethodGet, "/__tnl/team/session", nil)
			request.AddCookie(&http.Cookie{Name: httpaccess.BrowserCookieName, Value: base64.RawURLEncoding.EncodeToString(make([]byte, 32))})
			f.reserved(response, request, nil)
		}()
		ctx := serviceHTTPAwait(t, started)
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) != 15*time.Second {
			t.Fatal("preparation work has no original 15-second deadline", time.Until(deadline))
		}
		time.Sleep(15 * time.Second)
		if err := serviceHTTPAwait(t, canceled); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("preparation deadline did not reach owned work", err)
		}
		select {
		case <-done:
			t.Fatal("preparation returned before canceled work joined")
		default:
		}
		if len(f.preparations) != 1 {
			t.Fatal("preparation deadline released its slot before owned work joined")
		}
		finishJoin()
		serviceHTTPAwait(t, done)
		if len(f.preparations) != 0 {
			t.Fatal("joined preparation did not release its slot")
		}
	})
}

func TestServiceHTTPPreparationDeadlineDoesNotEndHTTP2Siblings(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		preparing, preparationStopped := make(chan context.Context, 1), make(chan error, 1)
		appStarted, appFinish := make(chan struct{}), make(chan struct{})
		finishApp := sync.OnceFunc(func() { close(appFinish) })
		defer finishApp()
		control := serviceHTTPPreparationControl{work: func(ctx context.Context, _ string) error {
			preparing <- ctx
			<-ctx.Done()
			preparationStopped <- ctx.Err()
			return ctx.Err()
		}}
		client, policy, update, token := serviceHTTPConfiguredFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			close(appStarted)
			select {
			case <-appFinish:
			case <-r.Context().Done():
				t.Error("preparation deadline ended its HTTP/2 sibling", r.Context().Err())
			}
			w.WriteHeader(http.StatusNoContent)
		}), true, true, func(f *HTTP) {
			f.Control = control
			f.preparations = make(chan struct{}, 16)
			f.browser = &httpaccess.Browser{Subject: f.Subject, Client: control, RunID: f.RunID, Number: f.Number, Token: f.Token}
		})
		client.Timeout = 0
		transport := client.Transport.(*http.Transport)
		transport.MaxConnsPerHost = 1
		var dialed atomic.Bool
		dial := transport.DialContext
		transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			if dialed.Swap(true) {
				return nil, errors.New("preparation deadline forced a second HTTP/2 connection")
			}
			return dial(ctx, network, address)
		}
		// keep the independently prepared run policy current while fake time
		// advances through the longer preparation deadline.
		refreshStop, refreshDone := make(chan struct{}), make(chan struct{})
		go func() {
			defer close(refreshDone)
			ticker := time.NewTicker(3 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					update.View.ObservedAt = time.Now()
					update.View.ValidUntil = time.Now().Add(10 * time.Second)
					if err := policy.Apply(policy.Begin(), update); err != nil {
						t.Error("refresh test policy", err)
						return
					}
				case <-refreshStop:
					return
				}
			}
		}()
		defer func() { close(refreshStop); <-refreshDone }()
		get := func(path string, application bool) serviceHTTPResult {
			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://preview.example.test"+path, nil)
			if err != nil {
				return serviceHTTPResult{err: err}
			}
			if application {
				request.Header.Set(httpaccess.VisitorTokenHeader, token.Reveal())
			} else {
				request.AddCookie(&http.Cookie{Name: httpaccess.BrowserCookieName, Value: visitorfixture.BrowserCookie})
			}
			return serviceHTTPDo(client, request)
		}
		preparationDone, appDone := make(chan serviceHTTPResult, 1), make(chan serviceHTTPResult, 1)
		go func() { preparationDone <- get("/__tnl/team/session", false) }()
		ctx := serviceHTTPAwait(t, preparing)
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) != 15*time.Second {
			t.Fatal("preparation lost its 15-second request context")
		}
		go func() { appDone <- get("/application", true) }()
		serviceHTTPAwait(t, appStarted)
		time.Sleep(16 * time.Second)
		if err := serviceHTTPAwait(t, preparationStopped); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("preparation did not finish at its request deadline", err)
		}
		if got := serviceHTTPAwait(t, preparationDone); got.err != nil || got.status != http.StatusServiceUnavailable || got.protocol != 2 {
			t.Fatalf("preparation deadline failed the HTTP/2 connection: %+v", got)
		}
		select {
		case got := <-appDone:
			t.Fatalf("preparation deadline ended ordinary sibling: %+v", got)
		default:
		}
		if got := get("/__tnl/connection-still-usable", false); got.err != nil || got.status != http.StatusNotFound || got.protocol != 2 {
			t.Fatalf("preparation deadline prevented later HTTP/2 streams: %+v", got)
		}
		finishApp()
		if got := serviceHTTPAwait(t, appDone); got.err != nil || got.status != http.StatusNoContent || got.protocol != 2 {
			t.Fatalf("ordinary sibling did not finish after preparation deadline: %+v", got)
		}
	})
}
