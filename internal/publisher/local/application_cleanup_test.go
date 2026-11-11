package local

import (
	"context"
	"errors"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/publisher"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	"github.com/tnldotdev/tnl/internal/publisher/invocation"
	"github.com/tnldotdev/tnl/internal/publisher/localapi"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
)

func TestApplicationPublicationWorkerCleanupRetryAcknowledgesSuccess(t *testing.T) {
	// keep the native HTTP boundary, registration manager, Workers.Run and SQLite
	// tunnel real. only the publication transport is replaced by a bound worker.
	a, _ := testAppRuntimeWorkers(t, true)
	endpoint, request := applicationRequest(t, a)
	request.ResourceId = nil
	request.Allocate = &struct {
		Namespace string `json:"namespace"`
	}{Namespace: "user.example"}
	var attempts atomic.Int32
	a.ApplicationAuthority = applicationAuthority(func(_ context.Context, selection invocation.ApplicationSelection) (invocation.ApplicationGrant, error) {
		grant := applicationGrant(selection)
		grant.Cleanup = func(context.Context) error {
			if attempts.Add(1) == 1 {
				return errors.New("transient allocation deletion failure")
			}
			return nil
		}
		return grant, nil
	})
	started := make(chan struct{})
	a.workers.RunPublisher = func(ctx context.Context, _ publisher.Config) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	}
	var accepted publisherprotocol.AcceptedPublication
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/publications", request, &accepted); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("Workers.Run did not reach the publication transport")
	}
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/unregister", accepted.Registration, nil); err != nil {
		t.Fatalf("successful allocation cleanup retry was not acknowledged: attempts=%d err=%v", attempts.Load(), err)
	}
	if attempts.Load() != 2 {
		t.Fatalf("cleanup attempts=%d, want one transient failure and one successful retry", attempts.Load())
	}
	if _, found := a.manager.ServiceForRegistration(accepted.Registration.RegistrationID); found {
		t.Fatal("successful cleanup retained registration ownership")
	}
	var snapshot publisherapp.Snapshot
	if err := publisherprotocol.Call(t.Context(), endpoint, "GET", "/v1/status", nil, &snapshot); err != nil || len(snapshot.Services) != 1 || snapshot.Services[0].Failure != "" {
		t.Fatalf("repaired cleanup remained a terminal publication error: %+v %v", snapshot.Services, err)
	}
	if err := publisherprotocol.Call(t.Context(), endpoint, "DELETE", "/v1/capability", nil, nil); err != nil {
		t.Fatal("cleaned publication could not release its capability", err)
	}
}

func TestApplicationPublicationWorkerCleanupRetryPreservesIndependentFailure(t *testing.T) {
	for _, independentFailure := range []bool{false, true} {
		name := "cleanup-only"
		if independentFailure {
			name = "independent-publication-failure"
		}
		t.Run(name, func(t *testing.T) {
			a, _ := testAppRuntimeWorkers(t, true)
			endpoint, request := applicationRequest(t, a)
			request.ResourceId = nil
			request.Allocate = &struct {
				Namespace string `json:"namespace"`
			}{Namespace: "user.example"}
			cleanupFailure := errors.New("allocation deletion unavailable")
			var operationFailure error
			if independentFailure {
				operationFailure = errors.New("publication operation failed independently")
			}
			var attempts atomic.Int32
			a.ApplicationAuthority = applicationAuthority(func(_ context.Context, selection invocation.ApplicationSelection) (invocation.ApplicationGrant, error) {
				grant := applicationGrant(selection)
				grant.Cleanup = func(context.Context) error {
					if attempts.Add(1) <= 2 {
						return cleanupFailure
					}
					return nil
				}
				return grant, nil
			})
			started := make(chan struct{})
			a.workers.RunPublisher = func(ctx context.Context, _ publisher.Config) error {
				close(started)
				<-ctx.Done()
				return errors.Join(ctx.Err(), operationFailure)
			}
			var accepted publisherprotocol.AcceptedPublication
			if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/publications", request, &accepted); err != nil {
				t.Fatal(err)
			}
			select {
			case <-started:
			case <-time.After(3 * time.Second):
				t.Fatal("Workers.Run did not reach the publication transport")
			}
			before := a.manager.Snapshot()
			registration := accepted.Registration
			// inspect the native cause tree as well as its bounded HTTP error.
			firstErr := a.manager.UnregisterTarget(registration.RegistrationID, registration.Owner, registration.Target)
			if !errors.Is(firstErr, publisherapp.ErrCleanupFailed) || !errors.Is(firstErr, cleanupFailure) || !errors.Is(firstErr, context.Canceled) || independentFailure && !errors.Is(firstErr, operationFailure) {
				t.Fatal("first close lost an independent cause", firstErr)
			}
			problem := httptest.NewRecorder()
			localapi.Problem(problem, firstErr)
			if problem.Code != 503 {
				t.Fatalf("retryable cleanup returned HTTP %d", problem.Code)
			}
			service, found := a.manager.ServiceForRegistration(registration.RegistrationID)
			if !found || service.Registered || service.Failure != "runtime.cleanup_failed" {
				t.Fatal("incomplete cleanup released its registration or remained routable")
			}
			secondErr := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/unregister", registration, nil)
			if independentFailure {
				var response *publisherprotocol.ResponseError
				if !errors.As(secondErr, &response) || response.Status != 503 || response.Code != "runtime.publication_failed" {
					t.Fatal("terminal publication failure was hidden or confused with cleanup", secondErr)
				}
			} else if secondErr != nil {
				t.Fatal("successful explicit cleanup retry was not acknowledged", secondErr)
			}
			if attempts.Load() != 3 {
				t.Fatalf("cleanup attempts=%d, want two failures and one successful retry", attempts.Load())
			}
			if _, found := a.manager.ServiceForRegistration(registration.RegistrationID); found {
				t.Fatal("successful cleanup retry retained ownership")
			}
			var snapshot publisherapp.Snapshot
			if err := publisherprotocol.Call(t.Context(), endpoint, "GET", "/v1/status", nil, &snapshot); err != nil {
				t.Fatal(err)
			}
			wantFailure := ""
			if independentFailure {
				wantFailure = "runtime.publication_failed"
			}
			if len(snapshot.Services) != 1 || snapshot.Services[0].Failure != wantFailure || snapshot.Services[0].Registered {
				t.Fatalf("cleanup and publication outcomes were conflated: %+v", snapshot.Services)
			}
			var events []publisherapp.Event
			if err := publisherprotocol.Call(t.Context(), endpoint, "GET", "/v1/events?after="+before.Cursor, nil, &events); err != nil {
				t.Fatal(err)
			}
			var cleanupObserved, operationObserved bool
			for _, event := range events {
				if event.Service != nil {
					cleanupObserved = cleanupObserved || event.Service.Failure == "runtime.cleanup_failed"
					operationObserved = operationObserved || event.Service.Failure == "runtime.publication_failed"
				}
			}
			if !cleanupObserved || operationObserved != independentFailure {
				t.Fatal("native events lost or invented an independent failure")
			}
			if err := publisherprotocol.Call(t.Context(), endpoint, "DELETE", "/v1/capability", nil, nil); err != nil {
				t.Fatal("joined publication could not release its capability", err)
			}
		})
	}
}

func TestApplicationPublicationWithoutAuthorityFailsClosed(t *testing.T) {
	a, _ := testAppRuntimeWorkers(t, true)
	endpoint, request := applicationRequest(t, a)
	var workers atomic.Int32
	a.workers.RunPublisher = func(context.Context, publisher.Config) error { workers.Add(1); return nil }
	var response *publisherprotocol.ResponseError
	err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/publications", request, nil)
	if !errors.As(err, &response) || response.Status != 503 || response.Code != "runtime.credential_unavailable" || workers.Load() != 0 {
		t.Fatal("missing production authority did not fail closed", err)
	}
	for _, service := range a.manager.Snapshot().Services {
		if service.Name == request.InvocationId {
			t.Fatal("missing authority created a registration")
		}
	}
}

func TestApplicationPublicationWorkerFailureBeforeTransportCleansAllocation(t *testing.T) {
	a, _ := testAppRuntimeWorkers(t, true)
	endpoint, request := applicationRequest(t, a)
	request.ResourceId = nil
	request.Allocate = &struct {
		Namespace string `json:"namespace"`
	}{Namespace: "user.example"}
	var cleaned, transported atomic.Int32
	a.ApplicationAuthority = applicationAuthority(func(_ context.Context, selection invocation.ApplicationSelection) (invocation.ApplicationGrant, error) {
		grant := applicationGrant(selection)
		grant.Cleanup = func(context.Context) error { cleaned.Add(1); return nil }
		return grant, nil
	})
	a.AttachPublication = func(_ context.Context, _ publisherapp.Service, cfg *publisher.Config) error {
		cfg.ControlURL = "http://invalid.example"
		return nil
	}
	a.workers.RunPublisher = func(context.Context, publisher.Config) error { transported.Add(1); return nil }
	var accepted publisherprotocol.AcceptedPublication
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/publications", request, &accepted); err != nil {
		t.Fatal(err)
	}
	waitInvocation(t, a, func(snapshot publisherapp.Snapshot) bool {
		for _, service := range snapshot.Services {
			if service.RegistrationID == accepted.Registration.RegistrationID {
				return service.Failure != ""
			}
		}
		return false
	})
	if cleaned.Load() != 1 || transported.Load() != 0 {
		t.Fatalf("early Workers.Run failure leaked allocation or reached transport: cleaned=%d transported=%d", cleaned.Load(), transported.Load())
	}
	var response *publisherprotocol.ResponseError
	err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/unregister", accepted.Registration, nil)
	if !errors.As(err, &response) || response.Status != 503 || response.Code != "runtime.publication_failed" || cleaned.Load() != 1 {
		t.Fatal("close lost the independent early worker error or repeated successful cleanup", err)
	}
}
