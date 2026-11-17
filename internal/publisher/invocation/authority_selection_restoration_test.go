package invocation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	publisheradhoc "github.com/tnldotdev/tnl/internal/publisher/adhoc"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestForegroundServingClientCannotSupplyManagementAuthority(t *testing.T) {
	f := newForegroundFixture(t)
	serving, err := clientcontrol.New(f.services.authenticated.ServerEndpoint,
		&http.Client{Transport: serviceSetupTransport(f.serve)}, "")
	if err != nil {
		t.Fatal(err)
	}
	selected := f.services
	selected.routes = serving
	if native, saved, _, err := prepareForegroundService(t.Context(), selected, PublicOptions{}, resolvedVisitorAccess{}, foregroundPlan()); !errors.Is(err, clientcontrol.ErrUnauthenticated) || native != nil || saved.Id != "" || f.requests != 0 {
		t.Fatal("serving client supplied implicit management authority", err, f.requests)
	}
	native, saved, _, err := prepareForegroundService(t.Context(), f.services, PublicOptions{}, resolvedVisitorAccess{}, foregroundPlan())
	if err != nil || native == nil || saved.Id != f.saved.Id || f.creates != 1 || f.enrollments != 1 {
		t.Fatal("explicit management selection did not reserve and enroll", err)
	}
}

func TestForegroundSelectedSignedIdentityRejectsSpoofedCallerSelection(t *testing.T) {
	f := newForegroundFixture(t)
	native, _, _, err := prepareForegroundService(t.Context(), f.services, PublicOptions{}, resolvedVisitorAccess{}, foregroundPlan())
	if err != nil {
		t.Fatal(err)
	}
	before := f.requests
	selected, err := publisheridentity.Resolve(t.Context(), f.services.state, publisheridentity.NativeControl{},
		f.services.authenticated.Authority, "", serviceTestID(t, opaqueid.PublisherIdentityPrefix), native)
	if !errors.Is(err, publisheridentity.ErrSelection) || selected != nil || f.requests != before {
		t.Fatal("caller identity overrode the selected signed publisher", err)
	}
	selected, err = publisheridentity.Resolve(t.Context(), f.services.state, publisheridentity.NativeControl{},
		f.services.authenticated.Authority, "", "", native)
	if err != nil || selected.PublisherIdentityID() != native.PublisherIdentityID() ||
		selected.PublisherGrantID() != native.PublisherGrantID() || selected.PublisherKeyID() != native.PublisherKeyID() {
		t.Fatal("explicit signed publisher selection changed its authority", err)
	}
	assertNamespaceAuthorityRun(t, selected, f.saved)
}

func TestEnrolledPolicyOverrideCannotIssueManagementRequests(t *testing.T) {
	f := newForegroundFixture(t)
	native, _, _, err := prepareForegroundService(t.Context(), f.services, PublicOptions{}, resolvedVisitorAccess{}, foregroundPlan())
	if err != nil {
		t.Fatal(err)
	}
	saved, err := native.SavedService(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(f.declaration)
	requests, updates := f.requests, f.updates
	_, err = enrolledServicePlan(t.Context(), EnrolledOptions{PublicOptions: PublicOptions{Target: foregroundPlan().Target, Anonymous: true}}, saved)
	reason, _ := failure.ReasonOf(err)
	after, _ := json.Marshal(f.declaration)
	if reason != failure.PublisherSavedPolicy || f.requests != requests || f.updates != updates || !bytes.Equal(before, after) {
		t.Fatal("serving-only policy override mutated or managed the saved service", err)
	}
}

func TestForegroundDisabledSavedServiceCannotMutateOrRecreate(t *testing.T) {
	f := newForegroundFixture(t)
	if _, _, _, err := prepareForegroundService(t.Context(), f.services, PublicOptions{}, resolvedVisitorAccess{}, foregroundPlan()); err != nil {
		t.Fatal(err)
	}
	f.saved.Enabled = false
	before, _ := json.Marshal(f.declaration)
	creates, updates, enrollments, redemptions := f.creates, f.updates, f.enrollments, f.redemptions
	native, saved, _, err := prepareForegroundService(t.Context(), f.services, PublicOptions{RequirePostQuantum: new(true)},
		resolvedVisitorAccess{explicit: true, access: controlv1.Anonymous}, foregroundPlan())
	reason, _ := failure.ReasonOf(err)
	after, _ := json.Marshal(f.declaration)
	if reason != failure.ServerResponseInvalid || native != nil || saved.Id != "" ||
		f.creates != creates || f.updates != updates || f.enrollments != enrollments || f.redemptions != redemptions ||
		f.saved.Enabled || !bytes.Equal(before, after) {
		t.Fatal("disabled foreground service was changed, recreated, or enrolled", err)
	}
}

func TestForegroundSelectionFailureNeverFallsBackOrMutates(t *testing.T) {
	for _, phase := range []string{"reservation", "configuration"} {
		for _, test := range []struct {
			name     string
			status   int
			code     controlv1.ProblemCode
			cause    error
			reason   failure.Reason
			attempts int
		}{
			{"unavailable", 503, controlv1.Unavailable, clientcontrol.ErrUnavailable, failure.ServerUnavailable, 3},
			{"unauthenticated", 401, controlv1.Unauthenticated, clientcontrol.ErrUnauthenticated, failure.Authentication, 1},
			{"malformed", 200, "", nil, failure.ServerResponseInvalid, 1},
		} {
			t.Run(phase+"/"+test.name, func(t *testing.T) {
				f := newForegroundFixture(t)
				if phase == "configuration" {
					if _, _, _, err := prepareForegroundService(t.Context(), f.services, PublicOptions{}, resolvedVisitorAccess{}, foregroundPlan()); err != nil {
						t.Fatal(err)
					}
				}
				before, _ := json.Marshal(f.declaration)
				creates, updates, enrollments, runs := f.creates, f.updates, f.enrollments, f.runs
				previous := f.before
				var calls int
				var keys []string
				f.before = func(r *http.Request) (*http.Response, bool) {
					selected := phase == "reservation" && r.Method == http.MethodPost && r.URL.Path == "/v1/services" ||
						phase == "configuration" && r.Method == http.MethodGet && r.URL.Path == "/v1/services/"+f.saved.Id+"/configuration"
					if !selected {
						return previous(r)
					}
					calls++
					keys = append(keys, r.Header.Get("Idempotency-Key"))
					if test.name == "malformed" {
						response := serviceTestResponse(r, 200, struct{}{})
						response.Body = http.NoBody
						return response, true
					}
					return serviceTestResponse(r, test.status, controlv1.Problem{Code: test.code, Status: test.status}), true
				}
				native, saved, _, err := prepareForegroundService(t.Context(), f.services, PublicOptions{},
					resolvedVisitorAccess{}, foregroundPlan())
				wantCalls := test.attempts
				if phase == "configuration" {
					wantCalls = 1
				}
				reason, _ := failure.ReasonOf(err)
				after, _ := json.Marshal(f.declaration)
				if reason != test.reason || test.cause != nil && !errors.Is(err, test.cause) ||
					native != nil || saved.Id != "" || calls != wantCalls ||
					f.creates != creates || f.updates != updates || f.enrollments != enrollments || f.runs != runs ||
					!bytes.Equal(before, after) {
					t.Fatal("failed selection mutated state or fell back to another service", err, calls, wantCalls)
				}
				if phase == "reservation" {
					for _, key := range keys {
						if !opaqueid.Valid(key, opaqueid.IdempotencyPrefix) || key != keys[0] {
							t.Fatal("failed reservation retries selected another creation operation")
						}
					}
				}
			})
		}
	}
}

func TestForegroundUnrecoverableConflictsKeepSafeReasonAndCause(t *testing.T) {
	for _, phase := range []string{"reservation", "update"} {
		t.Run(phase, func(t *testing.T) {
			f := newForegroundFixture(t)
			if phase == "update" {
				if _, _, _, err := prepareForegroundService(t.Context(), f.services, PublicOptions{}, resolvedVisitorAccess{}, foregroundPlan()); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := json.Marshal(f.declaration)
			creates, enrollments := f.creates, f.enrollments
			previous := f.before
			calls := 0
			f.before = func(r *http.Request) (*http.Response, bool) {
				if phase == "reservation" && r.Method == http.MethodPost && r.URL.Path == "/v1/services" ||
					phase == "update" && r.Method == http.MethodPut && r.URL.Path == "/v1/services/"+f.saved.Id {
					calls++
					code := controlv1.NameUnavailable
					if phase == "update" {
						code = controlv1.Conflict
					}
					return serviceTestResponse(r, 409, controlv1.Problem{Code: code, Status: 409,
						Detail: "sensitive-provider-conflict-detail"}), true
				}
				return previous(r)
			}
			native, saved, _, err := prepareForegroundService(t.Context(), f.services, PublicOptions{RequirePostQuantum: new(true)},
				resolvedVisitorAccess{}, foregroundPlan())
			wantCause := clientcontrol.ErrNameUnavailable
			if phase == "update" {
				wantCause = clientcontrol.ErrStatusConflict
			}
			reason, _ := failure.ReasonOf(err)
			definition, found := failure.DefinitionFor(reason)
			after, _ := json.Marshal(f.declaration)
			if !errors.Is(err, wantCause) || reason != failure.ServerConflict || !found || definition.Class != failure.Conflict ||
				strings.Contains(definition.Message+definition.Action, "sensitive-provider") ||
				native != nil || saved.Id != "" || calls != 3 || f.creates != creates || f.enrollments != enrollments ||
				!bytes.Equal(before, after) {
				t.Fatal("unrecoverable conflict lost its safe classification, cause, or selected service", err, calls)
			}
		})
	}
}

func TestForegroundConcurrentDifferentOwnerReservationCannotAdoptSavedService(t *testing.T) {
	f := newForegroundFixture(t)
	declaration := controlv1.ProjectServiceConfiguration{Target: "app"}
	first, err := reserveConfiguredService(t.Context(), f.services, declaration)
	if err != nil {
		t.Fatal(err)
	}
	other := f.services
	other.teamID = serviceTestID(t, opaqueid.TeamPrefix)
	before, _ := json.Marshal(f.declaration)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	type result struct {
		other bool
		saved controlv1.Service
		err   error
	}
	start, done := make(chan struct{}), make(chan result, 2)
	var workers sync.WaitGroup
	t.Cleanup(func() { cancel(); workers.Wait() })
	workers.Add(2)
	for _, outsider := range []bool{false, true} {
		go func() {
			defer workers.Done()
			<-start
			selected := f.services
			if outsider {
				selected = other
			}
			saved, err := reserveConfiguredService(ctx, selected, declaration,
				func(controlv1.Service, *controlv1.ProjectServiceConfiguration) (*controlv1.ProjectServiceConfiguration, error) {
					return nil, nil
				})
			done <- result{outsider, saved, err}
		}()
	}
	close(start)
	for range 2 {
		select {
		case got := <-done:
			if got.other {
				if !errors.Is(got.err, clientcontrol.ErrStatusConflict) || got.saved.Id != "" {
					t.Fatal("different-owner reservation adopted the saved service", got.err)
				}
			} else if got.err != nil || got.saved.Id != first.Id {
				t.Fatal("own reservation did not retain its exact service", got.err)
			}
		case <-ctx.Done():
			t.Fatal("concurrent reservations did not join", context.Cause(ctx))
		}
	}
	workers.Wait()
	after, _ := json.Marshal(f.declaration)
	if f.creates != 1 || f.updates != 0 || f.enrollments != 0 || !bytes.Equal(before, after) {
		t.Fatal("different-owner race changed or enrolled the original service")
	}
}

func TestForegroundEphemeralSelectionAllocatesFreshLifetimes(t *testing.T) {
	f := newServiceSetupFixture(t, "existing.member.example")
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	f.services.namespace = "member.example"
	f.identity.Kind, f.identity.ServiceId = authorityv1.Namespace, nil
	f.identity.DomainId, f.identity.Namespace = &f.services.domainID, &f.services.namespace
	f.saved.Ephemeral, f.created = true, true
	existing := f.saved
	allocations := map[string]controlv1.Service{}
	var invocations, deleted []string
	inventories, oldSelections := 0, 0
	previous := f.before
	f.before = func(r *http.Request) (*http.Response, bool) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/services" {
			inventories++
		}
		if r.Method == http.MethodGet && r.URL.Path == "/v1/publisher/services/"+existing.Id {
			oldSelections++
		}
		if r.Method == http.MethodPost && r.URL.Path == "/v1/publisher-enrollments" {
			var body controlv1.CreatePublisherEnrollmentRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body.TeamId != f.services.teamID || body.DomainId == nil || *body.DomainId != f.services.domainID ||
				body.ServiceId != nil || r.Header.Get("Authorization") != "Bearer session" {
				t.Fatal("temporary selection changed namespace enrollment authority")
			}
			return f.issueEnrollment(r, controlv1.PublisherEnrollment{
				ExpiresAt: time.Now().Add(time.Minute), TeamId: f.services.teamID,
				Kind: controlv1.PublisherEnrollmentKindNamespace, DomainId: &f.services.domainID, Namespace: &f.services.namespace}), true
		}
		if r.Method == http.MethodPost && r.URL.Path == "/v1/publisher/services" {
			if r.Header.Get("Authorization") != "Bearer service-access" {
				t.Fatal("temporary allocation did not use signed publisher access")
			}
			var body controlv1.AllocateServiceRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if !opaqueid.Valid(body.InvocationId, opaqueid.InvocationPrefix) || body.Configuration.Ephemeral == nil || !*body.Configuration.Ephemeral {
				t.Fatal("temporary allocation omitted its fresh lifetime")
			}
			saved := existing
			saved.Id = serviceTestID(t, opaqueid.ServicePrefix)
			saved.Endpoint = &controlv1.ServiceEndpoint{Hostname: fmt.Sprintf("fresh-%d.member.example", len(invocations)+1), Port: 443, Public: true}
			saved.HttpLimits = body.Configuration.Http.Limits
			allocations[saved.Id] = saved
			invocations = append(invocations, body.InvocationId)
			return serviceTestResponse(r, 201, saved), true
		}
		for id, saved := range allocations {
			if r.URL.Path == "/v1/publisher/services/"+id && r.Header.Get("Authorization") != "Bearer service-access" {
				t.Fatal("temporary selection or cleanup did not use signed publisher access")
			}
			if r.URL.Path == "/v1/publisher/services/"+id && r.Method == http.MethodGet {
				return serviceTestResponse(r, 200, saved), true
			}
			if r.URL.Path == "/v1/publisher/services/"+id && r.Method == http.MethodDelete {
				deleted = append(deleted, id)
				response := serviceTestResponse(r, http.StatusNoContent, nil)
				response.Body = http.NoBody
				return response, true
			}
		}
		if previous != nil {
			return previous(r)
		}
		return nil, false
	}
	native, _, err := publisheridentity.EnsureNamespace(ctx, f.services.state, f.services.authenticated.Control,
		f.services.authenticated.Authority, f.services.teamID, f.services.domainID, f.services.namespace)
	if err != nil {
		t.Fatal(err)
	}
	var preparations []*publisheradhoc.Prepared
	t.Cleanup(func() {
		for _, prepared := range preparations {
			ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 5*time.Second)
			if err := prepared.Cleanup(ctx); err != nil {
				t.Error("clean temporary lifetime", err)
			}
			cancel()
		}
	})
	for range 2 {
		prepared, err := publisheradhoc.Prepare(ctx, publisheradhoc.Options{
			ControlURL: native.ControlURL(), State: f.services.state, Publisher: native,
			InvocationID: serviceTestID(t, opaqueid.InvocationPrefix), Target: foregroundPlan().Target})
		if prepared != nil {
			preparations = append(preparations, prepared)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(invocations) != 2 || invocations[0] == invocations[1] ||
		preparations[0].Service.Id == preparations[1].Service.Id || preparations[0].Service.Id == existing.Id ||
		preparations[1].Service.Id == existing.Id || inventories != 0 || oldSelections != 0 ||
		f.creates != 0 || f.updates != 0 || f.enrollments != 1 || f.redemptions != 1 {
		t.Fatal("temporary invocation adopted a saved lifetime or changed durable service management")
	}
	for _, prepared := range preparations {
		if err := prepared.Cleanup(ctx); err != nil {
			t.Fatal(err)
		}
	}
	wantDeleted := []string{preparations[0].Service.Id, preparations[1].Service.Id}
	if !reflect.DeepEqual(deleted, wantDeleted) || len(invocations) != 2 {
		t.Fatal("temporary lifetime cleanup selected or reallocated another service", deleted)
	}
}
