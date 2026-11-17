package adhoc

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/applicationlimits"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestAllocationRequestUsesCanonicalServiceDeclarationAndCopiesInput(t *testing.T) {
	expires := time.Now().Add(time.Hour)
	options := Options{InvocationID: "inv_" + strings.Repeat("I", 22), Target: "https://app.example.test:8443",
		RequirePostQuantum: true, ExpiresAt: &expires, IP: []string{"192.0.2.9/24", "::ffff:192.0.2.19/120", "192.0.2.1", "::ffff:192.0.2.1"},
		TargetTLS: &controlv1.ProjectTargetTLS{Hostname: "target.example.test"},
		Limits:    applicationlimits.Limits{Requests: 2, Concurrency: 3, RateRequests: 4, RatePer: time.Minute, RateBurst: 5}}
	body, address, trust, err := allocationRequest(options)
	if err != nil {
		t.Fatal(err)
	}
	configuration := body.Configuration
	if body.InvocationId != options.InvocationID || address != "app.example.test:8443" || configuration.Target != address ||
		configuration.Protocol == nil || *configuration.Protocol != controlv1.ServiceProtocolHTTP ||
		configuration.Public == nil || !*configuration.Public || configuration.Ephemeral == nil || !*configuration.Ephemeral ||
		configuration.RequirePostQuantum == nil || !*configuration.RequirePostQuantum || configuration.Hostname != nil ||
		configuration.DomainId != nil || configuration.Name != nil || configuration.Http == nil ||
		configuration.Http.Access == nil || *configuration.Http.Access.Mode != controlv1.Restricted {
		t.Fatal("allocation did not contain an ordinary restricted HTTP declaration", body)
	}
	if trust == nil || !trust.System || trust.Hostname != "target.example.test" || configuration.TargetTls.Digest == trust.Digest {
		t.Fatal("declaration and saved target trust were confused", trust, configuration.TargetTls)
	}
	if err := trust.Validate(); err != nil {
		t.Fatal(err)
	}
	want := &controlv1.ProjectHTTPApplicationLimits{Total: new(2), Concurrency: new(3),
		Rate: &controlv1.ProjectApplicationRate{Count: 4, Per: "1m0s", Burst: new(5)}}
	if !reflect.DeepEqual(configuration.Http.Limits, want) || !reflect.DeepEqual(*configuration.Http.Access.Ip, []string{"192.0.2.0/24", "192.0.2.1/32"}) {
		t.Fatal("allocation lost canonical HTTP limits or IP policy", configuration.Http)
	}
	captured, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	expires = expires.Add(time.Hour)
	options.IP[0], options.TargetTLS.Hostname = "198.51.100.0/24", "changed.example.test"
	options.Limits.Requests++
	again, err := json.Marshal(body)
	if err != nil || string(captured) != string(again) {
		t.Fatal("caller mutation changed the captured invocation", err)
	}
}

func TestAllocationRequestRejectsInvalidInputs(t *testing.T) {
	for _, modify := range []func(*Options){
		func(o *Options) { o.Target = "http://localhost:3000" },
		func(o *Options) { o.AccessMode = "public" },
		func(o *Options) { o.IP = []string{"not-an-ip"} },
		func(o *Options) { o.Limits.RatePer = time.Second },
		func(o *Options) { o.ExpiresAt = new(time.Now().Add(-time.Second)) },
		func(o *Options) { o.TargetTLS = &controlv1.ProjectTargetTLS{Hostname: "target.example.test"} },
		func(o *Options) {
			o.Target = "https://app.example.test:443"
			o.TargetTLS = &controlv1.ProjectTargetTLS{Hostname: "app.example.test", Digest: "substituted"}
		},
	} {
		options := Options{Target: "http://127.0.0.1:3000"}
		modify(&options)
		if _, _, _, err := allocationRequest(options); err == nil {
			t.Fatal("invalid allocation input was accepted", options)
		}
	}
}

func TestAllocationRequestKeepsDefaultAndExplicitHostnameProvenance(t *testing.T) {
	for _, test := range []struct {
		name      string
		setting   *controlv1.ProjectTargetTLS
		automatic bool
	}{
		{name: "origin default", automatic: true},
		{name: "explicit same hostname", setting: &controlv1.ProjectTargetTLS{Hostname: "app.example.test"}},
		{name: "captured default", setting: &controlv1.ProjectTargetTLS{Hostname: "app.example.test", HostnameFromTarget: true}, automatic: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			body, _, trust, err := allocationRequest(Options{Target: "https://app.example.test:443", TargetTLS: test.setting})
			if err != nil {
				t.Fatal(err)
			}
			if trust == nil || body.Configuration.TargetTls == nil || trust.HostnameFromTarget != test.automatic ||
				body.Configuration.TargetTls.HostnameFromTarget != test.automatic {
				t.Fatal("allocation lost the captured hostname choice", trust, body.Configuration.TargetTls)
			}
		})
	}
}

type allocationControl struct {
	publisheridentity.ServiceControl
	allocate                        func(controlv1.AllocateServiceRequest) (controlv1.Service, error)
	read                            func() (controlv1.Service, error)
	remove                          func(string) error
	namespaceCalls, deploymentCalls int
}

func (*allocationControl) ControlURL() string { return "https://control.example.test" }

func (c *allocationControl) AllocatePublisherService(_ context.Context, access string, body controlv1.AllocateServiceRequest) (controlv1.Service, error) {
	c.namespaceCalls++
	if access != "signed-allocation-token" {
		return controlv1.Service{}, errors.New("allocation used a human credential")
	}
	return c.allocate(body)
}

func (c *allocationControl) AllocateDeploymentPublication(_ context.Context, access, team, project, deployment string, body controlv1.AllocateServiceRequest) (controlv1.Service, error) {
	c.deploymentCalls++
	if access != "signed-allocation-token" || team != "team" || project != "project" || deployment != "production" {
		return controlv1.Service{}, publisheridentity.ErrScope
	}
	return c.allocate(body)
}

func (c *allocationControl) GetPublisherService(_ context.Context, _ string, access string) (controlv1.Service, error) {
	if access != "signed-allocation-token" {
		return controlv1.Service{}, errors.New("selection used a human credential")
	}
	return c.read()
}

func (c *allocationControl) DeletePublisherService(_ context.Context, access, id string) error {
	if access != "signed-allocation-token" {
		return errors.New("cleanup used a human credential")
	}
	return c.remove(id)
}

type allocationAuthority struct{}

func (allocationAuthority) ExchangePublisherAssertion(context.Context, string, string, string, ed25519.PrivateKey) (string, error) {
	return "signed-allocation-token", nil
}

func allocationNative(t *testing.T, control *allocationControl) *publisheridentity.Native {
	t.Helper()
	native, err := publisheridentity.NewNative(publisheridentity.NativeControl{Services: control, Allocations: control}, allocationAuthority{},
		authorityv1.PublisherEnrollmentResult{ClientId: opaqueid.PublisherIdentityPrefix + strings.Repeat("I", 22),
			GrantId: opaqueid.PublisherGrantPrefix + strings.Repeat("G", 22), KeyId: opaqueid.PublisherIdentityKeyPrefix + strings.Repeat("K", 22),
			Kind: authorityv1.Namespace, TeamId: "team", DomainId: new(opaqueid.DomainPrefix + strings.Repeat("D", 22)), Namespace: new("member.example.test")},
		ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	return native
}

func deploymentAllocationNative(t *testing.T, control *allocationControl) *publisheridentity.Native {
	t.Helper()
	native, err := publisheridentity.NewDeploymentAllocator(control, allocationAuthority{},
		controlv1.DeploymentCredential{ClientId: opaqueid.PublisherIdentityPrefix + strings.Repeat("I", 22),
			GrantId: opaqueid.PublisherGrantPrefix + strings.Repeat("G", 22), KeyId: opaqueid.PublisherIdentityKeyPrefix + strings.Repeat("K", 22),
			TeamId: "team", ProjectKey: "project", ExpiresAt: time.Now().Add(time.Hour)},
		ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)), "production")
	if err != nil {
		t.Fatal(err)
	}
	return native
}

func allocatedService(body controlv1.AllocateServiceRequest) controlv1.Service {
	service := controlv1.Service{Id: opaqueid.ServicePrefix + strings.Repeat("S", 22), TeamId: "team", DomainId: new(opaqueid.DomainPrefix + strings.Repeat("D", 22)),
		Protocol: controlv1.ServiceProtocolHTTP, Enabled: true, Ephemeral: true, TrustRevision: 1, ExpiresAt: body.ExpiresAt,
		Endpoint: &controlv1.ServiceEndpoint{Hostname: "temporary.member.example.test", Public: true, Port: 443}}
	if body.Configuration.RequirePostQuantum != nil {
		service.RequirePostQuantum = *body.Configuration.RequirePostQuantum
	}
	if body.Configuration.TargetTls != nil {
		tls := body.Configuration.TargetTls
		ca := ""
		if tls.CaPem != nil {
			ca = *tls.CaPem
		}
		declaration, _ := targettrust.NewDeclaration(tls.Hostname, []byte(ca))
		trust, _ := declaration.Snapshot()
		service.TargetTls = publisheridentity.ServiceTargetTLS(trust)
	}
	service.HttpLimits = body.Configuration.Http.Limits
	return service
}

func allocationOptions(native *publisheridentity.Native) Options {
	return Options{ControlURL: native.ControlURL(), Publisher: native, State: &clientstate.Store{},
		InvocationID: opaqueid.InvocationPrefix + strings.Repeat("V", 22), Target: "http://127.0.0.1:3000"}
}

func TestAllocationLostReplyRetriesImmutableInvocationAndExactCleanup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		control := &allocationControl{}
		native := allocationNative(t, control)
		options := allocationOptions(native)
		expires := time.Now().Add(time.Hour)
		options.ExpiresAt, options.IP = &expires, []string{"192.0.2.0/24"}
		var bodies [][]byte
		var saved controlv1.Service
		control.allocate = func(body controlv1.AllocateServiceRequest) (controlv1.Service, error) {
			encoded, _ := json.Marshal(body)
			bodies = append(bodies, encoded)
			if len(bodies) == 1 {
				saved = allocatedService(body)
				expires = expires.Add(time.Hour)
				options.IP[0] = "198.51.100.0/24"
				return controlv1.Service{Id: "fabricated"}, io.ErrUnexpectedEOF
			}
			return saved, nil
		}
		control.read = func() (controlv1.Service, error) { return saved, nil }
		var deleted []string
		control.remove = func(id string) error { deleted = append(deleted, id); return nil }
		stopped := errors.New("registration stopped")
		options.OnAllocated = func(snapshot controlv1.Service) error {
			snapshot.Id, snapshot.Endpoint.Hostname = "changed", "changed.example.test"
			return errors.Join(context.Canceled, stopped)
		}
		err := Run(t.Context(), options)
		if !errors.Is(err, stopped) || len(bodies) != 2 || string(bodies[0]) != string(bodies[1]) ||
			!reflect.DeepEqual(deleted, []string{saved.Id}) || saved.Endpoint.Hostname != "temporary.member.example.test" {
			t.Fatal("lost reply changed invocation, snapshot, or cleanup ownership", err, deleted)
		}
		if err := native.DeleteAllocatedService(t.Context(), saved.Id); !errors.Is(err, publisheridentity.ErrScope) {
			t.Fatal("forked invocation mutated the prepared identity", err)
		}
	})
}

func TestAllocationFailedSelectionRetainsObservedCleanupOnSameNative(t *testing.T) {
	control := &allocationControl{}
	native := allocationNative(t, control)
	var saved controlv1.Service
	control.allocate = func(body controlv1.AllocateServiceRequest) (controlv1.Service, error) {
		saved = allocatedService(body)
		return saved, nil
	}
	selection, firstCleanup := errors.New("selection failed"), errors.New("initial observed cleanup failed")
	control.read = func() (controlv1.Service, error) { return controlv1.Service{}, selection }
	var deleted []string
	control.remove = func(id string) error {
		deleted = append(deleted, id)
		if len(deleted) == 1 {
			return firstCleanup
		}
		return nil
	}
	options := allocationOptions(native)
	options.OnAllocated = func(controlv1.Service) error { t.Error("failed selection reached publication"); return nil }
	err := Run(t.Context(), options)
	if !errors.Is(err, selection) || !errors.Is(err, firstCleanup) || !reflect.DeepEqual(deleted, []string{saved.Id, saved.Id}) {
		t.Fatal("observed allocation cleanup was abandoned or replaced", err, deleted)
	}
}

func TestAllocationUnvalidatedResponseNeverDeletesFabricatedID(t *testing.T) {
	control := &allocationControl{}
	native := allocationNative(t, control)
	control.allocate = func(body controlv1.AllocateServiceRequest) (controlv1.Service, error) {
		saved := allocatedService(body)
		saved.Endpoint.Hostname = "outside.example.test"
		return saved, nil
	}
	control.remove = func(string) error { t.Error("unvalidated response was treated as cleanup ownership"); return nil }
	options := allocationOptions(native)
	options.OnAllocated = func(controlv1.Service) error { t.Error("unvalidated response reached publication"); return nil }
	if err := Run(t.Context(), options); err == nil || !strings.Contains(err.Error(), options.InvocationID) {
		t.Fatal("ambiguous response lost its original recovery invocation", err)
	}
}

func TestAllocationCleanupKeepsIndependentCancellationFailures(t *testing.T) {
	control := &allocationControl{}
	native := allocationNative(t, control)
	var saved controlv1.Service
	control.allocate = func(body controlv1.AllocateServiceRequest) (controlv1.Service, error) {
		saved = allocatedService(body)
		return saved, nil
	}
	control.read = func() (controlv1.Service, error) { return saved, nil }
	primary, cleanup := errors.New("publication stopped"), errors.New("cleanup failed")
	control.remove = func(string) error { return errors.Join(context.Canceled, cleanup) }
	options := allocationOptions(native)
	options.OnAllocated = func(controlv1.Service) error { return errors.Join(context.Canceled, primary) }
	if err := Run(t.Context(), options); !errors.Is(err, primary) || !errors.Is(err, cleanup) {
		t.Fatal("cancellation discarded independent failures", err)
	}
}

func TestAllocationRetryDoesNotRenewFixedExpiration(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		control := &allocationControl{}
		native := allocationNative(t, control)
		options := allocationOptions(native)
		start := time.Now()
		options.ExpiresAt = new(start.Add(250 * time.Millisecond))
		var attempts int
		control.allocate = func(body controlv1.AllocateServiceRequest) (controlv1.Service, error) {
			attempts++
			if body.ExpiresAt == nil || !body.ExpiresAt.Equal(*options.ExpiresAt) {
				t.Error("ambiguous retry moved the fixed expiration")
			}
			return controlv1.Service{}, io.ErrUnexpectedEOF
		}
		control.remove = func(string) error { t.Error("unobserved allocation was deleted"); return nil }
		err := Run(t.Context(), options)
		if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, io.ErrUnexpectedEOF) ||
			!strings.Contains(err.Error(), options.InvocationID) || attempts != 2 || time.Since(start) != 250*time.Millisecond {
			t.Fatal("retry renewed expiration or discarded recovery facts", err, attempts, time.Since(start))
		}
	})
}

func TestAllocationRetryDoesNotDiscardIndependentFailure(t *testing.T) {
	independent := errors.New("independent cleanup failure")
	for _, transient := range []error{clientcontrol.ErrUnavailable, clientcontrol.ErrRateLimited, io.ErrUnexpectedEOF} {
		if !retryAllocation(transient) || retryAllocation(errors.Join(transient, independent)) ||
			retryAllocation(errors.Join(context.Canceled, transient)) || retryAllocation(errors.Join(context.DeadlineExceeded, transient)) {
			t.Fatal("retry classification discarded an independent failure", transient)
		}
	}
	if retryAllocation(context.Canceled) || retryAllocation(context.DeadlineExceeded) {
		t.Fatal("terminal cancellation or original expiry was retried")
	}
}

func TestAllocationCancellationDuringLostReplyRecoversExactCleanup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		control := &allocationControl{}
		native := allocationNative(t, control)
		options := allocationOptions(native)
		fixedExpiry := time.Now().Add(time.Hour)
		options.ExpiresAt = &fixedExpiry
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		committed := make(chan struct{})
		var saved controlv1.Service
		var bodies [][]byte
		control.allocate = func(body controlv1.AllocateServiceRequest) (controlv1.Service, error) {
			encoded, _ := json.Marshal(body)
			bodies = append(bodies, encoded)
			if len(bodies) == 1 {
				saved = allocatedService(body)
				close(committed)
				return controlv1.Service{}, io.ErrUnexpectedEOF
			}
			return saved, nil
		}
		control.read = func() (controlv1.Service, error) {
			t.Error("cleanup recovered publication selection instead of allocation ownership")
			return controlv1.Service{}, errors.New("cleanup must not select a service")
		}
		var deleted []string
		control.remove = func(id string) error { deleted = append(deleted, id); return nil }
		options.OnAllocated = func(controlv1.Service) error {
			t.Error("canceled recovery reached publication")
			return nil
		}
		done := make(chan error, 1)
		go func() { done <- Run(ctx, options) }()
		<-committed
		// cancel while the lost-response retry is waiting, not inside the
		// allocation call. cleanup must still recover the original invocation.
		synctest.Wait()
		cancel()
		err := <-done
		if !errors.Is(err, context.Canceled) ||
			len(bodies) != 2 || string(bodies[0]) != string(bodies[1]) ||
			!reflect.DeepEqual(deleted, []string{saved.Id}) || !saved.ExpiresAt.Equal(fixedExpiry) {
			t.Fatal("canceled lost reply abandoned or replaced the original allocation", err, len(bodies), deleted)
		}
	})
}

func TestAllocationCleanupRetriesNativeOperationWithoutReselection(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		control := &allocationControl{}
		native := allocationNative(t, control)
		options := allocationOptions(native)
		var saved controlv1.Service
		var allocations, selections int
		control.allocate = func(body controlv1.AllocateServiceRequest) (controlv1.Service, error) {
			allocations++
			saved = allocatedService(body)
			return saved, nil
		}
		control.read = func() (controlv1.Service, error) {
			selections++
			return saved, nil
		}
		var deleted []string
		control.remove = func(id string) error {
			deleted = append(deleted, id)
			if len(deleted) == 1 {
				return io.ErrUnexpectedEOF
			}
			return nil
		}
		stopped := errors.New("registration stopped")
		options.OnAllocated = func(controlv1.Service) error { return stopped }
		err := Run(t.Context(), options)
		if !errors.Is(err, stopped) || allocations != 1 || selections != 1 ||
			!reflect.DeepEqual(deleted, []string{saved.Id, saved.Id}) {
			t.Fatal("cleanup retry reallocated, reselected, or lost exact ownership", err, allocations, selections, deleted)
		}
	})
}

func TestAllocationRejectsSubstitutedSavedPublicationFacts(t *testing.T) {
	for _, fact := range []string{"protocol", "endpoint", "target_trust", "post_quantum", "expiration", "http_limits"} {
		t.Run(fact, func(t *testing.T) {
			control := &allocationControl{}
			native := allocationNative(t, control)
			options := allocationOptions(native)
			options.Target = "https://target.example.test:443"
			options.RequirePostQuantum = true
			options.ExpiresAt = new(time.Now().Add(time.Hour))
			options.Limits.Requests = 3
			var saved controlv1.Service
			control.allocate = func(body controlv1.AllocateServiceRequest) (controlv1.Service, error) {
				saved = allocatedService(body)
				return saved, nil
			}
			control.read = func() (controlv1.Service, error) {
				selected := saved
				selected.Endpoint = new(*saved.Endpoint)
				switch fact {
				case "protocol":
					selected.Protocol = controlv1.ServiceProtocol("tcp")
				case "endpoint":
					selected.Endpoint.Port = 8443
				case "target_trust":
					declaration, err := targettrust.NewDeclaration("substituted.example.test", nil)
					if err != nil {
						t.Fatal(err)
					}
					trust, err := declaration.Snapshot()
					if err != nil {
						t.Fatal(err)
					}
					selected.TargetTls = publisheridentity.ServiceTargetTLS(trust)
				case "post_quantum":
					selected.RequirePostQuantum = false
				case "expiration":
					selected.ExpiresAt = new(saved.ExpiresAt.Add(time.Hour))
				case "http_limits":
					selected.HttpLimits = &controlv1.ProjectHTTPApplicationLimits{Total: new(7)}
				}
				return selected, nil
			}
			var deleted []string
			control.remove = func(id string) error { deleted = append(deleted, id); return nil }
			options.OnAllocated = func(controlv1.Service) error {
				t.Error("substituted publication facts reached the application")
				return nil
			}
			if err := Run(t.Context(), options); err == nil || !reflect.DeepEqual(deleted, []string{saved.Id}) {
				t.Fatal("substituted saved facts were published or lost exact cleanup", err, deleted)
			}
		})
	}
}

func TestAllocationRequestKeepsHTTPBudgetAndTargetTLSSeparate(t *testing.T) {
	for _, target := range []string{"http://127.0.0.1:3000", "https://app.example.test:8443"} {
		t.Run(target, func(t *testing.T) {
			options := Options{InvocationID: "ivk_0123456789ABCDEFGHIJKL", Target: target, RequirePostQuantum: true,
				Limits: applicationlimits.Limits{Requests: 7, Concurrency: 2, RateRequests: 3, RatePer: 4 * time.Second, RateBurst: 5}}
			allocation, _, _, err := allocationRequest(options)
			if err != nil {
				t.Fatal(err)
			}
			declaration := allocation.Configuration
			if allocation.InvocationId != options.InvocationID || declaration.Protocol == nil || *declaration.Protocol != controlv1.ServiceProtocolHTTP ||
				declaration.Ephemeral == nil || !*declaration.Ephemeral || declaration.Public == nil || !*declaration.Public ||
				declaration.RequirePostQuantum == nil || !*declaration.RequirePostQuantum || declaration.Traffic != nil {
				t.Fatal("allocation introduced another publication model or traffic budget", declaration)
			}
			if declaration.Http.Limits == nil || *declaration.Http.Limits.Total != 7 || *declaration.Http.Limits.Concurrency != 2 ||
				declaration.Http.Limits.Rate.Count != 3 || declaration.Http.Limits.Rate.Per != "4s" || *declaration.Http.Limits.Rate.Burst != 5 {
				t.Fatal("allocation lost a supported HTTP budget", declaration.Http.Limits)
			}
			if strings.HasPrefix(target, "https:") {
				if declaration.Target != "app.example.test:8443" || declaration.TargetTls == nil ||
					declaration.TargetTls.Hostname != "app.example.test" || declaration.TargetTls.Digest == "" || declaration.TargetTls.CaPem != nil {
					t.Fatal("HTTPS target lost independent system trust", declaration)
				}
			} else if declaration.Target != "127.0.0.1:3000" || declaration.TargetTls != nil {
				t.Fatal("plaintext target acquired visitor TLS as target trust", declaration)
			}
		})
	}
}

func TestDeploymentPreparationLostReplyCleanupRetriesWithoutReselection(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		control := &allocationControl{}
		native := deploymentAllocationNative(t, control)
		options := allocationOptions(native)
		options.ExpiresAt = new(time.Now().Add(time.Minute))
		options.Limits = applicationlimits.Limits{Requests: 7}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		var saved controlv1.Service
		var declarations []string
		control.allocate = func(body controlv1.AllocateServiceRequest) (controlv1.Service, error) {
			encoded, _ := json.Marshal(body)
			declarations = append(declarations, string(encoded))
			if len(declarations) == 1 {
				saved = allocatedService(body)
				cancel()
				return controlv1.Service{}, io.ErrUnexpectedEOF
			}
			return saved, nil
		}
		control.read = func() (controlv1.Service, error) {
			t.Error("cleanup reselected publication")
			return controlv1.Service{}, errors.New("publication selection is unavailable")
		}
		var deleted []string
		independent := errors.New("delete unavailable")
		control.remove = func(id string) error {
			deleted = append(deleted, id)
			if len(deleted) == 1 {
				return errors.Join(context.Canceled, independent)
			}
			return nil
		}
		prepared, operationErr := Prepare(ctx, options)
		if prepared == nil || !errors.Is(operationErr, io.ErrUnexpectedEOF) || !errors.Is(operationErr, context.Canceled) {
			t.Fatal("uncertain preparation lost its original owner or failure", operationErr)
		}
		*options.ExpiresAt = options.ExpiresAt.Add(time.Hour)
		options.Limits.Requests = 99
		cleanup, stop := context.WithTimeout(t.Context(), time.Second)
		defer stop()
		cleanupErr := prepared.Cleanup(cleanup)
		combined := errors.Join(operationErr, cleanupErr)
		if !errors.Is(combined, independent) || !errors.Is(combined, io.ErrUnexpectedEOF) || len(declarations) != 2 {
			t.Fatal("cleanup hid an independent failure or replayed an observed allocation", combined, declarations)
		}
		for range 3 {
			if err := prepared.Cleanup(cleanup); err != nil {
				t.Fatal("cleanup did not retain its exact retry or terminal success", err)
			}
		}
		if len(declarations) != 2 || declarations[0] != declarations[1] || control.namespaceCalls != 0 || control.deploymentCalls != 2 ||
			!reflect.DeepEqual(deleted, []string{saved.Id, saved.Id}) || prepared.Config.Control != nil || prepared.Service.Id != "" {
			t.Fatal("cleanup changed authority, original declaration, or confirmed completion", declarations, deleted)
		}
	})
}

func TestDeploymentPreparationUsesSharedSavedFactValidation(t *testing.T) {
	for _, fact := range []string{"valid", "protocol", "endpoint", "target_trust", "post_quantum", "expiration", "http_limits"} {
		t.Run(fact, func(t *testing.T) {
			control := &allocationControl{}
			native := deploymentAllocationNative(t, control)
			options := allocationOptions(native)
			options.Target, options.RequirePostQuantum = "https://app.example.test:8443", true
			options.ExpiresAt = new(time.Now().Add(time.Minute))
			options.Limits.Requests = 7
			var saved controlv1.Service
			control.allocate = func(body controlv1.AllocateServiceRequest) (controlv1.Service, error) {
				saved = allocatedService(body)
				return saved, nil
			}
			control.read = func() (controlv1.Service, error) {
				selected := saved
				selected.Endpoint = new(*saved.Endpoint)
				switch fact {
				case "protocol":
					selected.Protocol = controlv1.Postgres
				case "endpoint":
					selected.Endpoint.Port = 8443
				case "target_trust":
					selected.TargetTls = nil
				case "post_quantum":
					selected.RequirePostQuantum = false
				case "expiration":
					selected.ExpiresAt = new(saved.ExpiresAt.Add(time.Hour))
				case "http_limits":
					selected.HttpLimits = &controlv1.ProjectHTTPApplicationLimits{Total: new(99)}
				}
				return selected, nil
			}
			var deleted []string
			control.remove = func(id string) error { deleted = append(deleted, id); return nil }
			prepared, err := Prepare(t.Context(), options)
			if prepared == nil || (err == nil) != (fact == "valid") {
				t.Fatal("deployment preparation bypassed shared saved-fact validation", fact, err)
			}
			if fact == "valid" && (prepared.Config.ServiceID != saved.Id || prepared.Config.PublisherIdentityID != native.PublisherIdentityID() ||
				prepared.Config.PublisherGrantID != native.PublisherGrantID() || prepared.Config.PublisherKeyID != native.PublisherKeyID()) {
				t.Fatal("preparation replaced its registered identity or exact service")
			}
			if err := prepared.Cleanup(t.Context()); err != nil || control.namespaceCalls != 0 || control.deploymentCalls != 1 ||
				!reflect.DeepEqual(deleted, []string{saved.Id}) {
				t.Fatal("validation lost cleanup ownership or used namespace allocation", err, deleted)
			}
		})
	}
}
