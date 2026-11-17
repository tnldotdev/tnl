package invocation

import (
	"errors"
	"io"
	"net/http"
	"reflect"
	"testing"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/applicationlimits"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type namespaceAuthorityFixture struct {
	*serviceSetupFixture
	inventories int
}

func newNamespaceAuthorityFixture(t *testing.T) *namespaceAuthorityFixture {
	t.Helper()
	f := &namespaceAuthorityFixture{serviceSetupFixture: newForegroundFixture(t)}
	f.services.membershipID = serviceTestID(t, opaqueid.MembershipPrefix)
	f.services.namespace = "member.example"
	previous := f.before
	f.before = func(r *http.Request) (*http.Response, bool) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/services" {
			f.inventories++
			return serviceTestResponse(r, http.StatusForbidden, controlv1.Problem{Status: 403, Code: controlv1.Forbidden}), true
		}
		return previous(r)
	}
	return f
}

func assertNamespaceAuthorityRun(t *testing.T, native *publisheridentity.Native, saved controlv1.Service) {
	t.Helper()
	if native == nil {
		t.Fatal("reservation did not enroll an exact publisher")
	}
	access, err := native.Access(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	// the shared transport verifies the generated key's signed assertion,
	// exact grant, and publisher bearer rather than accepting a control session.
	if _, err := native.PrepareServiceRun(t.Context(), saved.Id, "namespace-attempt", access, publisheridentity.ServiceDeclaration(saved)); !errors.Is(err, clientcontrol.ErrUnavailable) {
		t.Fatal("member publication did not reach run preparation with its real exact grant", err)
	}
}

func TestForegroundMemberPreparationDoesNotRequireTeamInventory(t *testing.T) {
	f := newNamespaceAuthorityFixture(t)
	for attempt := range 2 {
		native, saved, plan, err := prepareForegroundService(t.Context(), f.services, PublicOptions{}, resolvedVisitorAccess{}, foregroundPlan())
		if err != nil {
			t.Fatal("own-namespace preparation required team administration", err)
		}
		if saved.Id != f.saved.Id || plan.Target != foregroundPlan().Target || saved.Source != nil {
			t.Fatal("own-namespace preparation changed service identity or runtime target", saved, plan)
		}
		assertNamespaceAuthorityRun(t, native, saved)
		if attempt == 0 {
			f.declaration.Target = "saved.internal:8080"
			f.declaration.Http = &controlv1.ProjectServiceHTTP{Limits: &controlv1.ProjectHTTPApplicationLimits{Total: new(700)}}
			f.saved.PublisherPool = true
			f.applyDeclaration()
		}
	}
	if f.inventories != 0 || f.creates != 1 || f.enrollments != 1 || f.redemptions != 1 || f.runs != 2 ||
		f.updates != 0 || f.declaration.Target != "saved.internal:8080" || !f.saved.PublisherPool ||
		f.declaration.Http == nil || f.declaration.Http.Limits == nil ||
		f.declaration.Http.Limits.Total == nil || *f.declaration.Http.Limits.Total != 700 {
		t.Fatal("member restart used inventory or replaced saved intent, service, or publisher",
			f.inventories, f.creates, f.enrollments, f.redemptions, f.runs, f.updates)
	}
}

func TestForegroundMemberReservationRecoversUncertainCreationWithoutInventory(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(map[bool]string{false: "before commit", true: "committed reply lost"}[committed], func(t *testing.T) {
			f := newNamespaceAuthorityFixture(t)
			previous := f.before
			var keys []string
			f.before = func(r *http.Request) (*http.Response, bool) {
				if r.Method == http.MethodPost && r.URL.Path == "/v1/services" {
					keys = append(keys, r.Header.Get("Idempotency-Key"))
					if !committed && len(keys) == 1 {
						return serviceTestResponse(r, 503, controlv1.Problem{Status: 503, Code: controlv1.Unavailable}), true
					}
				}
				return previous(r)
			}
			if committed {
				f.afterCreate = func() error {
					f.afterCreate = nil
					return io.ErrUnexpectedEOF
				}
			}
			native, saved, _, err := prepareForegroundService(t.Context(), f.services, PublicOptions{}, resolvedVisitorAccess{}, foregroundPlan())
			if err != nil {
				t.Fatal("uncertain own-namespace reservation required team inventory", err)
			}
			if saved.Id != f.saved.Id || f.creates != 1 || f.inventories != 0 || len(keys) != 2 || keys[0] != keys[1] {
				t.Fatal("uncertain reservation changed its operation key or allocated another service", saved, f.creates, f.inventories, keys)
			}
			assertNamespaceAuthorityRun(t, native, saved)
			if f.enrollments != 1 || f.redemptions != 1 || f.runs != 1 {
				t.Fatal("reservation recovery replaced the exact publisher", f.enrollments, f.redemptions, f.runs)
			}
		})
	}
}

func TestForegroundMemberOverrideUsesExactConfigurationCASWithoutInventory(t *testing.T) {
	f := newNamespaceAuthorityFixture(t)
	if _, _, _, err := prepareForegroundService(t.Context(), f.services, PublicOptions{}, resolvedVisitorAccess{}, foregroundPlan()); err != nil {
		t.Fatal(err)
	}
	f.declaration.Target = "saved.internal:8080"
	f.declaration.RequirePostQuantum = new(true)
	f.declaration.Http = &controlv1.ProjectServiceHTTP{
		Access: &controlv1.ProjectHTTPAccess{Mode: new(controlv1.Restricted)},
		Limits: &controlv1.ProjectHTTPApplicationLimits{Total: new(900)},
	}
	f.saved.PublisherPool = true
	f.applyDeclaration()
	flags := PublicOptions{Limits: applicationlimits.Limits{Concurrency: 7}}
	policy := resolvedVisitorAccess{explicit: true, access: controlv1.Anonymous, prefixes: []string{"192.0.2.0/24"}}
	native, saved, _, err := prepareForegroundService(t.Context(), f.services, flags, policy, foregroundPlan())
	if err != nil {
		t.Fatal("member override required team inventory", err)
	}
	if saved.Id != f.saved.Id || f.inventories != 0 || f.creates != 1 || f.updates != 1 || f.changes != 1 ||
		!saved.PublisherPool || !saved.RequirePostQuantum || f.declaration.Target != "saved.internal:8080" ||
		f.declaration.Http == nil || f.declaration.Http.Access == nil || f.declaration.Http.Access.Mode == nil ||
		*f.declaration.Http.Access.Mode != controlv1.Anonymous || f.declaration.Http.Access.Ip == nil ||
		!reflect.DeepEqual(*f.declaration.Http.Access.Ip, policy.prefixes) ||
		f.declaration.Http.Limits == nil || f.declaration.Http.Limits.Total == nil || *f.declaration.Http.Limits.Total != 900 ||
		f.declaration.Http.Limits.Concurrency == nil || *f.declaration.Http.Limits.Concurrency != 7 {
		t.Fatal("member override replaced unselected saved intent or skipped exact CAS", saved, f.declaration, f.updates, f.changes)
	}
	assertNamespaceAuthorityRun(t, native, saved)
}
