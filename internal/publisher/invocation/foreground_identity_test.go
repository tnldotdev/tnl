package invocation

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/applicationlimits"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	targetplan "github.com/tnldotdev/tnl/internal/publisher/target"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type publicationHTTPTransport func(*http.Request) (*http.Response, error)

func (f publicationHTTPTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func foregroundPlan() targetplan.TargetPlan {
	return targetplan.TargetPlan{Protocol: config.ProtocolHTTP, Target: "http://127.0.0.1:3000"}
}

func foregroundDigest(declaration controlv1.ProjectServiceConfiguration) string {
	encoded, _ := json.Marshal(declaration)
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func newForegroundFixture(t *testing.T) *serviceSetupFixture {
	t.Helper()
	f := newServiceSetupFixture(t, "app.member.example")
	f.before = func(r *http.Request) (*http.Response, bool) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/services/"+f.saved.Id+"/configuration" {
			response := serviceTestResponse(r, 200, f.declaration)
			response.Header.Set("ETag", `"`+foregroundDigest(f.declaration)+`"`)
			return response, true
		}
		if r.Method == http.MethodPut && r.URL.Path == "/v1/services/"+f.saved.Id {
			data, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			r.Body = io.NopCloser(bytes.NewReader(data))
			var body controlv1.UpdateServiceRequest
			if err := json.Unmarshal(data, &body); err != nil {
				t.Fatal(err)
			}
			if body.ExpectedConfigurationDigest == nil || *body.ExpectedConfigurationDigest != foregroundDigest(f.declaration) {
				t.Fatal("foreground update omitted the declaration compare-and-swap", body)
			}
			if body.PublisherPool != f.saved.PublisherPool {
				t.Fatal("foreground update changed publisher-pool intent")
			}
		}
		return nil, false
	}
	return f
}

func TestForegroundPublicationReusesItsServiceAndIdentityWithoutSessionRuns(t *testing.T) {
	f := newForegroundFixture(t)
	for range 2 {
		native, saved, plan, err := prepareForegroundService(t.Context(), f.services, PublicOptions{}, resolvedVisitorAccess{}, foregroundPlan())
		if err != nil {
			t.Fatal(err)
		}
		if saved.Id != f.saved.Id || plan.Target != foregroundPlan().Target || f.declaration.Target != "app" || saved.Source != nil {
			t.Fatal("foreground listener replaced saved service intent", saved, plan, f.declaration)
		}
		access, err := native.Access(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := native.PrepareServiceRun(t.Context(), saved.Id, "attempt", access, publisheridentity.ServiceDeclaration(saved)); !errors.Is(err, clientcontrol.ErrUnavailable) {
			t.Fatal("service run was not created with its exact signed grant", err)
		}
	}
	if f.creates != 1 || f.enrollments != 1 || f.redemptions != 1 || f.runs != 2 || f.updates != 0 {
		t.Fatal("restart changed saved service, key, or policy", f.creates, f.enrollments, f.redemptions, f.runs, f.updates)
	}
}

func TestForegroundRestartPreservesSavedPolicyTargetAndPublisherPool(t *testing.T) {
	f := newForegroundFixture(t)
	flags := PublicOptions{RequirePostQuantum: new(true), Limits: applicationlimits.Limits{Requests: 700, Concurrency: 50, RateRequests: 10, RatePer: time.Second, RateBurst: 20}}
	policy := resolvedVisitorAccess{explicit: true, access: controlv1.Anonymous, prefixes: []string{"192.0.2.0/24"}}
	if _, _, _, err := prepareForegroundService(t.Context(), f.services, flags, policy, foregroundPlan()); err != nil {
		t.Fatal(err)
	}
	f.declaration.Target = "saved.internal:8080"
	f.saved.PublisherPool = true
	before, _ := json.Marshal(f.declaration)
	plan := foregroundPlan()
	plan.Target = "http://127.0.0.1:4000"
	_, saved, actual, err := prepareForegroundService(t.Context(), f.services, PublicOptions{}, resolvedVisitorAccess{}, plan)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(f.declaration)
	if !bytes.Equal(before, after) || f.updates != 0 || !saved.RequirePostQuantum || !saved.PublisherPool || actual.Target != plan.Target {
		t.Fatal("restart reset saved declaration or selected the saved runtime target", string(before), string(after), saved, actual)
	}
}

func TestForegroundOverrideMergesOnlySelectedPolicyFields(t *testing.T) {
	f := newForegroundFixture(t)
	if _, _, _, err := prepareForegroundService(t.Context(), f.services, PublicOptions{}, resolvedVisitorAccess{}, foregroundPlan()); err != nil {
		t.Fatal(err)
	}
	f.declaration.Target = "saved.internal:8080"
	f.declaration.RequirePostQuantum = new(true)
	f.declaration.Http = &controlv1.ProjectServiceHTTP{
		Access: &controlv1.ProjectHTTPAccess{Mode: new(controlv1.Anonymous)},
		Limits: &controlv1.ProjectHTTPApplicationLimits{Total: new(900), Rate: &controlv1.ProjectApplicationRate{Count: 5, Per: "1s", Burst: new(12)}},
	}
	f.saved.PublisherPool = true
	f.applyDeclaration()
	flags := PublicOptions{RequirePostQuantum: new(false), Limits: applicationlimits.Limits{Concurrency: 7}}
	_, saved, _, err := prepareForegroundService(t.Context(), f.services, flags, resolvedVisitorAccess{}, foregroundPlan())
	if err != nil {
		t.Fatal(err)
	}
	actual := f.declaration
	if f.updates != 1 || saved.RequirePostQuantum || !saved.PublisherPool || actual.Target != "saved.internal:8080" ||
		*actual.Http.Access.Mode != controlv1.Anonymous || *actual.Http.Limits.Total != 900 || *actual.Http.Limits.Concurrency != 7 ||
		actual.Http.Limits.Rate.Count != 5 || *actual.Http.Limits.Rate.Burst != 12 {
		t.Fatal("foreground override replaced unrelated saved policy", actual, saved, f.updates)
	}
}

func TestForegroundOverrideRereadsPolicyAfterConflictOrLostReply(t *testing.T) {
	for _, conflict := range []bool{true, false} {
		t.Run(map[bool]string{true: "conflict", false: "lost reply"}[conflict], func(t *testing.T) {
			f := newForegroundFixture(t)
			if _, _, _, err := prepareForegroundService(t.Context(), f.services, PublicOptions{}, resolvedVisitorAccess{}, foregroundPlan()); err != nil {
				t.Fatal(err)
			}
			previous := f.before
			attempts := 0
			f.before = func(r *http.Request) (*http.Response, bool) {
				if response, handled := previous(r); handled {
					return response, true
				}
				if r.Method == http.MethodPut {
					attempts++
					if attempts == 1 && conflict {
						f.declaration.Target = "concurrent.internal:8080"
						f.declaration.Http = &controlv1.ProjectServiceHTTP{Limits: &controlv1.ProjectHTTPApplicationLimits{Total: new(800)}}
						return serviceTestResponse(r, 409, map[string]any{"status": 409, "code": "conflict"}), true
					}
				}
				return nil, false
			}
			if !conflict {
				f.afterUpdate = func() error {
					f.afterUpdate = nil
					f.declaration.Target = "concurrent.internal:8080"
					f.declaration.Http.Limits.Total = new(800)
					return io.ErrUnexpectedEOF
				}
			}
			_, saved, _, err := prepareForegroundService(t.Context(), f.services, PublicOptions{Limits: applicationlimits.Limits{Concurrency: 7}}, resolvedVisitorAccess{}, foregroundPlan())
			if err != nil || saved.Id != f.saved.Id || f.creates != 1 || f.declaration.Target != "concurrent.internal:8080" ||
				*f.declaration.Http.Limits.Total != 800 || *f.declaration.Http.Limits.Concurrency != 7 {
				t.Fatal("retry overwrote current declaration or selected another service", err, f.declaration, saved)
			}
		})
	}
}

func TestForegroundRestartRetainsSavedTargetTrustAndRejectsPlaintext(t *testing.T) {
	f := newForegroundFixture(t)
	declaration, err := targettrust.NewDeclaration("target.example", nil)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := declaration.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	plan := foregroundPlan()
	plan.Target, plan.Trust = "https://127.0.0.1:3000", trust
	if _, _, _, err := prepareForegroundService(t.Context(), f.services, PublicOptions{}, resolvedVisitorAccess{}, plan); err != nil {
		t.Fatal(err)
	}
	_, saved, actual, err := prepareForegroundService(t.Context(), f.services, PublicOptions{Target: "4000"}, resolvedVisitorAccess{}, foregroundPlan())
	if err != nil || !reflect.DeepEqual(actual.Trust, trust) || actual.Target != "https://127.0.0.1:3000" || saved.TargetTls.Hostname != "target.example" {
		t.Fatal("restart replaced saved target trust", actual, saved, err)
	}
	if _, _, _, err := prepareForegroundService(t.Context(), f.services, PublicOptions{Target: "http://127.0.0.1:4000"}, resolvedVisitorAccess{}, foregroundPlan()); err == nil {
		t.Fatal("saved target TLS silently became plaintext")
	}
}

func TestForegroundServiceDeclarationDoesNotMutateItsSavedInput(t *testing.T) {
	current := controlv1.ProjectServiceConfiguration{Target: "saved.internal:8080",
		Http: &controlv1.ProjectServiceHTTP{Limits: &controlv1.ProjectHTTPApplicationLimits{Concurrency: new(9)}}}
	before, _ := json.Marshal(current)
	selected, err := foregroundServiceDeclaration(PublicOptions{Limits: applicationlimits.Limits{Concurrency: 7}}, resolvedVisitorAccess{}, foregroundPlan(), &current)
	after, _ := json.Marshal(current)
	if err != nil || !bytes.Equal(before, after) || *selected.Http.Limits.Concurrency != 7 || selected.Target != current.Target {
		t.Fatal("foreground merge changed its source snapshot", current, selected, err)
	}
}

func TestForegroundExplicitAccessWireShape(t *testing.T) {
	for _, mode := range []controlv1.VisitorAccessMode{controlv1.Anonymous, controlv1.Restricted} {
		for _, test := range []struct {
			name     string
			prefixes []string
		}{
			{"omitted IP filter", nil},
			{"empty IP selection", []string{}},
			{"nonempty IP filter", []string{"192.0.2.1", "198.51.100.0/24"}},
		} {
			for _, retained := range []bool{false, true} {
				t.Run(string(mode)+"/"+test.name+map[bool]string{false: "/new", true: "/retained"}[retained], func(t *testing.T) {
					var current *controlv1.ProjectServiceConfiguration
					if retained {
						current = &controlv1.ProjectServiceConfiguration{Target: "saved.internal:8080",
							Http: &controlv1.ProjectServiceHTTP{
								Access: &controlv1.ProjectHTTPAccess{Mode: new(controlv1.Restricted), Ip: new([]string{"203.0.113.0/24"})},
								Limits: &controlv1.ProjectHTTPApplicationLimits{Total: new(900)},
							}}
					}
					before, err := json.Marshal(current)
					if err != nil {
						t.Fatal(err)
					}
					policy := resolvedVisitorAccess{explicit: true, access: mode, prefixes: test.prefixes}
					selected, err := foregroundServiceDeclaration(PublicOptions{Limits: applicationlimits.Limits{Concurrency: 7}}, policy, foregroundPlan(), current)
					if err != nil {
						t.Fatal(err)
					}
					encoded, err := json.Marshal(selected.Http)
					if err != nil {
						t.Fatal(err)
					}
					// this is the same validated http declaration decoded by
					// control, including its rejection of an explicit empty list.
					var accepted config.HTTPService
					if err := json.Unmarshal(encoded, &accepted); err != nil {
						t.Fatalf("control cannot decode the explicit access declaration: %s: %v", encoded, err)
					}
					wantPrefixes := test.prefixes
					if len(wantPrefixes) == 0 {
						wantPrefixes = nil
					}
					if accepted.Access == nil || accepted.Access.Mode != string(mode) || accepted.Access.Validate() != nil ||
						!reflect.DeepEqual(accepted.Access.IP, wantPrefixes) {
						t.Fatalf("explicit replacement retained or changed an IP filter: %s", encoded)
					}
					var wire struct {
						Access map[string]json.RawMessage `json:"access"`
					}
					if err := json.Unmarshal(encoded, &wire); err != nil {
						t.Fatal(err)
					}
					_, hasIP := wire.Access["ip"]
					if hasIP != (len(test.prefixes) != 0) || selected.Http.Limits == nil ||
						selected.Http.Limits.Concurrency == nil || *selected.Http.Limits.Concurrency != 7 ||
						retained && (selected.Http.Limits.Total == nil || *selected.Http.Limits.Total != 900 || selected.Target != current.Target) {
						t.Fatalf("access wire shape or unrelated settings changed: %s", encoded)
					}
					after, err := json.Marshal(current)
					if err != nil || !bytes.Equal(before, after) {
						t.Fatal("explicit access mutated its saved declaration", err)
					}
					if len(test.prefixes) != 0 {
						(*selected.Http.Access.Ip)[0] = "changed"
						if test.prefixes[0] != "192.0.2.1" {
							t.Fatal("access declaration retained the caller's IP slice")
						}
					}
				})
			}
		}
	}
}

func TestForegroundServiceRejectsOtherOwnershipAndWorktree(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*controlv1.Service)
	}{
		{"team", func(s *controlv1.Service) { s.TeamId = "another-team" }},
		{"domain", func(s *controlv1.Service) { s.DomainId = new("another-domain") }},
		{"worktree", func(s *controlv1.Service) {
			s.Placement = &controlv1.ServicePlacement{WorktreeKey: new("another-worktree")}
		}},
		{"project", func(s *controlv1.Service) { s.Source = &controlv1.LocalServiceSource{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newForegroundFixture(t)
			if _, _, _, err := prepareForegroundService(t.Context(), f.services, PublicOptions{}, resolvedVisitorAccess{}, foregroundPlan()); err != nil {
				t.Fatal(err)
			}
			tc.mutate(&f.saved)
			_, _, _, err := prepareForegroundService(t.Context(), f.services, PublicOptions{}, resolvedVisitorAccess{}, foregroundPlan())
			if err == nil || f.creates != 1 || f.updates != 0 || f.enrollments != 1 {
				t.Fatal("foreground publication adopted another owner's service", err, f.creates, f.updates, f.enrollments)
			}
		})
	}
}

func TestForegroundTemporarySelectionUsesTheRealMemberNamespace(t *testing.T) {
	f := newServiceSetupFixture(t, "unused.member.example")
	f.services.membershipID = serviceTestID(t, opaqueid.MembershipPrefix)
	f.services.namespace = "member.example"
	f.identity.Kind, f.identity.ServiceId = authorityv1.Namespace, nil
	f.identity.DomainId, f.identity.Namespace = &f.services.domainID, &f.services.namespace
	f.before = func(r *http.Request) (*http.Response, bool) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/publisher-enrollments" {
			return nil, false
		}
		var body controlv1.CreatePublisherEnrollmentRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.TeamId != f.services.teamID || body.DomainId == nil || *body.DomainId != f.services.domainID ||
			body.ServiceId != nil || r.Header.Get("Authorization") != "Bearer session" {
			t.Fatal("temporary publisher selected a synthetic team, domain, or service", body)
		}
		f.enrollments++
		return serviceTestResponse(r, 201, controlv1.PublisherEnrollment{
			Id: f.enrollment, EnrollmentKey: f.enrollment + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
			ExpiresAt: time.Now().Add(time.Minute), TeamId: f.services.teamID,
			Kind: controlv1.PublisherEnrollmentKindNamespace, DomainId: &f.services.domainID, Namespace: &f.services.namespace,
		}), true
	}
	for range 2 {
		native, _, err := publisheridentity.EnsureNamespace(t.Context(), f.services.state, f.services.authenticated.Control, f.services.authenticated.Authority, f.services.teamID, f.services.domainID, f.services.namespace)
		if err != nil || native == nil {
			t.Fatal("real namespace selection failed", err)
		}
		if err := native.NamespaceScope(); err != nil {
			t.Fatal(err)
		}
		if native.Allocations == nil {
			t.Fatal("namespace owner omitted explicit service allocation capability")
		}
	}
	if f.enrollments != 1 || f.redemptions != 1 || f.creates != 0 || f.updates != 0 {
		t.Fatal("namespace selection replaced its key or reserved a service", f.enrollments, f.redemptions, f.creates, f.updates)
	}
}
