package identity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

var _ ServiceControl = (*Native)(nil)

func (s nativeScope) enrollment() authorityv1.PublisherEnrollmentResult {
	i := authorityv1.PublisherEnrollmentResult{ClientId: s.clientID, KeyId: s.keyID, GrantId: s.grantID, TeamId: s.teamID, Kind: authorityv1.PublisherEnrollmentResultKind(s.kind)}
	switch s.kind {
	case "service":
		i.ServiceId = &s.serviceID
	case "namespace":
		i.DomainId, i.Namespace = &s.domainID, &s.namespace
	}
	return i
}

type endpointControl struct {
	ServiceControl
	server string
}

func (c endpointControl) ControlURL() string { return c.server }

func TestNativeRequiresEndpointIdentityAndSelectedCapabilities(t *testing.T) {
	fixture, _ := privateScopeFixture(t)
	service := fixture.identity.enrollment()
	for _, server := range []string{"", "https://control.example/path", "https://CONTROL.example/"} {
		if _, err := NewNative(NativeControl{Services: endpointControl{server: server}}, &lostEnrollmentResponse{}, service, fixture.private); !errors.Is(err, ErrScope) {
			t.Fatalf("invalid endpoint identity %q accepted: %v", server, err)
		}
	}
	if _, err := NewNative(NativeControl{}, &lostEnrollmentResponse{}, service, fixture.private); !errors.Is(err, ErrScope) {
		t.Fatal("service grant accepted without service capabilities", err)
	}
	control := NativeControl{Services: &unusedControl{}}
	if _, err := NewNative(control, &lostEnrollmentResponse{}, service, fixture.private); err != nil {
		t.Fatal("service grant required an unrelated control capability", err)
	}
	if _, err := NewNative(control, &lostEnrollmentResponse{}, service, make(ed25519.PrivateKey, ed25519.PrivateKeySize)); !errors.Is(err, ErrScope) {
		t.Fatal("endpoint validation weakened signing-key validation", err)
	}
}

func TestNativeRejectsRetiredAndUnsupportedEnrollmentGrants(t *testing.T) {
	fixture, _ := privateScopeFixture(t)
	for _, kind := range []authorityv1.PublisherEnrollmentResultKind{"saved_public_url", "deployment_credential", "unknown"} {
		t.Run(string(kind), func(t *testing.T) {
			enrollment := fixture.identity.enrollment()
			enrollment.Kind, enrollment.ServiceId = kind, nil
			authority := &scopedAuthority{}
			if _, err := NewNative(fixture.NativeControl, authority, enrollment, fixture.private); !errors.Is(err, ErrScope) || authority.accesses != 0 {
				t.Fatal("unsupported wire grant became a native serving capability", err)
			}
		})
	}
}

type snapshotServiceControl struct {
	ServiceControl
	wire  []byte
	reads int
}

func (*snapshotServiceControl) ControlURL() string { return "https://control.example" }

func (c *snapshotServiceControl) GetPublisherService(_ context.Context, service, access string) (controlv1.Service, error) {
	var saved controlv1.Service
	if err := json.Unmarshal(c.wire, &saved); err != nil {
		return saved, err
	}
	if saved.Id != service || access != "access" {
		return controlv1.Service{}, ErrScope
	}
	c.reads++
	return saved, nil
}

func TestNativeScopeAndServiceReadSnapshots(t *testing.T) {
	fixture, scope := privateScopeFixture(t)
	identity := fixture.identity.enrollment()
	trust, err := targettrust.NewCache(nil).Capture(t.Context(), t.TempDir(), "target.internal:3000", config.TrustSource{CA: "system"})
	if err != nil {
		t.Fatal(err)
	}
	saved := scope.service
	saved.Protocol, saved.TargetTls = controlv1.ServiceProtocolHTTP, ServiceTargetTLS(&trust)
	saved.DomainId = new("domain")
	saved.Endpoint = &controlv1.ServiceEndpoint{Hostname: "app.example", Port: 443, Public: true}
	saved.Placement = &controlv1.ServicePlacement{WorktreeKey: new("worktree")}
	saved.Source = &controlv1.LocalServiceSource{ProjectKey: "project", SourceFingerprint: "source", WorktreeKey: "worktree", Service: "app"}
	saved.HttpLimits = &controlv1.ProjectHTTPApplicationLimits{Total: new(7), Concurrency: new(3), Rate: &controlv1.ProjectApplicationRate{Count: 2, Per: "1s", Burst: new(4)}}
	saved.ServiceRunId, saved.RunNumber = new("run"), new(int64(1))
	saved.ExpiresAt, saved.PublisherPool = new(time.Now().UTC().Add(time.Hour)), true
	wire, err := json.Marshal(saved)
	if err != nil {
		t.Fatal(err)
	}
	var expected controlv1.Service
	if err := json.Unmarshal(wire, &expected); err != nil {
		t.Fatal(err)
	}
	control := &snapshotServiceControl{wire: wire}
	private := bytes.Clone(fixture.private)
	n, err := NewNative(NativeControl{Services: control}, &lostEnrollmentResponse{}, identity, private)
	if err != nil {
		t.Fatal(err)
	}
	clear(private)
	result, err := n.SavedService(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	// each service read comes from the current wire response, not a cached
	// serving-resource record. caller-owned DTOs and keys remain independent.
	*identity.ServiceId = "changed-enrollment"
	*result.DomainId, result.Endpoint.Hostname, result.Placement.WorktreeKey = "changed-domain", "changed.example", new("changed-worktree")
	result.Source.ProjectKey, result.TargetTls.Hostname, result.TargetTls.Digest = "changed-project", "changed-target", "changed-digest"
	*result.HttpLimits.Total, *result.HttpLimits.Concurrency, *result.HttpLimits.Rate.Burst = 1, 1, 1
	result.HttpLimits.Rate.Count, result.HttpLimits.Rate.Per = 1, "1m"
	*result.ServiceRunId, *result.RunNumber, *result.ExpiresAt = "changed-run", 2, time.Time{}
	result.PublisherPool = false
	got, err := n.SavedService(t.Context())
	if err != nil || !reflect.DeepEqual(got, expected) || !bytes.Equal(n.private, fixture.private) || control.reads != 2 {
		t.Fatal("caller mutation changed native scope, signing key, or later service reads", err)
	}
	*got.DomainId = "changed-read"
	again, err := n.GetPublisherService(t.Context(), expected.Id, "access")
	if err != nil || !reflect.DeepEqual(again, expected) || control.reads != 3 {
		t.Fatal("service reads reused a mutated caller snapshot", err)
	}
	if selected, _, err := n.ForService(t.Context(), expected.Id); err != nil || selected.PublisherGrantID() != n.PublisherGrantID() {
		t.Fatal("enrollment pointer mutation changed exact service authority", err)
	}
}

func TestNativeForkOwnsIndependentScopeAndKey(t *testing.T) {
	fixture, control := privateScopeFixture(t)
	i := fixture.identity.enrollment()
	domain, _ := opaqueid.New(opaqueid.DomainPrefix)
	namespace := "member.example"
	i.Kind, i.ServiceId, i.DomainId, i.Namespace = authorityv1.Namespace, nil, &domain, &namespace
	n, err := NewNative(NativeControl{Services: control}, &lostEnrollmentResponse{}, i, fixture.private)
	if err != nil {
		t.Fatal(err)
	}
	selected, _, err := n.ForService(t.Context(), control.service.Id)
	if err != nil {
		t.Fatal(err)
	}
	fork, err := n.Fork()
	if err != nil {
		t.Fatal(err)
	}
	domain, namespace = "changed-domain", "changed.example"
	if n.identity.domainID == domain || n.identity.namespace == namespace {
		t.Fatal("caller mutation changed the original namespace authority")
	}
	sibling, _ := opaqueid.New(opaqueid.ServicePrefix)
	control.service.Id = sibling
	if _, _, err := fork.ForService(t.Context(), sibling); err != nil {
		t.Fatal("independent namespace worker could not select its allocated service", err)
	}
	if _, _, err := selected.ForService(t.Context(), sibling); !errors.Is(err, ErrScope) {
		t.Fatal("fork changed the original worker's selected service", err)
	}
	if err := n.NamespaceScope(); err != nil {
		t.Fatal("selection changed original namespace authority", err)
	}
	clear(fork.private)
	if !bytes.Equal(n.private, fixture.private) || !bytes.Equal(selected.private, fixture.private) {
		t.Fatal("independent workers share signing-key storage")
	}
}

func TestNativeGuestScopeKeepsExactTrialServiceAndFixedExpiry(t *testing.T) {
	fixture, current := privateScopeFixture(t)
	enrollment := fixture.identity.enrollment()
	guest, err := opaqueid.New(opaqueid.GuestPrefix)
	if err != nil {
		t.Fatal(err)
	}
	until := time.Now().UTC().Add(time.Hour)
	enrollment.TeamId, enrollment.GuestId, enrollment.ExpiresAt = "", guest, &until
	saved := current.service
	saved.TeamId, saved.GuestId, saved.Ephemeral, saved.ExpiresAt = "", guest, true, new(until)
	saved.Protocol, saved.Endpoint = controlv1.ServiceProtocolHTTP, &controlv1.ServiceEndpoint{Hostname: "demo.example", Public: true, Port: 443}
	wire, err := json.Marshal(saved)
	if err != nil {
		t.Fatal(err)
	}
	control := &snapshotServiceControl{wire: wire}
	native, err := NewNative(NativeControl{Services: control}, &lostEnrollmentResponse{}, enrollment, fixture.private)
	if err != nil {
		t.Fatal("guest exact-service enrollment required a fake team", err)
	}
	if _, err := native.SavedService(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := native.NamespaceScope(); !errors.Is(err, ErrScope) {
		t.Fatal("guest acquired namespace authority", err)
	}
	if _, _, err := native.ForService(t.Context(), "svc_2222222222222222222222"); !errors.Is(err, ErrScope) {
		t.Fatal("guest selected another service", err)
	}
	original := native.identity.expiresAt
	*enrollment.ExpiresAt = until.Add(72 * time.Hour)
	enrollment.GuestId = "changed-guest"
	if native.identity.guestID != guest || native.identity.expiresAt != original {
		t.Fatal("caller mutation extended or replaced the captured trial")
	}
	for _, change := range []string{"guest", "team", "expiry", "persistence"} {
		t.Run(change, func(t *testing.T) {
			other := saved
			switch change {
			case "guest":
				other.GuestId = "gst_2222222222222222222222"
			case "team":
				other.TeamId = fixture.identity.teamID
			case "expiry":
				other.ExpiresAt = new(original.Add(time.Second))
			case "persistence":
				other.Ephemeral = false
			}
			control.wire, err = json.Marshal(other)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := native.GetPublisherService(t.Context(), saved.Id, "access"); !errors.Is(err, ErrScope) {
				t.Fatal("changed service escaped the trial binding", err)
			}
		})
	}
	native.identity.expiresAt = time.Now().Add(-time.Second)
	if _, err := native.Access(t.Context()); !errors.Is(err, ErrScope) {
		t.Fatal("expired trial attempted assertion exchange", err)
	}
}

func TestNativeGuestEnrollmentRejectsAmbiguousOrUnboundedOwnership(t *testing.T) {
	fixture, _ := privateScopeFixture(t)
	for _, change := range []string{"neither", "both", "invalid guest", "namespace", "missing expiry", "elapsed expiry"} {
		t.Run(change, func(t *testing.T) {
			enrollment := fixture.identity.enrollment()
			enrollment.TeamId, enrollment.GuestId, enrollment.ExpiresAt = "", "gst_1111111111111111111111", new(time.Now().Add(time.Hour))
			switch change {
			case "neither":
				enrollment.GuestId = ""
			case "both":
				enrollment.TeamId = fixture.identity.teamID
			case "invalid guest":
				enrollment.GuestId = "guest"
			case "namespace":
				enrollment.Kind = authorityv1.Namespace
			case "missing expiry":
				enrollment.ExpiresAt = nil
			case "elapsed expiry":
				enrollment.ExpiresAt = new(time.Now().Add(-time.Second))
			}
			if _, err := newNativeScope(enrollment); !errors.Is(err, ErrScope) {
				t.Fatal("invalid guest enrollment was accepted", err)
			}
		})
	}
}
