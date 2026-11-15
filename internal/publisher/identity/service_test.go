package identity

import (
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"testing"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type privateScopeControl struct {
	ServiceOwnerControl
	service      controlv1.Service
	declarations []controlv1.ServiceRunDeclaration
	reads        int
}

func (*privateScopeControl) ControlURL() string { return "https://control.example" }

type privateOwnerControl struct {
	*privateScopeControl
	enrollment controlv1.PublisherEnrollment
	created    int
}

func (c *privateOwnerControl) CreatePublisherEnrollment(_ context.Context, request controlv1.CreatePublisherEnrollmentRequest) (controlv1.PublisherEnrollment, error) {
	if request.ServiceId == nil || *request.ServiceId != c.service.Id || request.DomainId != nil {
		return controlv1.PublisherEnrollment{}, ErrScope
	}
	c.created++
	return c.enrollment, nil
}

func TestPrivateOwnerEnrollmentRecoversResponseLossWithoutAnotherGrant(t *testing.T) {
	fixture, scope := privateScopeFixture(t)
	id, err := opaqueid.New(opaqueid.PublisherEnrollmentPrefix)
	if err != nil {
		t.Fatal(err)
	}
	control := &privateOwnerControl{privateScopeControl: scope, enrollment: controlv1.PublisherEnrollment{Id: id, TeamId: scope.service.TeamId, Kind: "service", ServiceId: &scope.service.Id, EnrollmentKey: id + ".one-use"}}
	authority := &lostEnrollmentResponse{result: fixture.identity.enrollment()}
	database, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	profile, err := database.Server(t.Context(), "https://control.example")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := EnsureServiceOwner(t.Context(), profile, control, authority, scope.service); err == nil {
		t.Fatal("lost redemption response was accepted")
	}
	for range 2 {
		native, identity, err := EnsureServiceOwner(t.Context(), profile, control, authority, scope.service)
		if err != nil || native == nil || identity.ClientId != fixture.identity.clientID || control.created != 1 || authority.calls != 2 {
			t.Fatalf("private owner recovery: identity=%+v created=%d redeemed=%d err=%v", identity, control.created, authority.calls, err)
		}
		if _, err := native.SavedService(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
}

func (c *privateScopeControl) GetPublisherService(_ context.Context, serviceID, access string) (controlv1.Service, error) {
	if access != "access" || serviceID == "" {
		return controlv1.Service{}, ErrScope
	}
	c.reads++
	return c.service, nil
}

func (c *privateScopeControl) PrepareServiceRun(_ context.Context, serviceID, key, access string, declaration controlv1.ServiceRunDeclaration) (controlv1.ServiceRunPreparation, error) {
	if serviceID != c.service.Id || access != "access" || key == "" {
		return controlv1.ServiceRunPreparation{}, ErrScope
	}
	c.declarations = append(c.declarations, declaration)
	return controlv1.ServiceRunPreparation{ServiceId: serviceID}, nil
}

func privateScopeFixture(t *testing.T) (*Native, *privateScopeControl) {
	t.Helper()
	id := func(prefix string) string {
		value, err := opaqueid.New(prefix)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	serviceID := id(opaqueid.ServicePrefix)
	identity := authorityv1.PublisherEnrollmentResult{ClientId: id(opaqueid.PublisherIdentityPrefix), GrantId: id(opaqueid.PublisherGrantPrefix), KeyId: id(opaqueid.PublisherIdentityKeyPrefix), TeamId: "team", Kind: authorityv1.Service, ServiceId: &serviceID}
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	control := &privateScopeControl{service: controlv1.Service{Id: serviceID, TeamId: "team", Name: "orders", Enabled: true, Protocol: controlv1.Postgres, TrustRevision: 3}}
	native, err := NewNative(NativeControl{Services: control}, &lostEnrollmentResponse{}, identity, key)
	if err != nil {
		t.Fatal(err)
	}
	return native, control
}

func TestNativeExactServiceGrantCannotSelectAnotherServiceOrNamespace(t *testing.T) {
	native, control := privateScopeFixture(t)
	grantID, err := opaqueid.New(opaqueid.PublisherGrantPrefix)
	if err != nil {
		t.Fatal(err)
	}
	other, err := opaqueid.New(opaqueid.ServicePrefix)
	if err != nil {
		t.Fatal(err)
	}
	enrollment := native.identity.enrollment()
	enrollment.GrantId, enrollment.ServiceId = grantID, &other
	selected, err := NewNative(native.NativeControl, native.authority, enrollment, native.private)
	if err != nil || selected.identity.serviceID != other || selected.PublisherGrantID() != grantID {
		t.Fatal("grant switch did not retain its independently issued exact service", err)
	}
	if _, err := selected.SavedService(t.Context()); !errors.Is(err, ErrScope) {
		t.Fatal("another service's grant retained the original service discovery", err)
	}
	if _, _, err := native.ForService(t.Context(), other); !errors.Is(err, ErrScope) {
		t.Fatal("exact service grant selected another service without another issued grant", err)
	}
	if err := native.NamespaceScope(); !errors.Is(err, ErrScope) {
		t.Fatal("exact service grant retained namespace allocation authority", err)
	}
	service, err := native.SavedService(t.Context())
	if err != nil || service.Id != native.identity.serviceID {
		t.Fatalf("exact private scope = %+v, %v", service, err)
	}
	control.service.TeamId = "other-team"
	if _, err := native.SavedService(t.Context()); !errors.Is(err, ErrScope) {
		t.Fatal("service crossed team scope", err)
	}
	control.service.TeamId = "team"
	control.service.Id, _ = opaqueid.New(opaqueid.ServicePrefix)
	if _, err := native.SavedService(t.Context()); !errors.Is(err, ErrScope) {
		t.Fatal("service crossed grant scope", err)
	}
}

func TestServiceRunDeclarationPreservesRevisionAndCapturedTrust(t *testing.T) {
	native, control := privateScopeFixture(t)
	trust, err := targettrust.NewCache(nil).Capture(t.Context(), t.TempDir(), "db.internal:5432", config.TrustSource{CA: "system"})
	if err != nil {
		t.Fatal(err)
	}
	control.service.TargetTls = ServiceTargetTLS(&trust)
	declaration := ServiceDeclaration(control.service)
	stale := declaration
	stale.TrustRevision--
	for _, value := range []controlv1.ServiceRunDeclaration{stale, {Protocol: controlv1.Mysql, TargetTls: declaration.TargetTls, TrustRevision: declaration.TrustRevision}, {Protocol: declaration.Protocol, TrustRevision: declaration.TrustRevision}} {
		if _, err := native.PrepareServiceRun(t.Context(), control.service.Id, "key", "access", value); !errors.Is(err, ErrScope) {
			t.Fatalf("mismatched declaration accepted: %+v, %v", value, err)
		}
	}
	if len(control.declarations) != 0 {
		t.Fatal("mismatched declaration reached control")
	}
	if _, err := native.PrepareServiceRun(t.Context(), control.service.Id, "key", "access", declaration); err != nil {
		t.Fatal(err)
	}
	if len(control.declarations) != 1 || !sameServiceDeclaration(control.declarations[0], declaration) {
		t.Fatal("approved declaration was changed")
	}
	if err := MatchServiceDeclaration(control.service, "postgres", nil); !errors.Is(err, ErrScope) {
		t.Fatal("missing local TLS silently adopted remote trust", err)
	}
	if err := MatchServiceDeclaration(control.service, "postgres", &trust); err != nil {
		t.Fatal(err)
	}
	other, err := targettrust.NewCache(nil).Capture(t.Context(), t.TempDir(), "other.internal:5432", config.TrustSource{CA: "system"})
	if err != nil {
		t.Fatal(err)
	}
	if err := MatchServiceDeclaration(control.service, "postgres", &other); !errors.Is(err, ErrScope) {
		t.Fatal("different local hostname adopted remote revision", err)
	}
}
