package native

import (
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"testing"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	privatetrust "github.com/tnldotdev/tnl/internal/security/targettrust"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type privateScopeControl struct {
	NativeControl
	privateRunControl
	service      controlv1.PrivateService
	declarations []controlv1.PrivateServiceRunDeclaration
	reads        int
}

type privateOwnerControl struct {
	*privateScopeControl
	enrollment controlv1.PublisherEnrollment
	created    int
}

func (c *privateOwnerControl) CreatePublisherEnrollment(_ context.Context, request controlv1.CreatePublisherEnrollmentRequest) (controlv1.PublisherEnrollment, error) {
	if request.PrivateServiceId == nil || *request.PrivateServiceId != c.service.Id || request.PublicUrlId != nil || request.DomainId != nil {
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
	control := &privateOwnerControl{privateScopeControl: scope, enrollment: controlv1.PublisherEnrollment{Id: id, TeamId: scope.service.TeamId, Kind: "private_service", PrivateServiceId: &scope.service.Id, EnrollmentKey: id + ".one-use"}}
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
	if _, _, err := EnsurePrivateServiceOwner(t.Context(), profile, control, authority, scope.service); err == nil {
		t.Fatal("lost redemption response was accepted")
	}
	for range 2 {
		native, identity, err := EnsurePrivateServiceOwner(t.Context(), profile, control, authority, scope.service)
		if err != nil || native == nil || identity.ClientId != fixture.identity.clientID || control.created != 1 || authority.calls != 2 {
			t.Fatalf("private owner recovery: identity=%+v created=%d redeemed=%d err=%v", identity, control.created, authority.calls, err)
		}
		if _, err := native.SavedPrivateService(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
}

func (c *privateScopeControl) GetPublisherPrivateService(_ context.Context, access string) (controlv1.PrivateService, error) {
	if access != "access" {
		return controlv1.PrivateService{}, ErrScope
	}
	c.reads++
	return c.service, nil
}

func (c *privateScopeControl) PreparePrivateServiceRun(_ context.Context, serviceID, key, access string, declarations ...controlv1.PrivateServiceRunDeclaration) (controlv1.PrivateServiceRunPreparation, error) {
	if serviceID != c.service.Id || access != "access" || key == "" || len(declarations) != 1 {
		return controlv1.PrivateServiceRunPreparation{}, ErrScope
	}
	c.declarations = append(c.declarations, declarations[0])
	return controlv1.PrivateServiceRunPreparation{PrivateServiceId: serviceID}, nil
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
	serviceID := id(opaqueid.PrivateServicePrefix)
	identity := authorityv1.PublisherEnrollmentResult{ClientId: id(opaqueid.PublisherIdentityPrefix), GrantId: id(opaqueid.PublisherGrantPrefix), KeyId: id(opaqueid.PublisherIdentityKeyPrefix), TeamId: "team", Kind: authorityv1.PrivateService, PrivateServiceId: &serviceID}
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	control := &privateScopeControl{service: controlv1.PrivateService{Id: serviceID, TeamId: "team", Name: "orders", Enabled: true, Protocol: controlv1.Postgres, TrustRevision: 3}}
	native, err := NewNative(control, &lostEnrollmentResponse{}, identity, key)
	if err != nil {
		t.Fatal(err)
	}
	return native, control
}

func TestNativePrivateGrantCannotSelectPublicURLOrAnotherService(t *testing.T) {
	native, control := privateScopeFixture(t)
	grantID, err := opaqueid.New(opaqueid.PublisherGrantPrefix)
	if err != nil {
		t.Fatal(err)
	}
	urlID, err := opaqueid.New(opaqueid.PublicURLPrefix)
	if err != nil {
		t.Fatal(err)
	}
	public, err := native.ForGrant(controlv1.PublisherGrant{Id: grantID, Kind: "saved_url", PublicUrlId: &urlID})
	if err != nil || public.identity.privateServiceID != "" || public.identity.publicURLID != urlID {
		t.Fatalf("grant switch retained another scope: %+v, %v", public, err)
	}
	if _, err := public.SavedPrivateService(t.Context()); !errors.Is(err, ErrScope) {
		t.Fatal("public grant retained private discovery", err)
	}
	if _, err := native.SavedURL(t.Context()); !errors.Is(err, ErrScope) {
		t.Fatal("private grant read a public URL", err)
	}
	if err := native.SelectRoute(controlv1.PublicURL{TeamId: "team", LifecycleState: controlv1.Enabled}); !errors.Is(err, ErrScope) {
		t.Fatal("private grant selected a public URL", err)
	}
	service, err := native.SavedPrivateService(t.Context())
	if err != nil || service.Id != native.identity.privateServiceID {
		t.Fatalf("exact private scope = %+v, %v", service, err)
	}
	control.service.TeamId = "other-team"
	if _, err := native.SavedPrivateService(t.Context()); !errors.Is(err, ErrScope) {
		t.Fatal("service crossed team scope", err)
	}
	control.service.TeamId = "team"
	control.service.Id, _ = opaqueid.New(opaqueid.PrivateServicePrefix)
	if _, err := native.SavedPrivateService(t.Context()); !errors.Is(err, ErrScope) {
		t.Fatal("service crossed grant scope", err)
	}
}

func TestPrivateRunDeclarationPreservesRevisionAndCapturedTrust(t *testing.T) {
	native, control := privateScopeFixture(t)
	trust, err := privatetrust.NewCache(nil).Capture(t.Context(), t.TempDir(), "db.internal:5432", config.TrustSource{CA: "system"})
	if err != nil {
		t.Fatal(err)
	}
	control.service.TargetTls = PrivateServiceTLS(&trust)
	declaration := PrivateServiceDeclaration(control.service)
	stale := declaration
	stale.TrustRevision--
	for _, value := range []controlv1.PrivateServiceRunDeclaration{stale, {Protocol: controlv1.Mysql, TargetTls: declaration.TargetTls, TrustRevision: declaration.TrustRevision}, {Protocol: declaration.Protocol, TrustRevision: declaration.TrustRevision}} {
		if _, err := native.PreparePrivateServiceRun(t.Context(), control.service.Id, "key", "access", value); !errors.Is(err, ErrScope) {
			t.Fatalf("mismatched declaration accepted: %+v, %v", value, err)
		}
	}
	if len(control.declarations) != 0 {
		t.Fatal("mismatched declaration reached control")
	}
	if _, err := native.PreparePrivateServiceRun(t.Context(), control.service.Id, "key", "access", declaration); err != nil {
		t.Fatal(err)
	}
	if len(control.declarations) != 1 || !samePrivateDeclaration(control.declarations[0], declaration) {
		t.Fatal("approved declaration was changed")
	}
	if err := MatchPrivateServiceDeclaration(control.service, "postgres", nil); !errors.Is(err, ErrScope) {
		t.Fatal("missing local TLS silently adopted remote trust", err)
	}
	if err := MatchPrivateServiceDeclaration(control.service, "postgres", &trust); err != nil {
		t.Fatal(err)
	}
	other, err := privatetrust.NewCache(nil).Capture(t.Context(), t.TempDir(), "other.internal:5432", config.TrustSource{CA: "system"})
	if err != nil {
		t.Fatal(err)
	}
	if err := MatchPrivateServiceDeclaration(control.service, "postgres", &other); !errors.Is(err, ErrScope) {
		t.Fatal("different local hostname adopted remote revision", err)
	}
}
