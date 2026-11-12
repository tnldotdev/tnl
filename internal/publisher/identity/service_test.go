package identity

import (
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type privateScopeControl struct {
	unusedControl
	ServiceControl
	service      controlv1.Service
	declarations []controlv1.ServiceRunDeclaration
	reads        int
}

func TestNativeEnvironmentPublicationCannotBeOverriddenOrDropped(t *testing.T) {
	native, control := privateScopeFixture(t)
	id, err := opaqueid.New(opaqueid.EnvironmentPrefix)
	if err != nil {
		t.Fatal(err)
	}
	native.environmentPublication = &controlv1.EnvironmentPublication{EnvironmentId: id, MutationRevision: 4, ConfigurationHash: strings.Repeat("a", 64)}
	declaration := ServiceDeclaration(control.service)
	override := *native.environmentPublication
	override.MutationRevision++
	declaration.Environment = &override
	if _, err := native.PrepareServiceRun(t.Context(), control.service.Id, "override", "access", declaration); !errors.Is(err, ErrScope) || len(control.declarations) != 0 {
		t.Fatal("caller replaced the selected application fence", err)
	}
	grant, err := opaqueid.New(opaqueid.PublisherGrantPrefix)
	if err != nil {
		t.Fatal(err)
	}
	clone, err := native.ForGrant(controlv1.PublisherGrant{Id: grant, Kind: "service", ServiceId: &control.service.Id})
	if err != nil || !sameEnvironmentPublication(clone.environmentPublication, native.environmentPublication) || clone.environmentPublication == native.environmentPublication {
		t.Fatal("same-service grant clone lost or shared its pinned application", err)
	}
	copy, err := native.WithTraffic(nil)
	if err != nil || !sameEnvironmentPublication(copy.environmentPublication, native.environmentPublication) || copy.environmentPublication == native.environmentPublication {
		t.Fatal("worker clone lost or shared its pinned application", err)
	}
	fork, err := native.Fork()
	if err != nil || !sameEnvironmentPublication(fork.environmentPublication, native.environmentPublication) || fork.environmentPublication == native.environmentPublication {
		t.Fatal("invocation fork lost or shared its pinned application", err)
	}
	otherService, err := opaqueid.New(opaqueid.ServicePrefix)
	if err != nil {
		t.Fatal(err)
	}
	other, err := native.ForGrant(controlv1.PublisherGrant{Id: grant, Kind: "service", ServiceId: &otherService})
	if err != nil || other.environmentPublication != nil {
		t.Fatal("different-service grant inherited another environment's application", err)
	}
	ordinary, ordinaryControl := privateScopeFixture(t)
	declaration = ServiceDeclaration(ordinaryControl.service)
	declaration.Environment = cloneEnvironmentPublication(native.environmentPublication)
	if _, err := ordinary.PrepareServiceRun(t.Context(), ordinaryControl.service.Id, "injected", "access", declaration); !errors.Is(err, ErrScope) {
		t.Fatal("ordinary service client accepted an injected environment context", err)
	}
}

func TestNativeConstructorValidatesAndCopiesEnvironmentPublication(t *testing.T) {
	original, _ := privateScopeFixture(t)
	id, err := opaqueid.New(opaqueid.EnvironmentPrefix)
	if err != nil {
		t.Fatal(err)
	}
	fence := &controlv1.EnvironmentPublication{EnvironmentId: id, MutationRevision: 2, ConfigurationHash: strings.Repeat("a", 64)}
	native, err := NewNative(original.NativeControl, original.authority, original.identity.enrollment(), original.private, fence)
	if err != nil || !sameEnvironmentPublication(native.environmentPublication, fence) || native.environmentPublication == fence {
		t.Fatal("native constructor lost or shared the assigned snapshot", err)
	}
	fence.MutationRevision++
	if native.environmentPublication.MutationRevision != 2 {
		t.Fatal("caller changed a constructed native publisher's application")
	}
	for _, invalid := range []controlv1.EnvironmentPublication{
		{EnvironmentId: "pgrp_invalid", MutationRevision: 1, ConfigurationHash: strings.Repeat("a", 64)},
		{EnvironmentId: id, MutationRevision: 0, ConfigurationHash: strings.Repeat("a", 64)},
		{EnvironmentId: id, MutationRevision: 1, ConfigurationHash: strings.Repeat("A", 64)},
	} {
		if _, err := NewNative(original.NativeControl, original.authority, original.identity.enrollment(), original.private, &invalid); !errors.Is(err, ErrScope) {
			t.Fatal("malformed environment context entered the native publisher", err)
		}
	}
}

type privateOwnerControl struct {
	*privateScopeControl
	enrollment controlv1.PublisherEnrollment
	created    int
}

func (c *privateOwnerControl) CreatePublisherEnrollment(_ context.Context, request controlv1.CreatePublisherEnrollmentRequest) (controlv1.PublisherEnrollment, error) {
	if request.ServiceId == nil || *request.ServiceId != c.service.Id || request.PublicUrlId != nil || request.DomainId != nil {
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

func (c *privateScopeControl) GetPublisherService(_ context.Context, access string) (controlv1.Service, error) {
	if access != "access" {
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
	native, err := NewNative(NativeControl{PublicURLControl: control, Services: control}, &lostEnrollmentResponse{}, identity, key, nil)
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
	public, err := native.ForGrant(controlv1.PublisherGrant{Id: grantID, Kind: "saved_public_url", PublicUrlId: &urlID})
	if err != nil || public.identity.serviceID != "" || public.identity.publicURLID != urlID {
		t.Fatalf("grant switch retained another scope: %+v, %v", public, err)
	}
	if _, err := public.SavedService(t.Context()); !errors.Is(err, ErrScope) {
		t.Fatal("public grant retained private discovery", err)
	}
	if _, err := native.SavedPublicURL(t.Context()); !errors.Is(err, ErrScope) {
		t.Fatal("private grant read a public URL", err)
	}
	if err := native.SelectPublicURL(controlv1.PublicURL{TeamId: "team", LifecycleState: controlv1.Enabled}); !errors.Is(err, ErrScope) {
		t.Fatal("private grant selected a public URL", err)
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
