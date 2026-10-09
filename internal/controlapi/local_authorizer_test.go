package controlapi

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/naming"
)

type localAuthorizationStoreStub struct {
	principal           controlstate.ControlPrincipal
	identity            controlstate.IdentityContext
	domains             []controlstate.Domain
	authenticationError error
}

func TestSimpleManagedOrganizationUsesFullMemberNamespace(t *testing.T) {
	store := localAuthorizationStoreStub{
		principal: controlstate.ControlPrincipal{IdentityID: "alex"},
		identity: controlstate.IdentityContext{Memberships: []controlstate.Membership{{
			ID: "membership", TeamID: "studio", TeamKind: controlstate.TeamKindOrganization,
			TeamDisplayName: "studio", MemberSlug: "alex", ManagedLabel: "generated-name", Role: controlstate.TeamRoleMember,
			PolicyRevision: 1,
		}}},
		domains: []controlstate.Domain{{ID: "managed", Kind: controlstate.DomainKindManaged,
			CanonicalDomain: "routes.example.com", State: controlstate.DomainReady}},
	}
	authorizer := localAuthorizer{store: store, managedURLMode: naming.ManagedURLModeSimple}
	request := authorization.Request{Operation: authorization.OperationPublicURLCreate, TeamID: "studio",
		DomainID: "managed", PublicURLScope: authorization.PublicURLScopeMember,
		CanonicalHostname: "app.alex.studio.routes.example.com"}
	if _, err := authorizer.Authorize(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	for _, hostname := range []string{"alex.studio.routes.example.com", "app.generated-name.routes.example.com", "app.bob.studio.routes.example.com"} {
		request.CanonicalHostname = hostname
		if _, err := authorizer.Authorize(t.Context(), request); !errors.Is(err, authorization.ErrForbidden) {
			t.Errorf("authorized %q: %v", hostname, err)
		}
	}
}

func TestPersonalDirectURLCannotUseMemberScope(t *testing.T) {
	for _, managed := range []bool{false, true} {
		kind := controlstate.DomainKindCustom
		if managed {
			kind = controlstate.DomainKindManaged
		}
		store := localAuthorizationStoreStub{
			principal: controlstate.ControlPrincipal{IdentityID: "admin", Administrator: true},
			identity: controlstate.IdentityContext{Memberships: []controlstate.Membership{{
				ID: "membership", TeamID: "personal", TeamKind: controlstate.TeamKindPersonal,
				TeamDisplayName: "local-administrator", Role: controlstate.TeamRoleOwner, MemberSlug: "local-administrator",
			}}},
			domains: []controlstate.Domain{{ID: "domain", Kind: kind, CanonicalDomain: "dev.example.com", State: controlstate.DomainReady}},
		}
		authorizer := localAuthorizer{store: store, managedURLMode: naming.ManagedURLModeSimple}
		request := authorization.Request{Operation: authorization.OperationPublicURLCreate, TeamID: "personal",
			DomainID: "domain", PublicURLScope: authorization.PublicURLScopeMember,
			CanonicalHostname: "app.dev.example.com"}
		if _, err := authorizer.Authorize(t.Context(), request); !errors.Is(err, authorization.ErrForbidden) {
			t.Errorf("member scope used a direct domain (%s): %v", kind, err)
		}
		request.PublicURLScope = authorization.PublicURLScopeShared
		if _, err := authorizer.Authorize(t.Context(), request); err != nil {
			t.Errorf("shared scope rejected a direct domain (%s): %v", kind, err)
		}
	}
}

func (s localAuthorizationStoreStub) AuthenticateAccessToken(context.Context, credentials.AccessToken, int64, time.Time) (controlstate.ControlPrincipal, error) {
	return s.principal, s.authenticationError
}
func (s localAuthorizationStoreStub) IdentityContext(context.Context, string) (controlstate.IdentityContext, error) {
	return s.identity, nil
}
func (s localAuthorizationStoreStub) ListTeamDomains(context.Context, string, string) ([]controlstate.Domain, error) {
	return s.domains, nil
}

func TestLocalAuthorityUsesCurrentMembershipAndPreservesDeletePermissions(t *testing.T) {
	store := localAuthorizationStoreStub{principal: controlstate.ControlPrincipal{IdentityID: "identity", RetrySecret: [32]byte{4, 5, 6}},
		identity: controlstate.IdentityContext{Memberships: []controlstate.Membership{{ID: "membership", TeamID: "team", Role: "admin", PolicyRevision: 7}}},
		domains:  []controlstate.Domain{{ID: "domain", State: "ready"}}}
	request := authorization.Request{Operation: authorization.OperationPublicURLDelete, TeamID: "team", DomainID: "domain", PublicURLScope: "member", PublicURLMembershipID: "another-member", CanonicalHostname: "api.example.test"}
	decision, err := (localAuthorizer{store: store}).Authorize(t.Context(), request)
	if err != nil || decision.PolicyRevision != 7 || decision.RetrySecret != store.principal.RetrySecret || decision.PublicURLMembershipID != "another-member" {
		t.Fatalf("decision=%+v error=%v", decision, err)
	}
	request.Operation = authorization.OperationPublicURLUpdate
	if _, err := (localAuthorizer{store: store}).Authorize(t.Context(), request); !errors.Is(err, authorization.ErrForbidden) {
		t.Fatalf("updated another member URL: %v", err)
	}
	request.PublicURLMembershipID = "membership"
	store.domains[0].State = "releasing"
	for _, operation := range []authorization.Operation{authorization.OperationPublicURLCreate, authorization.OperationPublicURLUpdate, authorization.OperationPublishRunCreate} {
		request.Operation = operation
		if _, err := (localAuthorizer{store: store}).Authorize(t.Context(), request); !errors.Is(err, authorization.ErrForbidden) {
			t.Fatalf("used releasing domain: %s %v", operation, err)
		}
	}
	request.Operation = authorization.OperationPublicURLDelete
	if _, err := (localAuthorizer{store: store}).Authorize(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	store.authenticationError = controlstate.ErrControlAuthentication
	if _, err := (localAuthorizer{store: store}).Authorize(t.Context(), request); !errors.Is(err, authorization.ErrUnauthenticated) {
		t.Fatal(err)
	}
	store.authenticationError = errors.New("database unavailable")
	if _, err := (localAuthorizer{store: store}).Authorize(t.Context(), request); !errors.Is(err, authorization.ErrUnavailable) || !errors.Is(err, store.authenticationError) {
		t.Fatal(err)
	}
}
