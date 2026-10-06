package controlapi

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
)

type localAuthorizationStoreStub struct {
	principal           controlstate.ControlPrincipal
	identity            controlstate.IdentityContext
	domains             []controlstate.Domain
	authenticationError error
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
