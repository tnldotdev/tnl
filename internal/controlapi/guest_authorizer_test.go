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

type guestStoreStub struct {
	guest controlstate.GuestTrial
	owned bool
}

func (s guestStoreStub) GuestTrialByAccessToken(_ context.Context, token credentials.AccessToken) (controlstate.GuestTrial, error) {
	if token != "guest-token" {
		return controlstate.GuestTrial{}, controlstate.ErrGuestUnknown
	}
	return s.guest, nil
}

func (s guestStoreStub) GuestOwnsPublicURL(context.Context, string, string) (bool, error) {
	return s.owned, nil
}

func (s guestStoreStub) GuestSourceMatches(_ controlstate.GuestTrial, prefix string) (bool, error) {
	return prefix == "192.0.2.7/32", nil
}

func (s guestStoreStub) EnsureGuestPrincipal(context.Context, string, time.Time) ([32]byte, error) {
	return [32]byte{1}, nil
}

type guestFallback struct{}

func (guestFallback) AuthorizePublicURLReads(context.Context, string) (publicURLReadPrincipal, error) {
	return publicURLReadPrincipal{}, authorization.ErrUnauthenticated
}

func (guestFallback) Authorize(context.Context, authorization.Request) (authorization.Decision, error) {
	return authorization.Decision{}, authorization.ErrUnauthenticated
}

func TestGuestAuthorizationLimitsPublicURLsToOneLocalDemo(t *testing.T) {
	guest := controlstate.GuestTrial{
		ID: "gst_1", TeamID: "tm_1", MembershipID: "mem_1", DomainID: "dom_1",
		NamespaceLabel: "guest-01234567", DNSAuthorityReference: "da_1",
		LastDemoNumber: 1,
		ExpiresAt:      time.Now().Add(72 * time.Hour),
	}
	authorizer := guestAuthorizer{
		fallback: guestFallback{}, store: guestStoreStub{guest: guest, owned: true},
		managedDomain: "tnl.wtf", dnsAutomation: true,
	}
	create := authorization.Request{
		AccessToken: "guest-token", Operation: authorization.OperationPublicURLCreate,
		TeamID: guest.TeamID, DomainID: guest.DomainID,
		CanonicalHostname: "demo-1.guest-01234567.tnl.wtf",
		PublicURLScope:    authorization.PublicURLScopeMember, Target: "http://127.0.0.1:3000",
		AllowedIPPrefixes: []string{"192.0.2.7/32"}, Ephemeral: true,
	}
	decision, err := authorizer.Authorize(t.Context(), create)
	if err != nil || decision.GuestID != guest.ID || decision.PublicURLMembershipID != guest.MembershipID {
		t.Fatalf("guest create decision = %+v, error = %v", decision, err)
	}
	changedIP := create
	changedIP.AllowedIPPrefixes = []string{"192.0.2.8/32"}
	if _, err := authorizer.Authorize(t.Context(), changedIP); !errors.Is(err, authorization.ErrGuestIPChanged) {
		t.Fatalf("changed guest IP was accepted: %v", err)
	}
	for _, invalid := range []authorization.Request{
		func() authorization.Request { r := create; r.AllowedIPPrefixes = []string{}; return r }(),
		func() authorization.Request {
			r := create
			r.CanonicalHostname = "app.guest-01234567.tnl.wtf"
			return r
		}(),
		func() authorization.Request {
			r := create
			r.CanonicalHostname = "demo-1.other.tnl.wtf"
			return r
		}(),
		func() authorization.Request { r := create; r.Ephemeral = false; return r }(),
		func() authorization.Request {
			r := create
			r.Operation = authorization.OperationPublicURLUpdate
			return r
		}(),
		func() authorization.Request { r := create; r.Operation = authorization.OperationShareCreate; return r }(),
		func() authorization.Request {
			r := create
			r.Operation = authorization.OperationFeedbackManage
			return r
		}(),
	} {
		if _, err := authorizer.Authorize(t.Context(), invalid); !errors.Is(err, authorization.ErrGuestDemoOnly) {
			t.Fatalf("guest accepted forbidden operation %+v: %v", invalid, err)
		}
	}
	create.Operation = authorization.OperationPublishRunCreate
	create.PublicURLID = "url_1"
	create.PublicURLMembershipID = guest.MembershipID
	decision, err = authorizer.Authorize(t.Context(), create)
	if err != nil || decision.CertificatePlan == nil || decision.CertificatePlan.Scope != "guest-01234567.tnl.wtf" {
		t.Fatalf("guest certificate plan = %+v, error = %v", decision, err)
	}
	authorizer.store = guestStoreStub{guest: guest}
	if _, err := authorizer.Authorize(t.Context(), create); !errors.Is(err, authorization.ErrForbidden) {
		t.Fatalf("foreign public URL accepted: %v", err)
	}
	guest.UsedBytes = controlstate.GuestByteAllowance
	authorizer.store = guestStoreStub{guest: guest, owned: true}
	if _, err := authorizer.Authorize(t.Context(), create); !errors.Is(err, controlstate.ErrGuestTrialSpent) {
		t.Fatalf("exhausted guest accepted: %v", err)
	}
}
