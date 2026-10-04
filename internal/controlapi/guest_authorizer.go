package controlapi

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/certificateidentity"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
)

type guestAuthorizer struct {
	fallback      publicURLAuthorizer
	store         guestAuthorizationStore
	managedDomain string
	dnsAutomation bool
}

type guestAuthorizationStore interface {
	GuestTrialByAccessToken(context.Context, credentials.AccessToken) (controlstate.GuestTrial, error)
	GuestOwnsPublicURL(context.Context, string, string) (bool, error)
	GuestSourceMatches(controlstate.GuestTrial, string) (bool, error)
	EnsureExternalAuthorityPrincipal(context.Context, string, time.Time) ([32]byte, error)
}

func (a guestAuthorizer) AuthorizePublicURLReads(ctx context.Context, token string) (publicURLReadPrincipal, error) {
	guest, err := a.store.GuestTrialByAccessToken(ctx, credentials.AccessToken(token))
	if errors.Is(err, controlstate.ErrGuestUnknown) {
		return a.fallback.AuthorizePublicURLReads(ctx, token)
	}
	if err != nil {
		return publicURLReadPrincipal{}, authorization.ErrUnavailable
	}
	return publicURLReadPrincipal{identityID: guest.ID, teamIDs: map[string]struct{}{guest.TeamID: {}}}, nil
}

func (a guestAuthorizer) Authorize(ctx context.Context, request authorization.Request) (authorization.Decision, error) {
	guest, err := a.store.GuestTrialByAccessToken(ctx, credentials.AccessToken(request.AccessToken))
	if errors.Is(err, controlstate.ErrGuestUnknown) {
		return a.fallback.Authorize(ctx, request)
	}
	if err != nil {
		return authorization.Decision{}, authorization.ErrUnavailable
	}
	if request.Operation == authorization.OperationPublicURLUpdate ||
		request.Operation != authorization.OperationPublicURLDelete &&
			(!guest.ExpiresAt.After(time.Now()) || guest.UsedReady >= controlstate.GuestReadyAllowance || guest.UsedBytes >= controlstate.GuestByteAllowance) {
		if !guest.ExpiresAt.After(time.Now()) || guest.UsedReady >= controlstate.GuestReadyAllowance || guest.UsedBytes >= controlstate.GuestByteAllowance {
			return authorization.Decision{}, controlstate.ErrGuestTrialSpent
		}
		return authorization.Decision{}, authorization.ErrGuestDemoOnly
	}
	namespace := guest.NamespaceLabel + "." + a.managedDomain
	label := ""
	if len(request.CanonicalHostname) > len(namespace)+1 &&
		request.CanonicalHostname[len(request.CanonicalHostname)-len(namespace)-1:] == "."+namespace {
		label = request.CanonicalHostname[:len(request.CanonicalHostname)-len(namespace)-1]
	}
	validDemoLabel := strings.HasPrefix(label, "demo-")
	if validDemoLabel {
		number, parseErr := strconv.ParseInt(strings.TrimPrefix(label, "demo-"), 10, 64)
		validDemoLabel = parseErr == nil && number > 0 && label == fmt.Sprintf("demo-%d", number) &&
			(request.Operation != authorization.OperationPublicURLCreate || number == guest.LastDemoNumber)
	}
	if request.TeamID != guest.TeamID || request.DomainID != guest.DomainID ||
		request.PublicURLScope != authorization.PublicURLScopeMember || !validDemoLabel ||
		!request.Ephemeral || request.PublicURLMembershipID != "" && request.PublicURLMembershipID != guest.MembershipID ||
		request.ActingMembershipID != "" && request.ActingMembershipID != guest.MembershipID {
		return authorization.Decision{}, authorization.ErrGuestDemoOnly
	}
	if request.Operation == authorization.OperationPublicURLCreate {
		if len(request.AllowedIPPrefixes) != 1 {
			return authorization.Decision{}, authorization.ErrGuestDemoOnly
		}
		matched, err := a.store.GuestSourceMatches(guest, request.AllowedIPPrefixes[0])
		if err != nil {
			return authorization.Decision{}, authorization.ErrUnavailable
		}
		if !matched {
			return authorization.Decision{}, authorization.ErrGuestIPChanged
		}
	}
	if request.Operation != authorization.OperationPublicURLCreate {
		if request.PublicURLID == "" {
			return authorization.Decision{}, authorization.ErrGuestDemoOnly
		}
		owned, err := a.store.GuestOwnsPublicURL(ctx, guest.ID, request.PublicURLID)
		if err != nil || !owned {
			return authorization.Decision{}, authorization.ErrForbidden
		}
	}
	retrySecret, err := a.store.EnsureExternalAuthorityPrincipal(ctx, guest.ID, time.Now())
	if err != nil {
		return authorization.Decision{}, authorization.ErrUnavailable
	}
	decision := authorization.Decision{
		GuestID: guest.ID, IdentityID: guest.ID, TeamID: guest.TeamID,
		ActingMembershipID: guest.MembershipID, ActingRole: "owner", PublicURLMembershipID: guest.MembershipID,
		PolicyRevision: 1, DomainID: guest.DomainID, CanonicalHostname: request.CanonicalHostname,
		PublicURLScope: authorization.PublicURLScopeMember, DNSAuthorityReference: guest.DNSAuthorityReference,
		RetrySecret: retrySecret,
	}
	if request.Operation == authorization.OperationPublishRunCreate {
		plan := &authorization.CertificatePlan{
			CacheKey: request.CanonicalHostname, Scope: request.CanonicalHostname,
			Identifiers: []string{request.CanonicalHostname}, ChallengeMethod: certificateidentity.ChallengeTLSALPN01,
		}
		if a.dnsAutomation {
			plan.CacheKey, plan.Scope = namespace, namespace
			plan.Identifiers = []string{"*." + namespace, namespace}
			plan.ChallengeMethod = certificateidentity.ChallengeDNS01
		}
		decision.CertificatePlan = plan
	}
	return decision, nil
}
