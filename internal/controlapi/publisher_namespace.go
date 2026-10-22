package controlapi

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/tnldotdev/tnl/internal/applicationlimits"
	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type PublisherRunStore interface {
	AuthenticatePublisherAccess(context.Context, string, string, time.Time) (controlstate.PublisherIdentity, error)
	PublisherMayStartRun(context.Context, controlstate.PublisherIdentity, string) (bool, error)
	PublisherRunPlan(context.Context, controlstate.PublisherIdentity, controlstate.PublicURL, bool) (authorization.CertificatePlan, error)
}

func publisherRequestSource(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" {
		return ""
	}
	ip = ip.Unmap()
	return netip.PrefixFrom(ip, ip.BitLen()).String()
}

func (h *handler) authenticatePublisher(w http.ResponseWriter, r *http.Request) (PublisherIdentityStore, controlstate.PublisherIdentity, bool) {
	store, ok := h.store.(PublisherIdentityStore)
	if !ok {
		writeProblem(w, 503, controlv1.Unavailable, "publisher authentication is unavailable")
		return nil, controlstate.PublisherIdentity{}, false
	}
	token, ok := requestBearerToken(r)
	if !ok {
		writeBearerProblem(w)
		return nil, controlstate.PublisherIdentity{}, false
	}
	p, err := store.AuthenticatePublisherAccess(r.Context(), token, publisherRequestSource(r), time.Now())
	if err != nil {
		publisherProblem(w, "authenticate publisher", err)
		return nil, controlstate.PublisherIdentity{}, false
	}
	fields := observability.Fields{Component: "control"}
	if p.Scope.PublicURLID != "" {
		fields.ServiceProtocol = observability.ProtocolHTTP
	}
	*r = *r.WithContext(observability.AuthenticatedServerScope(r.Context(), observability.Identity{TeamID: p.Scope.TeamID, PublisherIdentityID: p.ID, PublicURLID: p.Scope.PublicURLID, ServiceID: p.Scope.PrivateServiceID}, fields))
	return store, p, true
}

func (h *handler) GetPublisherPublicURL(w http.ResponseWriter, r *http.Request) {
	_, p, ok := h.authenticatePublisher(w, r)
	if !ok {
		return
	}
	if p.Scope.Kind != "saved_url" {
		writeProblem(w, 404, controlv1.NotFound, "resource not found")
		return
	}
	u, err := h.store.GetPublicURLForAuthorization(r.Context(), p.Scope.PublicURLID)
	if err != nil {
		publisherProblem(w, "read publisher URL", err)
		return
	}
	if u.TeamID != p.Scope.TeamID || u.LifecycleState != controlstate.PublicURLLifecycleEnabled {
		writeProblem(w, 404, controlv1.NotFound, "resource not found")
		return
	}
	writeJSON(w, 200, publicURLResponse(u))
}

func validAllocationLimits(l *controlv1.PublisherApplicationLimits) bool {
	if l == nil {
		return true
	}
	requests, concurrency, rate := 0, 0, 0
	period := time.Duration(0)
	if l.Requests != nil {
		requests = *l.Requests
		if requests < 1 {
			return false
		}
	}
	if l.Concurrency != nil {
		concurrency = *l.Concurrency
		if concurrency < 1 {
			return false
		}
	}
	if l.Rate != nil {
		var err error
		period, err = time.ParseDuration(l.Rate.Per)
		if err != nil || period <= 0 || l.Rate.Requests < 1 {
			return false
		}
		rate = l.Rate.Requests
	}
	return applicationlimits.Valid(requests, rate, concurrency, period)
}

func allocationIPPolicy(b controlv1.AllocateEphemeralPublicURLRequest) ([]string, error) {
	values := []string{}
	if b.Ip != nil {
		values = *b.Ip
	}
	p, err := authorization.CanonicalizeIPPrefixes(values)
	if err != nil || len(p) > 32 {
		return nil, authorization.ErrInvalid
	}
	return p, nil
}

func (h *handler) AllocatePublisherPublicURL(w http.ResponseWriter, r *http.Request) {
	if !h.config.DNSAutomation {
		writeProblem(w, 409, controlv1.Conflict, "namespace allocation requires automated DNS")
		return
	}
	store, p, ok := h.authenticatePublisher(w, r)
	if !ok {
		return
	}
	var b controlv1.AllocateEphemeralPublicURLRequest
	if decodeJSON(w, r, &b) != nil || !opaqueid.Valid(b.InvocationId, opaqueid.InvocationPrefix) || !validAllocationLimits(b.Limits) {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid namespace allocation")
		return
	}
	if _, err := localproxy.ParseCanonicalTarget(b.Target); err != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "target must be an HTTP or HTTPS origin")
		return
	}
	prefixes, err := allocationIPPolicy(b)
	if err != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid visitor IP policy")
		return
	}
	mode := controlstate.VisitorAccessRestricted
	if b.AccessMode != nil {
		mode = controlstate.VisitorAccessMode(*b.AccessMode)
	}
	if !mode.Valid() {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid visitor access mode")
		return
	}
	// retain a canonical limits binding in retries even though limits are
	// applied by the publisher rather than stored as URL policy.
	binding, err := json.Marshal(b.Limits)
	if err != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid publisher limits")
		return
	}
	u, err := store.AllocatePublisherPublicURL(r.Context(), p, b.InvocationId, b.Target, prefixes, binding, time.Now(), mode)
	if err != nil {
		publisherProblem(w, "allocate publisher URL", err)
		return
	}
	writeJSON(w, 201, publicURLResponse(u))
}

func (h *handler) DeletePublisherPublicURL(w http.ResponseWriter, r *http.Request, id controlv1.PublicURLID) {
	store, p, ok := h.authenticatePublisher(w, r)
	if !ok {
		return
	}
	if p.Scope.Kind != "namespace" || p.GuestID != "" {
		writeProblem(w, 404, controlv1.NotFound, "resource not found")
		return
	}
	owns, err := store.PublisherMayStartRun(r.Context(), p, id)
	if err != nil || !owns {
		writeProblem(w, 404, controlv1.NotFound, "resource not found")
		return
	}
	u, err := h.store.GetPublicURLForAuthorization(r.Context(), id)
	if err != nil {
		publisherProblem(w, "read allocated URL", err)
		return
	}
	if err := h.store.DeleteAuthorizedPublicURL(r.Context(), controlstate.AuthorizedPublicURLDeleteRequest{PublicURLID: id, TeamID: p.Scope.TeamID, ActingIdentityID: p.CreatorID, PolicyRevision: uint64(u.PolicyRevision), ExpectedMutationRevision: u.MutationRevision, PublisherIdentityID: p.ID, PublisherGrantID: p.GrantID}, time.Now()); err != nil {
		publisherProblem(w, "delete allocated URL", err)
		return
	}
	w.WriteHeader(204)
}
