package controlapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type PublisherIdentityStore interface {
	IdentityContext(context.Context, string) (controlstate.IdentityContext, error)
	IssuePublisherEnrollment(context.Context, controlstate.CreatePublisherEnrollmentRequest) (controlstate.PublisherEnrollment, error)
	CreatePublisherGrant(context.Context, controlstate.CreatePublisherGrantRequest) (string, error)
	ListPublisherIdentities(context.Context, string, string) (controlstate.PublisherIdentityPage, error)
	PublisherIdentityRecord(context.Context, string, string) (controlstate.PublisherRecord, error)
	AuthorizePublisherManagement(context.Context, string, string, string) error
	RevokePublisherIdentity(context.Context, string, string, string, time.Time) error
	RevokePublisherGrant(context.Context, string, string, string, string, time.Time) error
	AuthenticatePublisherAccess(context.Context, string, string, time.Time) (controlstate.PublisherIdentity, error)
	AllocatePublisherPublicURL(context.Context, controlstate.PublisherIdentity, string, string, []string, []byte, time.Time, ...controlstate.VisitorAccessMode) (controlstate.PublicURL, error)
	PublisherMayStartRun(context.Context, controlstate.PublisherIdentity, string) (bool, error)
}

func publisherProblem(w http.ResponseWriter, operation string, err error) {
	if errors.Is(err, controlstate.ErrAuthorityConflict) {
		writeProblem(w, http.StatusConflict, controlv1.Conflict, "publisher grant already exists")
		return
	}
	if errors.Is(err, controlstate.ErrPublisherIdentity) || errors.Is(err, controlstate.ErrPublisherEnrollment) || errors.Is(err, pgx.ErrNoRows) {
		writeBearerProblem(w)
		return
	}
	writeControlStateProblem(w, operation, err)
}

func (h *handler) publisherEditor(w http.ResponseWriter, r *http.Request, team string) (PublisherIdentityStore, controlstate.Membership, string, bool) {
	store, ok := h.store.(PublisherIdentityStore)
	if !ok {
		writeProblem(w, 503, controlv1.Unavailable, "publisher identities are unavailable")
		return nil, controlstate.Membership{}, "", false
	}
	p, ok := h.authorizeRouteReads(w, r)
	if !ok {
		return nil, controlstate.Membership{}, "", false
	}
	if _, ok := p.teamIDs[team]; !ok {
		writeProblem(w, 404, controlv1.NotFound, "resource not found")
		return nil, controlstate.Membership{}, "", false
	}
	i, err := store.IdentityContext(r.Context(), p.identityID)
	if err != nil {
		writeControlStateProblem(w, "read publisher editor", err)
		return nil, controlstate.Membership{}, "", false
	}
	for _, m := range i.Memberships {
		if m.TeamID == team {
			return store, m, p.identityID, true
		}
	}
	writeProblem(w, 403, controlv1.Forbidden, "publisher management requires current team membership")
	return nil, controlstate.Membership{}, "", false
}

func publisherScope(team string, url, domain, private *string) (controlstate.PublisherScope, bool) {
	s := controlstate.PublisherScope{TeamID: team}
	selected := 0
	for _, value := range []*string{url, domain, private} {
		if value != nil {
			selected++
		}
	}
	if selected != 1 {
		return s, false
	}
	if private != nil {
		s.Kind, s.PrivateServiceID = "private_service", *private
		return s, opaqueid.Valid(*private, opaqueid.PrivateServicePrefix)
	}
	if url != nil {
		s.Kind, s.PublicURLID = "saved_url", *url
		return s, opaqueid.Valid(*url, opaqueid.PublicURLPrefix)
	}
	s.Kind, s.DomainID = "namespace", *domain
	return s, opaqueid.Valid(*domain, opaqueid.DomainPrefix)
}

func (h *handler) CreatePublisherEnrollment(w http.ResponseWriter, r *http.Request) {
	var b controlv1.CreatePublisherEnrollmentRequest
	if decodeJSON(w, r, &b) != nil || !b.Kind.Valid() || !naming.ValidServiceName(b.Name) {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid publisher enrollment")
		return
	}
	s, valid := publisherScope(b.TeamId, b.PublicUrlId, b.DomainId, b.PrivateServiceId)
	if !valid || s.Kind == "namespace" && !h.config.DNSAutomation {
		writeProblem(w, 400, controlv1.InvalidRequest, "select a saved URL or an automated HTTP namespace")
		return
	}
	store, m, editor, ok := h.publisherEditor(w, r, b.TeamId)
	if !ok {
		return
	}
	request := controlstate.CreatePublisherEnrollmentRequest{Scope: s, Name: b.Name, Kind: string(b.Kind), EditorID: editor, EditorMembershipID: m.ID, PolicyRevision: uint64(m.PolicyRevision), Now: time.Now()}
	if b.Ownership != nil {
		request.Ownership = string(*b.Ownership)
	}
	e, err := store.IssuePublisherEnrollment(r.Context(), request)
	if err != nil {
		publisherProblem(w, "issue publisher enrollment", err)
		return
	}
	result := controlv1.PublisherEnrollment{Id: e.ID, EnrollmentKey: e.Key, ExpiresAt: e.Until, TeamId: s.TeamID, Kind: controlv1.PublisherEnrollmentKind(s.Kind)}
	if e.Scope.PublicURLID != "" {
		result.PublicUrlId = &e.Scope.PublicURLID
	}
	if e.Scope.PrivateServiceID != "" {
		result.PrivateServiceId = &e.Scope.PrivateServiceID
	}
	if e.Scope.DomainID != "" {
		result.DomainId = &e.Scope.DomainID
	}
	if e.Scope.Namespace != "" {
		result.Namespace = &e.Scope.Namespace
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 201, result)
}

func publisherGrantResponse(g controlstatedb.ControlPublisherGrant) controlv1.PublisherGrant {
	r := controlv1.PublisherGrant{Id: g.ID, Kind: controlv1.PublisherGrantKind(g.Kind), CreatedAt: g.CreatedAt.Time}
	if g.PublicURLID.Valid {
		r.PublicUrlId = &g.PublicURLID.String
	}
	if g.PrivateServiceID.Valid {
		r.PrivateServiceId = &g.PrivateServiceID.String
	}
	if g.DomainID.Valid {
		r.DomainId = &g.DomainID.String
	}
	if g.Namespace.Valid {
		r.Namespace = &g.Namespace.String
	}
	if g.ExpiresAt.Valid {
		r.ExpiresAt = &g.ExpiresAt.Time
	}
	if g.RevokedAt.Valid {
		r.RevokedAt = &g.RevokedAt.Time
	}
	return r
}

func (h *handler) ListPublisherIdentities(w http.ResponseWriter, r *http.Request, params controlv1.ListPublisherIdentitiesParams) {
	w.Header().Set("Cache-Control", "no-store")
	store, _, editor, ok := h.publisherEditor(w, r, params.TeamId)
	if !ok {
		return
	}
	after := ""
	if params.Cursor != nil {
		after = *params.Cursor
	}
	if after != "" && !opaqueid.Valid(after, opaqueid.PublisherIdentityPrefix) {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid publisher cursor")
		return
	}
	page, err := store.ListPublisherIdentities(r.Context(), params.TeamId, after)
	if err != nil {
		publisherProblem(w, "list publishers", err)
		return
	}
	result := controlv1.PublisherIdentityPage{Identities: []controlv1.PublisherIdentity{}}
	for _, record := range page.Identities {
		err := store.AuthorizePublisherManagement(r.Context(), params.TeamId, record.Identity.ID, editor)
		if errors.Is(err, controlstate.ErrPublisherIdentity) || errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			publisherProblem(w, "authorize publisher listing", err)
			return
		}
		i := record.Identity
		p := controlv1.PublisherIdentity{Id: i.ID, Name: i.Name, Kind: controlv1.PublisherIdentityKind(i.Kind), CreatedAt: i.CreatedAt.Time, Grants: []controlv1.PublisherGrant{}}
		p.Ownership = controlv1.PublisherIdentityOwnership(i.Ownership)
		p.Runtime = runtimeResponse(record.Runtime)
		if i.OwnerMembershipID.Valid {
			p.OwnerMembershipId = &i.OwnerMembershipID.String
		}
		if i.RevokedAt.Valid {
			p.RevokedAt = &i.RevokedAt.Time
		}
		for _, g := range record.Grants {
			p.Grants = append(p.Grants, publisherGrantResponse(g))
		}
		result.Identities = append(result.Identities, p)
	}
	if page.NextCursor != "" {
		result.NextCursor = &page.NextCursor
	}
	writeJSON(w, 200, result)
}

func (h *handler) CreatePublisherGrant(w http.ResponseWriter, r *http.Request, id controlv1.PublisherIdentityID) {
	var b controlv1.CreatePublisherGrantRequest
	if decodeJSON(w, r, &b) != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid publisher grant")
		return
	}
	s, valid := publisherScope(b.TeamId, b.PublicUrlId, b.DomainId, b.PrivateServiceId)
	if !valid || s.Kind == "namespace" && !h.config.DNSAutomation {
		writeProblem(w, 400, controlv1.InvalidRequest, "select a saved URL or an automated HTTP namespace")
		return
	}
	store, m, editor, ok := h.publisherEditor(w, r, b.TeamId)
	if !ok {
		return
	}
	if err := store.AuthorizePublisherManagement(r.Context(), b.TeamId, id, editor); err != nil {
		publisherProblem(w, "authorize publisher grant", err)
		return
	}
	now := time.Now()
	grant, err := store.CreatePublisherGrant(r.Context(), controlstate.CreatePublisherGrantRequest{PublisherIdentityID: id, Scope: s, EditorID: editor, EditorMembershipID: m.ID, PolicyRevision: uint64(m.PolicyRevision), ExpiresAt: b.ExpiresAt, Now: now})
	if err != nil {
		publisherProblem(w, "create publisher grant", err)
		return
	}
	// read the server-captured namespace rather than echoing request fields.
	p, err := store.PublisherIdentityRecord(r.Context(), b.TeamId, id)
	if err != nil {
		publisherProblem(w, "read publisher grant", err)
		return
	}
	for _, g := range p.Grants {
		if g.ID == grant {
			writeJSON(w, 201, publisherGrantResponse(g))
			return
		}
	}
	writeProblem(w, 503, controlv1.Unavailable, "created grant could not be read")
}

func (h *handler) RevokePublisherIdentity(w http.ResponseWriter, r *http.Request, id controlv1.PublisherIdentityID, params controlv1.RevokePublisherIdentityParams) {
	store, _, editor, ok := h.publisherEditor(w, r, params.TeamId)
	if !ok {
		return
	}
	if err := store.RevokePublisherIdentity(r.Context(), params.TeamId, id, editor, time.Now()); err != nil {
		publisherProblem(w, "revoke publisher", err)
		return
	}
	w.WriteHeader(204)
}

func (h *handler) RevokePublisherGrant(w http.ResponseWriter, r *http.Request, id controlv1.PublisherIdentityID, grant controlv1.ResourceID, params controlv1.RevokePublisherGrantParams) {
	store, _, editor, ok := h.publisherEditor(w, r, params.TeamId)
	if !ok {
		return
	}
	if err := store.RevokePublisherGrant(r.Context(), params.TeamId, id, grant, editor, time.Now()); err != nil {
		publisherProblem(w, "revoke publisher grant", err)
		return
	}
	w.WriteHeader(204)
}
