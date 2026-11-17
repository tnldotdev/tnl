package public

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/httpjson"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
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
	AllocatePublisherService(context.Context, controlstate.PublisherIdentity, controlstate.AllocateServiceRequest, time.Time) (controlstate.ServiceRecord, error)
	DeletePublisherService(context.Context, controlstate.PublisherIdentity, string, time.Time) error
}

func publisherProblem(ctx context.Context, w http.ResponseWriter, operation string, err error) {
	if errors.Is(err, controlstate.ErrAuthorityConflict) {
		writeProblem(w, http.StatusConflict, controlv1.Conflict, "publisher grant already exists")
		return
	}
	if errors.Is(err, controlstate.ErrPublisherIdentity) || errors.Is(err, controlstate.ErrPublisherEnrollment) || errors.Is(err, pgx.ErrNoRows) {
		writeBearerProblem(w)
		return
	}
	writeControlStateProblem(ctx, w, operation, err)
}

func (h *handler) publisherEditor(w http.ResponseWriter, r *http.Request, team string) (PublisherIdentityStore, controlstate.Membership, string, bool) {
	store, ok := h.dependencies.PublisherIdentities, h.dependencies.PublisherIdentities != nil
	if !ok {
		writeProblem(w, 503, controlv1.Unavailable, "publisher identities are unavailable")
		return nil, controlstate.Membership{}, "", false
	}
	p, ok := h.authorizeReads(w, r)
	if !ok {
		return nil, controlstate.Membership{}, "", false
	}
	if _, ok := p.teamIDs[team]; !ok {
		writeProblem(w, 404, controlv1.NotFound, "resource not found")
		return nil, controlstate.Membership{}, "", false
	}
	i, err := store.IdentityContext(r.Context(), p.identityID)
	if err != nil {
		writeControlStateProblem(r.Context(), w, "read publisher editor", err)
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

func publisherScope(team string, domain, service *string) (controlstate.PublisherScope, bool) {
	s := controlstate.PublisherScope{TeamID: team}
	selected := 0
	for _, value := range []*string{domain, service} {
		if value != nil {
			selected++
		}
	}
	if selected != 1 {
		return s, false
	}
	if service != nil {
		s.Kind, s.ServiceID = "service", *service
		return s, opaqueid.Valid(*service, opaqueid.ServicePrefix)
	}
	s.Kind, s.DomainID = "namespace", *domain
	return s, opaqueid.Valid(*domain, opaqueid.DomainPrefix)
}

func (h *handler) CreatePublisherEnrollment(w http.ResponseWriter, r *http.Request) {
	var b controlv1.CreatePublisherEnrollmentRequest
	if !decodePublisherIssuance(w, r, &b) || !b.Kind.Valid() || !naming.ValidServiceName(b.Name) {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid publisher enrollment")
		return
	}
	s, valid := publisherScope(b.TeamId, b.DomainId, b.ServiceId)
	if !valid || s.Kind == "namespace" && !h.config.DNSAutomation {
		writeProblem(w, 400, controlv1.InvalidRequest, "select a service or an automated namespace")
		return
	}
	store, m, editor, ok := h.publisherEditor(w, r, b.TeamId)
	if !ok {
		return
	}
	request := controlstate.CreatePublisherEnrollmentRequest{Scope: s, Name: b.Name, Kind: string(b.Kind), EditorID: editor, EditorMembershipID: m.ID, PolicyRevision: uint64(m.PolicyRevision), Now: time.Now()}
	protocols, valid := publisherProtocolsInput(b.Protocols)
	if !valid || s.Kind != "service" && protocols != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "select a nonempty set of supported publisher protocols")
		return
	}
	request.Protocols = protocols
	if b.Ownership != nil {
		request.Ownership = string(*b.Ownership)
	}
	e, err := store.IssuePublisherEnrollment(r.Context(), request)
	if err != nil {
		publisherProblem(r.Context(), w, "issue publisher enrollment", err)
		return
	}
	result := controlv1.PublisherEnrollment{Id: e.ID, EnrollmentKey: e.Key, ExpiresAt: e.Until, TeamId: s.TeamID, Kind: controlv1.PublisherEnrollmentKind(s.Kind)}
	result.Protocols = publisherProtocolsResponse(e.Protocols)
	if e.Scope.ServiceID != "" {
		result.ServiceId = &e.Scope.ServiceID
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
	r.Protocols = publisherProtocolsResponse(g.Protocols)
	if g.TeamID.Valid {
		r.TeamId = g.TeamID.String
	}
	if g.GuestID.Valid {
		r.GuestId = g.GuestID.String
	}
	if g.ServiceID.Valid {
		r.ServiceId = &g.ServiceID.String
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
		publisherProblem(r.Context(), w, "list publishers", err)
		return
	}
	result := controlv1.PublisherIdentityPage{Identities: []controlv1.PublisherIdentity{}}
	for _, record := range page.Identities {
		err := store.AuthorizePublisherManagement(r.Context(), params.TeamId, record.Identity.ID, editor)
		if errors.Is(err, controlstate.ErrPublisherIdentity) || errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			publisherProblem(r.Context(), w, "authorize publisher listing", err)
			return
		}
		i := record.Identity
		p := controlv1.PublisherIdentity{Id: i.ID, Name: i.Name,
			Kind: controlv1.PublisherIdentityKind(i.Kind), CreatedAt: i.CreatedAt.Time, Grants: []controlv1.PublisherGrant{}}
		if i.TeamID.Valid {
			p.TeamId = i.TeamID.String
		}
		if i.GuestID.Valid {
			p.GuestId = i.GuestID.String
		}
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
	if !decodePublisherIssuance(w, r, &b) {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid publisher grant")
		return
	}
	s, valid := publisherScope(b.TeamId, b.DomainId, b.ServiceId)
	if !valid || s.Kind == "namespace" && !h.config.DNSAutomation {
		writeProblem(w, 400, controlv1.InvalidRequest, "select a service or an automated namespace")
		return
	}
	store, m, editor, ok := h.publisherEditor(w, r, b.TeamId)
	if !ok {
		return
	}
	if err := store.AuthorizePublisherManagement(r.Context(), b.TeamId, id, editor); err != nil {
		publisherProblem(r.Context(), w, "authorize publisher grant", err)
		return
	}
	now := time.Now()
	protocols, valid := publisherProtocolsInput(b.Protocols)
	if !valid || s.Kind != "service" && protocols != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "select a nonempty set of supported publisher protocols")
		return
	}
	grant, err := store.CreatePublisherGrant(r.Context(), controlstate.CreatePublisherGrantRequest{PublisherIdentityID: id, Scope: s, EditorID: editor, EditorMembershipID: m.ID, PolicyRevision: uint64(m.PolicyRevision), ExpiresAt: b.ExpiresAt, Now: now, Protocols: protocols})
	if err != nil {
		publisherProblem(r.Context(), w, "create publisher grant", err)
		return
	}
	// read the server-captured namespace rather than echoing request fields.
	p, err := store.PublisherIdentityRecord(r.Context(), b.TeamId, id)
	if err != nil {
		publisherProblem(r.Context(), w, "read publisher grant", err)
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

func decodePublisherIssuance(w http.ResponseWriter, r *http.Request, target any) bool {
	var raw json.RawMessage
	if decodeJSON(w, r, &raw) != nil || httpjson.Decode(json.NewDecoder(bytes.NewReader(raw)), target) != nil {
		return false
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return false
	}
	value, present := fields["protocols"]
	return !present || !bytes.Equal(bytes.TrimSpace(value), []byte("null"))
}

func publisherProtocolsInput(input *controlv1.PublisherServiceProtocols) ([]string, bool) {
	if input == nil {
		return nil, true
	}
	if len(*input) == 0 || len(*input) > 5 {
		return nil, false
	}
	result, seen := make([]string, 0, len(*input)), make(map[controlv1.ServiceProtocol]bool)
	for _, protocol := range *input {
		if !protocol.Valid() || seen[protocol] {
			return nil, false
		}
		seen[protocol] = true
		result = append(result, string(protocol))
	}
	return result, true
}

func publisherProtocolsResponse(values []string) *controlv1.PublisherServiceProtocols {
	if values == nil {
		return nil
	}
	result := make(controlv1.PublisherServiceProtocols, len(values))
	for index, value := range values {
		result[index] = controlv1.ServiceProtocol(value)
	}
	return &result
}

func (h *handler) RevokePublisherIdentity(w http.ResponseWriter, r *http.Request, id controlv1.PublisherIdentityID, params controlv1.RevokePublisherIdentityParams) {
	store, _, editor, ok := h.publisherEditor(w, r, params.TeamId)
	if !ok {
		return
	}
	if err := store.RevokePublisherIdentity(r.Context(), params.TeamId, id, editor, time.Now()); err != nil {
		publisherProblem(r.Context(), w, "revoke publisher", err)
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
		publisherProblem(r.Context(), w, "revoke publisher grant", err)
		return
	}
	w.WriteHeader(204)
}
