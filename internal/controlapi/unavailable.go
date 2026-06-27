package controlapi

import (
	"net/http"

	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func unavailable(response http.ResponseWriter, _ *http.Request) {
	details := map[string]any{}
	writeJSON(response, http.StatusServiceUnavailable, controlv1.Problem{
		Type: "https://tnl.dev/problems/control_unavailable", Title: "control unavailable",
		Status: http.StatusServiceUnavailable, Code: controlv1.Unavailable, RequestId: "unavailable", Details: &details,
	})
}

type unavailableControlServer struct{}

func (unavailableControlServer) ListMaintenanceControls(w http.ResponseWriter, r *http.Request) {
	unavailable(w, r)
}
func (unavailableControlServer) SetMaintenanceControl(w http.ResponseWriter, r *http.Request, _ controlv1.MaintenanceControlName) {
	unavailable(w, r)
}
func (unavailableControlServer) ListAdminRelays(w http.ResponseWriter, r *http.Request) {
	unavailable(w, r)
}
func (unavailableControlServer) DrainAdminRelay(w http.ResponseWriter, r *http.Request, _ controlv1.RelayID) {
	unavailable(w, r)
}
func (unavailableControlServer) GetAdminServerStatus(w http.ResponseWriter, r *http.Request) {
	unavailable(w, r)
}

type unavailableAuthorityServer struct{}

func (unavailableAuthorityServer) ExchangeOIDCToken(w http.ResponseWriter, r *http.Request) {
	unavailable(w, r)
}
func (unavailableAuthorityServer) IssueAuthorization(w http.ResponseWriter, r *http.Request, _ authorityv1.IssueAuthorizationParams) {
	unavailable(w, r)
}
func (unavailableAuthorityServer) AcceptInvitation(w http.ResponseWriter, r *http.Request) {
	unavailable(w, r)
}
func (unavailableAuthorityServer) CreateTeam(w http.ResponseWriter, r *http.Request, _ authorityv1.CreateTeamParams) {
	unavailable(w, r)
}
func (unavailableAuthorityServer) ClaimTeamDomain(w http.ResponseWriter, r *http.Request, _ authorityv1.TeamID, _ authorityv1.ClaimTeamDomainParams) {
	unavailable(w, r)
}
func (unavailableAuthorityServer) ReleaseTeamDomain(w http.ResponseWriter, r *http.Request, _ authorityv1.TeamID, _ authorityv1.DomainID) {
	unavailable(w, r)
}
func (unavailableAuthorityServer) SetTeamDefaultDomain(w http.ResponseWriter, r *http.Request, _ authorityv1.TeamID, _ authorityv1.DomainID) {
	unavailable(w, r)
}
func (unavailableAuthorityServer) ListTeamInvitations(w http.ResponseWriter, r *http.Request, _ authorityv1.TeamID) {
	unavailable(w, r)
}
func (unavailableAuthorityServer) CreateTeamInvitation(w http.ResponseWriter, r *http.Request, _ authorityv1.TeamID, _ authorityv1.CreateTeamInvitationParams) {
	unavailable(w, r)
}
func (unavailableAuthorityServer) RevokeTeamInvitation(w http.ResponseWriter, r *http.Request, _ authorityv1.TeamID, _ authorityv1.InvitationID) {
	unavailable(w, r)
}
func (unavailableAuthorityServer) ListTeamMemberships(w http.ResponseWriter, r *http.Request, _ authorityv1.TeamID) {
	unavailable(w, r)
}
func (unavailableAuthorityServer) RemoveMembership(w http.ResponseWriter, r *http.Request, _ authorityv1.TeamID, _ authorityv1.MembershipID) {
	unavailable(w, r)
}
func (unavailableAuthorityServer) SetMembershipRole(w http.ResponseWriter, r *http.Request, _ authorityv1.TeamID, _ authorityv1.MembershipID) {
	unavailable(w, r)
}
