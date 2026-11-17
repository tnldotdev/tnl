package state

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"reflect"
	"testing"
)

func TestIntegrationAppliedServiceEndpointRejectsUnauthorizedMoveAtomically(t *testing.T) {
	for _, registered := range []bool{true, false} {
		protocol := "tcp"
		if registered {
			protocol = "http"
		}
		t.Run(protocol, func(t *testing.T) {
			f := newAppliedEndpointFixture(t, protocol, registered, true)
			ctx := t.Context()
			if _, err := f.d.pool.Exec(ctx, `UPDATE control.teams SET kind='organization' WHERE id=$1`, f.request.TeamID); err != nil {
				t.Fatal(err)
			}
			if _, err := f.d.CreateTeamInvitation(ctx,
				authorityInvitationRequest(f.request.ActorID, f.request.TeamID, "alice", f.now), f.now); err != nil {
				t.Fatal(err)
			}
			owned := appliedEndpointDomain(t, f.d, f.request.TeamID, f.request.ActorID, "other.example.test", f.now)
			foreignTeam, err := f.d.CreateTeam(ctx, CreateTeamRequest{
				IdentityID: f.request.ActorID, IdempotencyKey: "foreign-team", DisplayName: "foreign-team", MemberSlug: "owner",
				RequestDigest: sha256.Sum256([]byte("foreign-team")),
			}, f.now)
			if err != nil {
				t.Fatal(err)
			}
			foreign := appliedEndpointDomain(t, f.d, foreignTeam.ID, f.request.ActorID, "foreign.example.test", f.now)
			before, pairBefore := f.authority(t), connectorPairSavedAuthority(t, f.d, f.pair.ID)
			for _, test := range []struct {
				name, domain, hostname, deploymentDomain string
				want                                     error
			}{
				{name: "hostname outside domain", domain: f.service.DomainID, hostname: "api.foreign.example.test", want: ErrServiceAccess},
				{name: "foreign domain", domain: foreign.ID, hostname: "api.foreign.example.test", want: ErrServiceAccess},
				{name: "reserved member namespace", domain: f.service.DomainID, hostname: "preview.alice.custom.example.test", want: ErrServiceAccess},
				{name: "owned domain hostname mismatch", domain: owned.ID, hostname: f.service.Endpoint.Hostname, want: ErrServiceAccess},
				{name: "deployment authority domain", domain: f.service.DomainID, hostname: f.service.Endpoint.Hostname, deploymentDomain: owned.ID, want: ErrProjectManaged},
			} {
				t.Run(test.name, func(t *testing.T) {
					r := f.nextRequest(t)
					binding := r.Configuration.Services["api"]
					binding.DomainID, binding.Hostname = test.domain, test.hostname
					r.Configuration.Services["api"] = binding
					if test.deploymentDomain != "" {
						r.Configuration.Settings.DomainID = test.deploymentDomain
					}
					if _, err := f.d.ApplyProjectConfiguration(ctx, r); !errors.Is(err, test.want) {
						t.Fatal("endpoint/namespace authority was not enforced", err)
					}
					current, err := f.d.GetProjectConfiguration(ctx, r.TeamID, r.ProjectKey, r.ActorID, "production")
					if err != nil || current.Revision != f.applied.Revision || current.ConfigurationHash != f.applied.ConfigurationHash ||
						!reflect.DeepEqual(current.Deployments, f.applied.Deployments) ||
						!reflect.DeepEqual(current.Configuration, f.applied.Configuration) {
						t.Fatal("denied endpoint edit committed desired or namespace authority", err)
					}
					service, err := f.d.GetService(ctx, f.service.ID, r.ActorID)
					if err != nil || service.EndpointRevision != f.service.EndpointRevision ||
						service.TrustRevision != f.service.TrustRevision || service.DomainID != f.service.DomainID ||
						!reflect.DeepEqual(service.Endpoint, f.service.Endpoint) {
						t.Fatal("denied endpoint edit committed a new endpoint", err)
					}
					if !bytes.Equal(before, f.authority(t)) || !bytes.Equal(pairBefore, connectorPairSavedAuthority(t, f.d, f.pair.ID)) {
						t.Fatal("denied apply changed an actual grant, run, slot, or connector")
					}
					for _, replica := range f.replicas {
						assignments, err := f.d.GetDeploymentPublisherAssignments(ctx, replica.lease.AccessToken, r.Now)
						if err != nil || assignments.Revision != replica.assignments.Revision ||
							assignments.ConfigurationHash != replica.assignments.ConfigurationHash ||
							!bytes.Equal(appliedEndpointWorkerDefinitions(t, assignments), appliedEndpointWorkerDefinitions(t, replica.assignments)) {
							t.Fatal("denied apply changed an enrolled publication assignment", err)
						}
					}
				})
			}
		})
	}
}

func TestIntegrationAppliedServiceEndpointDomainMovePreservesAuthority(t *testing.T) {
	for _, registered := range []bool{true, false} {
		protocol := "tcp"
		if registered {
			protocol = "http"
		}
		t.Run(protocol, func(t *testing.T) {
			f := newAppliedEndpointFixture(t, protocol, registered, true)
			domain := appliedEndpointDomain(t, f.d, f.request.TeamID, f.request.ActorID, "other.example.test", f.now)
			assertAppliedEndpointMove(t, f, domain.ID, "relocated.other.example.test")
		})
	}
}
