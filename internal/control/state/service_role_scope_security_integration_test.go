package state

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
)

func TestIntegrationServiceRoleScopeDomainManagementMatrix(t *testing.T) {
	for _, kind := range []string{"managed", "custom"} {
		t.Run(kind, func(t *testing.T) {
			d, now, owner, team := newAuthorityTeam(t)
			admin := addAuthorityMember(t, d, now, owner, team.ID, "matrix-admin", TeamRoleAdmin)
			member := addAuthorityMember(t, d, now, owner, team.ID, "matrix-member", TeamRoleMember)
			unrelated := addAuthorityMember(t, d, now, owner, team.ID, "matrix-other", TeamRoleMember)
			foreign := "identity_matrix_foreign_owner"
			insertAuthorityIdentity(t, d, foreign, "", false, now)
			foreignRequest := authorityTeamRequest(foreign)
			foreignRequest.DisplayName = "matrix-foreign"
			foreignTeam, err := d.CreateTeam(t.Context(), foreignRequest, now)
			if err != nil || foreignTeam.ID == team.ID || foreign == owner {
				t.Fatal(err)
			}
			domains, err := d.ListTeamDomains(t.Context(), owner, team.ID)
			if err != nil || len(domains) != 1 {
				t.Fatal("fixture requires one managed domain", domains, err)
			}
			domain := domains[0]
			if kind == "custom" {
				domain = deploymentCustomDomain(t, d, ApplyProjectConfigurationRequest{TeamID: team.ID, ActorID: owner}, now)
			}
			memberNamespace, _ := naming.PublicURLNamespace(naming.NamespaceFacts{Domain: domain.CanonicalDomain, Managed: kind == "managed",
				Mode: d.managedURLMode, TeamName: team.DisplayName, MemberSlug: member.MemberSlug, ManagedLabel: team.ManagedLabel})
			sharedNamespace := naming.SharedPublicURLNamespace(domain.CanonicalDomain, kind == "managed", d.managedURLMode, team.DisplayName, team.ManagedLabel)
			for _, scope := range []string{"member", "shared"} {
				for index, actor := range []struct {
					name, id string
					manager  bool
					source   bool
				}{
					{"owner", owner, true, scope == "shared"},
					{"admin", admin.IdentityID, true, scope == "shared"},
					{"source member", member.IdentityID, scope == "member", scope == "member"},
					{"other member", unrelated.IdentityID, false, false},
					{"foreign owner", foreign, false, false},
				} {
					t.Run(scope+"/"+actor.name, func(t *testing.T) {
						name := fmt.Sprintf("%s-%d", scope, index)
						creator, namespace := admin.IdentityID, sharedNamespace
						if scope == "member" {
							creator, namespace = member.IdentityID, memberNamespace
						}
						service, err := d.CreateServiceAt(t.Context(), team.ID, creator, name, name,
							ServicePlacement{Reserve: true, DomainID: domain.ID, Hostname: name + "." + namespace},
							now, ServiceMetadata{}, &ProjectServiceConfiguration{Target: "private.internal:3000"})
						if err != nil {
							t.Fatal("create exact service source", err)
						}
						var storedScope bool
						if err := d.pool.QueryRow(t.Context(), `SELECT
							CASE WHEN $2='member' THEN membership_id=$3 AND owner_team_id IS NULL
								ELSE membership_id IS NULL AND owner_team_id=$4 END
							FROM control.service_namespace_claims WHERE namespace=$1`,
							service.Endpoint.Hostname, scope, member.ID, team.ID).Scan(&storedScope); err != nil || !storedScope {
							t.Fatal("fixture did not capture the intended member or shared source", err)
						}
						before := serviceSecuritySnapshot(t, d)
						record, err := d.GetService(t.Context(), service.ID, actor.id)
						if actor.manager {
							if err != nil || record.ID != service.ID {
								t.Fatal("authorized exact service read failed", err)
							}
						} else if !errors.Is(err, ErrServiceAccess) || record.ID != "" {
							t.Fatal("denied service read returned protected facts", err)
						}
						configuration, digest, err := d.GetServiceConfiguration(t.Context(), service.ID, actor.id)
						if actor.manager {
							if err != nil || configuration == nil || !ValidServiceConfigurationDigest(digest) {
								t.Fatal("authorized protected configuration read failed", err)
							}
						} else if !errors.Is(err, ErrServiceAccess) || configuration != nil || digest != "" {
							t.Fatal("denied configuration read exposed settings or a fingerprint", err)
						}
						if after := serviceSecuritySnapshot(t, d); !reflect.DeepEqual(after, before) {
							t.Fatal("management reads changed durable service authority")
						}
						metadata := service.ServiceMetadata
						metadata.PublisherPool = !metadata.PublisherPool
						updated, err := d.ConfigureService(t.Context(), service.ID, actor.id, metadata, nil, ServiceUpdateConditions{}, now)
						if actor.manager {
							if err != nil || updated.PublisherPool != metadata.PublisherPool {
								t.Fatal("authorized metadata update failed", err)
							}
							service = updated
						} else {
							if !errors.Is(err, ErrServiceAccess) {
								t.Fatal("unrelated actor changed service metadata", err)
							}
							if after := serviceSecuritySnapshot(t, d); !reflect.DeepEqual(after, before) {
								t.Fatal("denied metadata update persisted changes")
							}
						}
						// management of another member's metadata is not permission
						// to replace that member's target declaration.
						desired, digest, err := d.GetServiceConfiguration(t.Context(), service.ID, creator)
						if err != nil || desired == nil {
							t.Fatal(err)
						}
						desired.Target = "replacement.internal:4000"
						before = serviceSecuritySnapshot(t, d)
						_, err = d.ConfigureService(t.Context(), service.ID, actor.id, service.ServiceMetadata, desired,
							ServiceUpdateConditions{ConfigurationDigest: digest}, now)
						if actor.source {
							if err != nil {
								t.Fatal("stored source owner could not replace its declaration", err)
							}
							saved, next, err := d.GetServiceConfiguration(t.Context(), service.ID, creator)
							if err != nil || saved == nil || saved.Target != desired.Target || next == digest {
								t.Fatal("authorized replacement did not commit its exact target", err)
							}
						} else {
							if !errors.Is(err, ErrServiceAccess) {
								t.Fatal("management role bypassed declaration ownership", err)
							}
							if after := serviceSecuritySnapshot(t, d); !reflect.DeepEqual(after, before) {
								t.Fatal("denied declaration replacement persisted changes")
							}
						}
						before = serviceSecuritySnapshot(t, d)
						err = d.DeleteService(t.Context(), service.ID, actor.id, observedServiceDeletion(t, d, service.ID), now)
						if actor.manager {
							if err != nil {
								t.Fatal("authorized cleanup failed", err)
							}
							var deleted bool
							if err := d.pool.QueryRow(t.Context(), `SELECT deleted_at IS NOT NULL
								AND (SELECT count(*)=1 FROM control.service_audit_events WHERE service_id=$1 AND event_type='service.delete')
								FROM control.services WHERE id=$1`, service.ID).Scan(&deleted); err != nil || !deleted {
								t.Fatal("cleanup did not commit its tombstone and one audit", err)
							}
						} else {
							if !errors.Is(err, ErrServiceAccess) {
								t.Fatal("unrelated actor deleted the service", err)
							}
							if after := serviceSecuritySnapshot(t, d); !reflect.DeepEqual(after, before) {
								t.Fatal("denied deletion persisted changes")
							}
						}
					})
				}
			}
		})
	}
}

// snapshots include the endpoint and source claims as well as the service;
// a rejected operation must not leave a receipt, policy change, or audit.
func serviceSecuritySnapshot(t *testing.T, d *Database) map[string]string {
	t.Helper()
	return serviceSecuritySnapshotQuery(t, d.pool)
}

func serviceSecuritySnapshotQuery(t *testing.T, q controlstatedb.DBTX) map[string]string {
	t.Helper()
	result := privateOwnershipSnapshotQuery(t, q)
	for _, table := range []string{"service_endpoints", "service_namespace_claims", "service_creation_requests", "deployment_names", "visitor_policies", "visitor_policy_events", "service_port_claims", "service_recovery_episodes"} {
		var rows string
		if err := q.QueryRow(t.Context(), `SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb)::text FROM control.`+table+` r`).Scan(&rows); err != nil {
			t.Fatal(err)
		}
		result[table] = rows
	}
	return result
}
