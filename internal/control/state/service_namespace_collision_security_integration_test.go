package state

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/naming"
)

func TestIntegrationServiceDeploymentNamespaceCollisionBothOrders(t *testing.T) {
	for _, kind := range []string{"managed", "custom"} {
		for _, first := range []string{"service", "deployment"} {
			for _, prefix := range []string{"", "web.", "other.", "deep.web."} {
				t.Run(kind+"/"+first+"/"+prefix, func(t *testing.T) {
					d, now, owner, team := newAuthorityTeam(t)
					// the hosted mode reserves the branch before any service
					// exists. this test retains both collision orders on a
					// self-hosted domain where the branch is not reserved.
					d.managedURLMode = naming.ManagedURLModeSimple
					domains, err := d.ListTeamDomains(t.Context(), owner, team.ID)
					if err != nil || len(domains) != 1 {
						t.Fatal(err)
					}
					domain := domains[0]
					if kind == "custom" {
						domain = deploymentCustomDomain(t, d, ApplyProjectConfigurationRequest{TeamID: team.ID, ActorID: owner}, now)
					}
					shared := naming.SharedPublicURLNamespace(domain.CanonicalDomain, kind == "managed", d.managedURLMode, team.DisplayName, team.ManagedLabel)
					namespace, err := naming.DeploymentNamespace("production", "shop", shared)
					if err != nil {
						t.Fatal(err)
					}
					request := selectedProjectRequest(ApplyProjectConfigurationRequest{
						TeamID: team.ID, ActorID: owner, ProjectKey: "collision", ProjectLabel: "shop",
						SourceFingerprint: strings.Repeat("a", 64), Now: now,
						Configuration: ProjectConfiguration{Settings: &DeploymentSettings{DomainID: domain.ID},
							Services: map[string]ProjectServiceConfiguration{"web": {Target: "deployment.internal:3000"}}},
					}, "production")
					create := func(hostname, key string) error {
						_, err := d.CreateServiceAt(t.Context(), team.ID, owner, key, key,
							ServicePlacement{DomainID: domain.ID, Hostname: hostname}, now,
							ServiceMetadata{}, &ProjectServiceConfiguration{Target: "standalone.internal:3000"})
						return err
					}
					apply := func() error {
						applied, err := d.ApplyProjectConfiguration(t.Context(), request)
						if err == nil && (len(applied.Deployments) != 1 || applied.Deployments[0].Namespace != namespace) {
							t.Fatal("deployment fixture did not claim the intended namespace")
						}
						return err
					}
					initial, conflicting := apply, func() error { return create(prefix+namespace, "collision") }
					if first == "service" {
						initial, conflicting = conflicting, apply
					}
					if err := initial(); err != nil {
						t.Fatal("initial source could not claim its namespace", err)
					}
					before := serviceSecuritySnapshot(t, d)
					if err := conflicting(); !errors.Is(err, ErrServiceConflict) {
						t.Fatal("a different source adopted an exact or descendant namespace", err)
					}
					if after := serviceSecuritySnapshot(t, d); !reflect.DeepEqual(after, before) {
						t.Fatal("collision changed services, deployment, endpoint, source claim, receipt, or audit")
					}
					// a lexical suffix without the DNS-label boundary is a
					// different namespace, not a conflicting descendant.
					if err := create("not"+namespace, "independent"); err != nil {
						t.Fatal("namespace collision check rejected an independent sibling", err)
					}
				})
			}
		}
	}
}
