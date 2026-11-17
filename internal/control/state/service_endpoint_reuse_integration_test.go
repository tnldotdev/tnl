package state

import (
	"errors"
	"testing"
	"time"
)

func TestIntegrationRetiredExplicitServiceHostnameTransfersDeployment(t *testing.T) {
	for _, automation := range []bool{false, true} {
		name := "unmanaged"
		if automation {
			name = "managed_dns"
		}
		t.Run(name, func(t *testing.T) {
			d, now := newControlStateIntegrationDatabase(t, "explicit_endpoint_reuse")
			r := appliedProjectRequest(t, d, now)
			domain := deploymentCustomDomain(t, d, r, now)
			hostname := "reused." + domain.CanonicalDomain
			r.ProjectKey, r.ProjectLabel, r.DNSAutomation = "old-project", "old", automation
			r.Configuration = ProjectConfiguration{Settings: &DeploymentSettings{DomainID: domain.ID}, Services: map[string]ProjectServiceConfiguration{
				"api": {Protocol: "http", Target: "localhost:3000", Public: new(true), Hostname: hostname, DomainID: domain.ID},
			}}
			r = selectedProjectRequest(r, "production")
			first, err := d.ApplyProjectConfiguration(t.Context(), r)
			if err != nil {
				t.Fatal(err)
			}
			oldDeployment := first.Deployments[0].ID
			next := r
			next.ProjectKey, next.ProjectLabel, next.ExpectedRevision = "new-project", "new", 0
			reject := func(at time.Time) {
				t.Helper()
				next.Now = at
				if _, err := d.ApplyProjectConfiguration(t.Context(), next); !errors.Is(err, ErrServiceConflict) {
					t.Fatal("unsettled hostname transferred to a distinct deployment", err)
				}
				var stillOld bool
				if err := d.pool.QueryRow(t.Context(), `SELECT deployment_id=$2 FROM control.service_namespace_claims WHERE namespace=$1`,
					hostname, oldDeployment).Scan(&stillOld); err != nil || !stillOld {
					t.Fatal("rejected takeover changed the old claim", stillOld, err)
				}
			}
			reject(now)
			retiredAt := now.Add(time.Second)
			if _, err := d.RetireProject(t.Context(), r.TeamID, r.ProjectKey, r.ActorID, first.Revision, retiredAt); err != nil {
				t.Fatal(err)
			}
			reject(retiredAt.Add(time.Second))
			at := now.Add(8 * 24 * time.Hour)
			if automation {
				reject(at)
				removal, found, err := d.ClaimServiceEndpointDNSWork(t.Context(), "retired-host-removal", at, time.Minute)
				if err != nil || !found || removal.ServiceID != first.Services[0].ServiceID || removal.State != ServiceEndpointDNSRemoving {
					t.Fatal("retired endpoint lost its DNS cleanup receipt", removal, found, err)
				}
				removal.State, removal.AvailableAt = ServiceEndpointDNSRemoved, time.Time{}
				if _, err := d.SaveServiceEndpointDNSWork(t.Context(), removal, at); err != nil {
					t.Fatal(err)
				}
			}
			var reusable, retired, dnsRemoved bool
			if err := d.pool.QueryRow(t.Context(), `SELECT control.service_namespace_reusable(claim.namespace,$2),
				claim.retired_at IS NOT NULL,endpoint.dns_state='removed'
				FROM control.service_namespace_claims claim JOIN control.service_endpoints endpoint ON endpoint.hostname=claim.namespace
				WHERE claim.namespace=$1`, hostname, at).Scan(&reusable, &retired, &dnsRemoved); err != nil || !reusable || !retired || !dnsRemoved {
				t.Fatal("predecessor is not fully reusable", reusable, retired, dnsRemoved, err)
			}
			fresh := next
			fresh.ProjectKey, fresh.ProjectLabel, fresh.Now = "fresh-project", "fresh", at
			fresh.Configuration = ProjectConfiguration{Settings: r.Configuration.Settings, Services: map[string]ProjectServiceConfiguration{
				"api": {Protocol: "http", Target: "localhost:3000", Public: new(true), Hostname: "fresh." + domain.CanonicalDomain, DomainID: domain.ID},
			}}
			control, err := d.ApplyProjectConfiguration(t.Context(), fresh)
			if err != nil || len(control.Deployments) != 1 || control.Deployments[0].ID == oldDeployment {
				t.Fatal("fresh-host distinct deployment control", err)
			}
			next.Now = at
			reused, err := d.ApplyProjectConfiguration(t.Context(), next)
			if err != nil || len(reused.Deployments) != 1 || reused.Deployments[0].ID == oldDeployment ||
				reused.Services[0].ServiceID == first.Services[0].ServiceID || reused.Services[0].Hostname != hostname {
				t.Fatal("fully retired exact hostname could not transfer", reused, err)
			}
			var transferred bool
			if err := d.pool.QueryRow(t.Context(), `SELECT claim.deployment_id=$2 AND claim.domain_id=$3 AND claim.created_at=$4
				AND claim.retired_at IS NULL AND claim.reusable_after IS NULL AND claim.local_source_key=''
				AND claim.membership_id IS NULL AND claim.owner_team_id IS NULL
				AND endpoint.deployment_id=claim.deployment_id AND endpoint.service_id=$5 AND endpoint.retired_at IS NULL
				FROM control.service_namespace_claims claim JOIN control.service_endpoints endpoint ON endpoint.hostname=claim.namespace
				WHERE claim.namespace=$1`, hostname, reused.Deployments[0].ID, domain.ID, at, reused.Services[0].ServiceID).
				Scan(&transferred); err != nil || !transferred {
				t.Fatal("reuse retained predecessor ownership or retirement fields", transferred, err)
			}
		})
	}
}
