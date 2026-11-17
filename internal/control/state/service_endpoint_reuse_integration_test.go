package state

import (
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming"
)

func TestIntegrationRetiredExplicitServiceHostnameTransfersDeployment(t *testing.T) {
	for _, test := range []struct {
		name                 string
		automation, explicit bool
	}{
		{"unmanaged", false, true},
		{"managed_dns", true, true},
		{"default_unmanaged", false, false},
		{"default_managed_dns", true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			d, now := newControlStateIntegrationDatabase(t, "explicit_endpoint_reuse")
			r := appliedProjectRequest(t, d, now)
			domain := deploymentCustomDomain(t, d, r, now)
			declaration := ProjectServiceConfiguration{Protocol: "http", Target: "localhost:3000", Public: new(true), DomainID: domain.ID}
			if test.explicit {
				declaration.Hostname = "reused." + domain.CanonicalDomain
			}
			r.ProjectKey, r.ProjectLabel, r.DNSAutomation = "old-project", "old", test.automation
			r.Configuration = ProjectConfiguration{Settings: &DeploymentSettings{DomainID: domain.ID}, Services: map[string]ProjectServiceConfiguration{
				"api": declaration,
			}}
			r = selectedProjectRequest(r, "production")
			first, err := d.ApplyProjectConfiguration(t.Context(), r)
			if err != nil {
				t.Fatal(err)
			}
			oldDeployment := first.Deployments[0].ID
			hostname := first.Services[0].Hostname
			var oldNamespace string
			if err := d.pool.QueryRow(t.Context(), `SELECT namespace FROM control.service_endpoints WHERE hostname=$1`, hostname).Scan(&oldNamespace); err != nil {
				t.Fatal(err)
			}
			next := r
			next.ProjectKey, next.ProjectLabel, next.ExpectedRevision = "new-project", "new", 0
			declaration.Hostname = hostname
			next.Configuration = ProjectConfiguration{Settings: r.Configuration.Settings, Services: map[string]ProjectServiceConfiguration{"api": declaration}}
			reject := func(at time.Time) {
				t.Helper()
				next.Now = at
				if _, err := d.ApplyProjectConfiguration(t.Context(), next); !errors.Is(err, ErrServiceConflict) {
					t.Fatal("unsettled hostname transferred to a distinct deployment", err)
				}
				var stillOld bool
				if err := d.pool.QueryRow(t.Context(), `SELECT deployment_id=$2 FROM control.service_namespace_claims WHERE namespace=$1`,
					oldNamespace, oldDeployment).Scan(&stillOld); err != nil || !stillOld {
					t.Fatal("rejected takeover changed the old claim", stillOld, err)
				}
				if !test.explicit {
					var rolledBack bool
					if err := d.pool.QueryRow(t.Context(), `SELECT NOT EXISTS(SELECT 1 FROM control.service_namespace_claims WHERE namespace=$1)`,
						hostname).Scan(&rolledBack); err != nil || !rolledBack {
						t.Fatal("rejected takeover retained a new exact-host claim", rolledBack, err)
					}
				}
			}
			reject(now)
			retiredAt := now.Add(time.Second)
			if _, err := d.RetireProject(t.Context(), r.TeamID, r.ProjectKey, r.ActorID, first.Revision, retiredAt); err != nil {
				t.Fatal(err)
			}
			reject(retiredAt.Add(time.Second))
			at := now.Add(8 * 24 * time.Hour)
			if test.automation {
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
				FROM control.service_namespace_claims claim JOIN control.service_endpoints endpoint ON endpoint.namespace=claim.namespace
				WHERE claim.namespace=$3 AND endpoint.hostname=$1`, hostname, at, oldNamespace).Scan(&reusable, &retired, &dnsRemoved); err != nil || !reusable || !retired || !dnsRemoved {
				t.Fatal("predecessor is not fully reusable", reusable, retired, dnsRemoved, err)
			}
			var oldClaim string
			if err := d.pool.QueryRow(t.Context(), `SELECT to_jsonb(claim)::text FROM control.service_namespace_claims claim WHERE namespace=$1`,
				oldNamespace).Scan(&oldClaim); err != nil {
				t.Fatal(err)
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
				AND endpoint.namespace=claim.namespace
				FROM control.service_namespace_claims claim JOIN control.service_endpoints endpoint ON endpoint.hostname=claim.namespace
				WHERE claim.namespace=$1`, hostname, reused.Deployments[0].ID, domain.ID, at, reused.Services[0].ServiceID).
				Scan(&transferred); err != nil || !transferred {
				t.Fatal("reuse retained predecessor ownership or retirement fields", transferred, err)
			}
			if !test.explicit {
				var retained string
				if err := d.pool.QueryRow(t.Context(), `SELECT to_jsonb(claim)::text FROM control.service_namespace_claims claim WHERE namespace=$1`,
					oldNamespace).Scan(&retained); err != nil || retained != oldClaim {
					t.Fatal("exact-host reuse transferred or rewrote the old broader namespace", retained, err)
				}
			}
		})
	}
}

func TestIntegrationRetiredDefaultHostnameKeepsSiblingCertificateFence(t *testing.T) {
	e := newRestoredCertificateEnvironment(t, DomainKindCustom, naming.ManagedURLModeGenerated, false)
	applied, _ := e.deployment(t, "old", false, map[string]ProjectServiceConfiguration{
		"api":   {Protocol: "http", Target: "localhost:3000", Public: new(true)},
		"other": {Protocol: "http", Target: "localhost:3001", Public: new(true)},
	})
	scope := DeploymentScope{TeamID: e.team.ID, ProjectKey: "old", ActorID: e.actor}
	registration, key := managementRegistration(t, scope, e.now)
	registration.Permissions = map[string][]string{"publish": {"other"}}
	registration.AllDeployments, registration.DeploymentIDs = false, []string{applied.Deployments[0].ID}
	credential, err := e.database.RegisterDeploymentCredential(t.Context(), registration)
	if err != nil {
		t.Fatal(err)
	}
	access := managementAccess(t, e.database, credential, key, e.now)
	service, err := e.database.GetDeploymentPublication(t.Context(), DeploymentScope{
		TeamID: e.team.ID, ProjectKey: "old", AccessToken: access.Token,
	}, "production", "other", e.now)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := e.database.PrepareServiceRun(t.Context(), service.ID, access.PublisherIdentity, "sibling-certificate", e.now, ServiceRunRequest{Metadata: service.ServiceMetadata})
	if err != nil {
		t.Fatal(err)
	}
	run, err := e.database.StartServiceRun(t.Context(), service.ID, prepared.RunID, prepared.RunNumber, access.PublisherIdentity, e.now)
	if err != nil {
		t.Fatal(err)
	}
	oldNamespace := applied.Deployments[0].Namespace
	if prepared.CertificatePlan.Scope == oldNamespace || prepared.CertificatePlan.Scope != service.Endpoint.Hostname {
		t.Fatal("sibling certificate did not capture its independent exact-host scope")
	}
	installPrivateTestCertificate(t, e.database, prepared, run, e.now, 10*24*time.Hour)
	var hostname string
	if err := e.database.pool.QueryRow(t.Context(), `SELECT certificate_hostname FROM control.services
		WHERE id=(SELECT service_id FROM control.applied_project_services WHERE deployment_id=$1 AND service='api')`,
		applied.Deployments[0].ID).Scan(&hostname); err != nil {
		t.Fatal(err)
	}
	if _, err := e.database.RetireProject(t.Context(), e.team.ID, "old", e.actor, applied.Revision, e.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	at := e.now.Add(8 * 24 * time.Hour)
	var endpointSettled, claimSettled, reusable bool
	if err := e.database.pool.QueryRow(t.Context(), `SELECT endpoint.retired_at IS NOT NULL AND endpoint.dns_state='removed' AND endpoint.reusable_after<=$3,
		claim.retired_at IS NOT NULL AND claim.reusable_after<=$3,control.service_namespace_reusable(claim.namespace,$3)
		FROM control.service_endpoints endpoint JOIN control.service_namespace_claims claim ON claim.namespace=endpoint.namespace
		WHERE endpoint.hostname=$1 AND claim.namespace=$2`, hostname, oldNamespace, at).
		Scan(&endpointSettled, &claimSettled, &reusable); err != nil || !endpointSettled || !claimSettled || reusable {
		t.Fatal("fixture failed to isolate the sibling's issued certificate beyond both quarantine deadlines", endpointSettled, claimSettled, reusable, err)
	}
	request := appliedCertificateRequest(e, "new", applied, at)
	request.ExpectedRevision = 0
	request.Configuration = ProjectConfiguration{Settings: &DeploymentSettings{DomainID: e.domain.ID}, Services: map[string]ProjectServiceConfiguration{
		"api": {Protocol: "http", Target: "localhost:3000", Public: new(true), Hostname: hostname, DomainID: e.domain.ID},
	}}
	if _, err := e.database.ApplyProjectConfiguration(t.Context(), request); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("exact-host handoff bypassed its old namespace's outstanding sibling certificate", err)
	}
	request.Now = e.now.Add(11 * 24 * time.Hour)
	if err := e.database.pool.QueryRow(t.Context(), `SELECT control.service_namespace_reusable($1,$2)`,
		oldNamespace, request.Now).Scan(&reusable); err != nil || !reusable {
		t.Fatal("old namespace did not settle after actual sibling certificate expiry", reusable, err)
	}
	if _, err := e.database.ApplyProjectConfiguration(t.Context(), request); err != nil {
		t.Fatal("exact-host handoff stayed blocked after all old namespace authority expired", err)
	}
}
