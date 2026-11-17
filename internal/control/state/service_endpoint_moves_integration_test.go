package state

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
)

func TestIntegrationConfigureServiceEndpointKeepsConnectorAuthority(t *testing.T) {
	f := newConnectorPairFixture(t)
	service, err := f.d.GetService(f.visitor, f.run.ServiceID, f.request.Subject.IdentityID)
	if err != nil {
		t.Fatal(err)
	}
	pair := f.create(t)
	before := connectorPairSavedAuthority(t, f.d, pair.ID)
	declaration := ProjectServiceConfiguration{Protocol: "tcp", Target: "localhost:3000",
		Hostname: "moved." + service.Endpoint.Hostname, Public: new(true)}
	moved, err := f.d.ConfigureService(f.visitor, service.ID, f.request.Subject.IdentityID, service.ServiceMetadata, &declaration, ServiceUpdateConditions{UnconditionalConfiguration: true}, f.now)
	if err != nil || moved.ID != service.ID || moved.Endpoint.Hostname != declaration.Hostname || moved.Endpoint.Port == 0 ||
		!moved.Endpoint.Public || moved.TrustRevision != service.TrustRevision || moved.EndpointRevision != service.EndpointRevision+1 {
		t.Fatal("endpoint move replaced service identity or target trust", err)
	}
	if !bytes.Equal(before, connectorPairSavedAuthority(t, f.d, pair.ID)) {
		t.Fatal("endpoint move changed connector session, publisher grant, run, or connection slots")
	}
	private := declaration
	private.Public = new(false)
	disabled, err := f.d.ConfigureService(f.visitor, service.ID, f.request.Subject.IdentityID, moved.ServiceMetadata, &private, ServiceUpdateConditions{UnconditionalConfiguration: true}, f.now)
	if err != nil || disabled.Endpoint.Public || disabled.Endpoint.Port != moved.Endpoint.Port ||
		disabled.TrustRevision != moved.TrustRevision || disabled.EndpointRevision != moved.EndpointRevision+1 {
		t.Fatal("reachability edit changed trust or lost the retained reservation", err)
	}
	if !bytes.Equal(before, connectorPairSavedAuthority(t, f.d, pair.ID)) {
		t.Fatal("endpoint disablement retired authorized connector authority")
	}
	retry, err := f.d.ConfigureService(f.visitor, service.ID, f.request.Subject.IdentityID, disabled.ServiceMetadata, &private, ServiceUpdateConditions{UnconditionalConfiguration: true}, f.now)
	if err != nil || retry.EndpointRevision != disabled.EndpointRevision {
		t.Fatal("lost-response endpoint retry advanced the binding again", err)
	}
	domain := deploymentCustomDomain(t, f.d, ApplyProjectConfigurationRequest{TeamID: service.TeamID, ActorID: f.request.Subject.IdentityID}, f.now)
	var membership, source, slug string
	if err := f.d.pool.QueryRow(f.visitor, `SELECT claim.membership_id,claim.local_source_key,reservation.member_slug
	    FROM control.service_endpoints endpoint
	    JOIN control.service_namespace_claims claim ON claim.namespace=endpoint.namespace AND claim.local_source_key=endpoint.local_source_key AND claim.domain_id=endpoint.domain_id
	    JOIN control.team_memberships member ON member.id=claim.membership_id AND member.team_id=$2
	    JOIN control.member_slug_reservations reservation ON reservation.id=member.slug_reservation_id
	    WHERE endpoint.service_id=$1 AND endpoint.retired_at IS NULL AND claim.retired_at IS NULL`,
		service.ID, service.TeamID).Scan(&membership, &source, &slug); err != nil {
		t.Fatal("domain move lost its saved member owner", err)
	}
	private.DomainID, private.Hostname = domain.ID, "moved."+slug+"."+domain.CanonicalDomain
	relocated, err := f.d.ConfigureService(f.visitor, service.ID, f.request.Subject.IdentityID, disabled.ServiceMetadata, &private, ServiceUpdateConditions{UnconditionalConfiguration: true}, f.now)
	if err != nil || relocated.DomainID != domain.ID || relocated.Endpoint.Hostname != private.Hostname ||
		relocated.TrustRevision != disabled.TrustRevision || relocated.EndpointRevision != disabled.EndpointRevision+1 {
		t.Fatal("domain edit replaced service identity or target trust", err)
	}
	var retained bool
	if err := f.d.pool.QueryRow(f.visitor, `SELECT claim.membership_id=$2 AND claim.local_source_key=$3 AND claim.owner_team_id IS NULL
	    FROM control.service_endpoints endpoint
	    JOIN control.service_namespace_claims claim ON claim.namespace=endpoint.namespace AND claim.local_source_key=endpoint.local_source_key AND claim.domain_id=endpoint.domain_id
	    WHERE endpoint.service_id=$1 AND endpoint.hostname=$4 AND endpoint.retired_at IS NULL AND claim.retired_at IS NULL`,
		service.ID, membership, source, private.Hostname).Scan(&retained); err != nil || !retained {
		t.Fatal("domain edit changed the saved member owner", err)
	}
	if !bytes.Equal(before, connectorPairSavedAuthority(t, f.d, pair.ID)) {
		t.Fatal("domain edit retired authorized connector authority")
	}
	if _, err := f.d.HeartbeatServiceRun(f.visitor, f.run.ServiceID, f.run.RunID, f.run.Token, f.now,
		ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil {
		t.Fatal("endpoint changes closed an authorized connector run", err)
	}
}

func TestIntegrationServiceDeploymentMove(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "managed_group_move")
	r := appliedProjectRequest(t, d, now)
	r.Deployment = "production"
	r.ServiceDeclarations = map[string]string{"orders": "postgres", "testdb": "postgres"}
	r.Configuration = ProjectConfiguration{Settings: &DeploymentSettings{}, Services: map[string]ProjectServiceConfiguration{
		"orders": {Name: "database", Protocol: "postgres", Target: "orders.internal:5432", Access: &ProjectServiceAccess{Team: true}},
	}}
	first, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	old := first.Services[0]
	staging := r
	staging.Deployment, staging.ExpectedRevision = "staging", first.Revision
	staging.Configuration = ProjectConfiguration{Settings: &DeploymentSettings{}, Services: map[string]ProjectServiceConfiguration{
		"testdb": {Name: "database", Protocol: "postgres", Target: "staging.internal:5432"},
	}}
	second, err := d.ApplyProjectConfiguration(t.Context(), staging)
	if err != nil {
		t.Fatal(err)
	}
	grants, _, err := d.ListServiceGrants(t.Context(), old.ServiceID, r.ActorID, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.ListServiceAudit(t.Context(), r.TeamID, r.ActorID, ServiceAuditFilter{Service: "database"}, now); !errors.Is(err, serviceaudit.ErrInvalid) {
		t.Fatal("ambiguous name selected an arbitrary service", err)
	}
	// a colliding destination must roll back the complete apply.
	staging.ExpectedRevision = second.Revision
	s := r.Configuration.Services["orders"]
	staging.Configuration.Services["orders"] = s
	if _, err = d.ApplyProjectConfiguration(t.Context(), staging); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("accepted a conflicting destination", err)
	}
	current, err := d.GetProjectConfiguration(t.Context(), r.TeamID, r.ProjectKey, r.ActorID, "production")
	if err != nil || current.Revision != second.Revision || current.Services[0] != old {
		t.Fatal("failed move changed the endpoint", current, err)
	}
	delete(staging.Configuration.Services, "testdb")
	staging.Now = now.Add(time.Second)
	moved, err := d.ApplyProjectConfiguration(t.Context(), staging)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := moved.Services[0]
	if endpoint.ServiceID == old.ServiceID || endpoint.Hostname == old.Hostname || !strings.HasPrefix(endpoint.Hostname, "database.staging.") {
		t.Fatal("another deployment adopted the original identity or namespace", old, endpoint)
	}
	production, err := d.GetProjectConfiguration(t.Context(), r.TeamID, r.ProjectKey, r.ActorID, "production")
	if err != nil || len(production.Services) != 1 || production.Services[0] != old || !reflect.DeepEqual(production.Configuration, first.Configuration) {
		t.Fatal("staging replacement changed production", production, err)
	}
	after, _, err := d.ListServiceGrants(t.Context(), old.ServiceID, r.ActorID, "")
	if err != nil || len(after) != len(grants) {
		t.Fatal("move lost visitor grants", after, err)
	}
	for i, grant := range grants {
		if after[i].ID != grant.ID || after[i].RevokedAt != nil {
			t.Fatal("move replaced visitor grants", grants, after)
		}
	}
	retry, err := d.ApplyProjectConfiguration(t.Context(), staging)
	if err != nil || retry.Services[0] != endpoint || retry.Revision != moved.Revision {
		t.Fatal("move retry changed endpoint", retry, err)
	}
}
