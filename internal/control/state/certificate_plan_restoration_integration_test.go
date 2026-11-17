package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
)

type restoredCertificateEnvironment struct {
	database *Database
	now      time.Time
	actor    string
	team     Team
	member   Membership
	domain   Domain
}

func newRestoredCertificateEnvironment(t *testing.T, kind DomainKind, mode naming.ManagedURLMode, personal bool) restoredCertificateEnvironment {
	t.Helper()
	d, now := newControlStateIntegrationDatabase(t, "restored_certificate_plan")
	d.managedURLMode = mode
	session := newOIDCSession(t, d, now)
	actor := session.Identity.Identity.ID
	var team Team
	var err error
	if personal {
		team, err = d.GetTeam(t.Context(), actor, session.Identity.PersonalTeamID)
	} else {
		team, err = d.CreateTeam(t.Context(), authorityTeamRequest(actor), now)
	}
	if err != nil {
		t.Fatal(err)
	}
	members, err := d.ListTeamMemberships(t.Context(), actor, team.ID)
	if err != nil {
		t.Fatal(err)
	}
	var member Membership
	for _, candidate := range members {
		if candidate.IdentityID == actor {
			member = candidate
		}
	}
	if member.ID == "" {
		t.Fatal("certificate fixture lacks its actual owner membership")
	}
	domains, err := d.ListTeamDomains(t.Context(), actor, team.ID)
	if err != nil || len(domains) != 1 {
		t.Fatal("certificate fixture lacks its managed domain", err)
	}
	domain := domains[0]
	if kind == DomainKindCustom {
		domain = deploymentCustomDomain(t, d, ApplyProjectConfigurationRequest{TeamID: team.ID, ActorID: actor}, now)
	}
	if err := d.EnsurePrimaryIngressPool(t.Context(), "192.0.2.10", "", now); err != nil {
		t.Fatal(err)
	}
	registerTestIngress(t, d, now)
	registerCertificatePlanRelays(t, d, now)
	return restoredCertificateEnvironment{d, now, actor, team, member, domain}
}

func (e restoredCertificateEnvironment) nativeService(t *testing.T, name, hostname string, automation bool) ServiceRecord {
	t.Helper()
	service, err := e.database.CreateServiceAt(t.Context(), e.team.ID, e.actor, name, "certificate-"+name,
		ServicePlacement{DomainID: e.domain.ID, Hostname: hostname, DNSAutomation: automation}, e.now,
		ServiceMetadata{Protocol: "http"}, &ProjectServiceConfiguration{Protocol: "http", Target: "localhost:3000", Public: new(true)})
	if err != nil {
		t.Fatal("create actual native HTTP service", err)
	}
	return service
}

func (e restoredCertificateEnvironment) startNative(t *testing.T, service ServiceRecord) servicePublicationFixture {
	t.Helper()
	enrollment, err := e.database.IssuePublisherEnrollment(t.Context(),
		standaloneEnrollmentRequest(t, e.database, service, e.actor, "certificate-"+service.Name, e.now))
	if err != nil {
		t.Fatal(err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := e.database.RedeemPublisherEnrollment(t.Context(), enrollment.Key, public, e.now)
	if err != nil {
		t.Fatal(err)
	}
	f := servicePublicationFixture{database: e.database, now: e.now, service: service, publisher: publisher}
	f.start(t, "certificate-native", e.now)
	return f
}

func (e restoredCertificateEnvironment) deployment(t *testing.T, project string, automation bool, services map[string]ProjectServiceConfiguration) (AppliedProjectConfiguration, enrolledDeploymentReplica) {
	t.Helper()
	request := ApplyProjectConfigurationRequest{
		TeamID: e.team.ID, ActorID: e.actor, ProjectKey: project, ProjectLabel: project,
		SourceFingerprint: strings.Repeat("c", 64), DNSAutomation: automation, Now: e.now,
		Configuration: ProjectConfiguration{Settings: &DeploymentSettings{DomainID: e.domain.ID}, Services: services},
	}
	request = selectedProjectRequest(request, "production")
	applied, err := e.database.ApplyProjectConfiguration(t.Context(), request)
	if err != nil {
		t.Fatal("apply actual HTTP deployment", err)
	}
	enrollment, err := testDeploymentPublisherEnrollment(e.database, t.Context(), e.team.ID, project,
		"production", e.actor, 1, time.Hour, e.now)
	if err != nil {
		t.Fatal(err)
	}
	replica := enrollAppliedDeployment(t, e.database, request, enrollment, e.now)
	return applied, replica
}

func (e restoredCertificateEnvironment) startAssigned(t *testing.T, replica enrolledDeploymentReplica, name string) servicePublicationFixture {
	t.Helper()
	var assignment DeploymentPublisherServiceAssignment
	for _, candidate := range replica.assignments.Services {
		if candidate.Service == name {
			assignment = candidate
		}
	}
	if assignment.ServiceID == "" {
		t.Fatal("actual enrolled deployment lacks the requested HTTP assignment", name)
	}
	access := deploymentAssignmentAccess(t, e.database, replica, assignment, e.now)
	service, err := e.database.GetServiceForPublisher(t.Context(), assignment.ServiceID, access.PublisherIdentity, e.now)
	if err != nil {
		t.Fatal(err)
	}
	f := servicePublicationFixture{database: e.database, now: e.now, service: service, publisher: access.PublisherIdentity}
	f.start(t, "certificate-"+name, e.now)
	return f
}

func TestIntegrationCertificateRestoredTwelveCaseCapturedPlanMatrix(t *testing.T) {
	// retain all twelve historical contrasts at the transaction that now
	// captures authority. native runs get one exact host; deployment-enrolled
	// HTTP runs may share only their approved deployment namespace.
	for _, test := range []struct {
		name       string
		kind       DomainKind
		shared     bool
		automation bool
		nested     bool
		simple     bool
		personal   bool
		limited    bool
	}{
		{name: "managed_member_dns", kind: DomainKindManaged, automation: true},
		{name: "custom_member_dns", kind: DomainKindCustom, automation: true},
		{name: "managed_member_no_dns", kind: DomainKindManaged},
		{name: "custom_member_no_dns", kind: DomainKindCustom},
		{name: "shared_dns", kind: DomainKindCustom, shared: true, automation: true},
		{name: "simple_team_shared_dns", kind: DomainKindManaged, shared: true, automation: true, simple: true, personal: true},
		{name: "generated_team_shared_dns", kind: DomainKindManaged, shared: true, automation: true},
		{name: "shared_no_dns", kind: DomainKindCustom, shared: true},
		{name: "nested_managed_dns", kind: DomainKindManaged, automation: true, nested: true},
		{name: "nested_managed_manual_dns", kind: DomainKindManaged, nested: true},
		{name: "nested_custom_domain", kind: DomainKindCustom, automation: true, nested: true},
		{name: "nested_managed_limited", kind: DomainKindManaged, automation: true, nested: true, limited: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			mode := naming.ManagedURLModeGenerated
			if test.simple {
				mode = naming.ManagedURLModeSimple
			}
			e := newRestoredCertificateEnvironment(t, test.kind, mode, test.personal)
			var f servicePublicationFixture
			var want CertificatePlan
			if test.shared {
				applied, replica := e.deployment(t, "plan", test.automation, map[string]ProjectServiceConfiguration{
					"api": {Protocol: "http", Target: "localhost:3000", Public: new(true)},
				})
				if len(applied.Deployments) != 1 {
					t.Fatal("matrix lost its actual deployment namespace")
				}
				owner := naming.SharedPublicURLNamespace(e.domain.CanonicalDomain, test.kind == DomainKindManaged,
					mode, e.team.DisplayName, e.team.ManagedLabel)
				namespace := "production.plan." + owner
				if applied.Deployments[0].Namespace != namespace {
					t.Fatal("simple/generated/custom deployment naming changed", applied.Deployments[0].Namespace, namespace)
				}
				f = e.startAssigned(t, replica, "api")
				if f.service.Endpoint.Hostname != "api."+namespace {
					t.Fatal("HTTP assignment lost its exact hostname")
				}
				want = CertificatePlan{CacheKey: namespace, Scope: namespace, Identifiers: []string{"*." + namespace}, ChallengeMethod: "dns-01"}
			} else {
				namespace, direct := naming.PublicURLNamespace(naming.NamespaceFacts{
					Domain: e.domain.CanonicalDomain, Managed: test.kind == DomainKindManaged, Mode: mode,
					TeamName: e.team.DisplayName, MemberSlug: e.member.MemberSlug, ManagedLabel: e.member.ManagedLabel,
				})
				if direct {
					t.Fatal("member matrix unexpectedly selected a shared personal name")
				}
				hostname := "api." + namespace
				if test.nested {
					hostname = "api.shop." + namespace
				}
				service := e.nativeService(t, "api", hostname, test.automation)
				if test.limited {
					// the old configurable member-child-label limit is no
					// longer an input. test the actual captured authority:
					// an enrolled shallow service cannot prepare the deeper one.
					shallow := e.startNative(t, e.nativeService(t, "shallow", "first."+namespace, test.automation))
					if _, err := e.database.PrepareServiceRun(t.Context(), service.ID, shallow.publisher,
						"forbidden-deeper", e.now, ServiceRunRequest{Metadata: service.ServiceMetadata}); !errors.Is(err, ErrServiceAccess) {
						t.Fatal("shallow exact-service authority reached a deeper hostname", err)
					}
					var count int
					if err := e.database.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.service_runs WHERE service_id=$1`,
						service.ID).Scan(&count); err != nil || count != 0 {
						t.Fatal("rejected deeper preparation committed a run", err)
					}
				}
				f = e.startNative(t, service)
				want = CertificatePlan{CacheKey: hostname, Scope: hostname, Identifiers: []string{hostname}, ChallengeMethod: "dns-01"}
				var membership string
				if err := e.database.pool.QueryRow(t.Context(), `SELECT claim.membership_id
					FROM control.service_endpoints endpoint JOIN control.service_namespace_claims claim
					ON claim.namespace=endpoint.namespace AND claim.local_source_key=endpoint.local_source_key
					WHERE endpoint.service_id=$1 AND endpoint.retired_at IS NULL`, service.ID).Scan(&membership); err != nil ||
					membership != e.member.ID {
					t.Fatal("native certificate plan lost its actual member-owned hostname claim", err)
				}
			}
			if !reflect.DeepEqual(f.prepared.CertificatePlan, want) || !slices.IsSorted(want.Identifiers) ||
				f.prepared.Hostname != f.service.Endpoint.Hostname || f.prepared.DomainID != e.domain.ID ||
				f.prepared.PublisherIdentityID != f.publisher.ID || f.prepared.PublisherGrantID != f.publisher.GrantID ||
				f.prepared.PublisherKeyID != f.publisher.KeyID {
				t.Fatalf("captured certificate plan or publisher authority changed: got=%+v want=%+v", f.prepared, want)
			}
			stored, err := controlstatedb.New(e.database.pool).LockServiceRun(t.Context(),
				controlstatedb.LockServiceRunParams{ID: f.run.RunID, ServiceID: f.service.ID})
			if err != nil || stored.CertificateCacheKey != want.CacheKey || stored.CertificateScope != want.Scope ||
				!slices.Equal(stored.CertificateIdentifiers, want.Identifiers) || stored.CertificateDomainID.String != e.domain.ID ||
				stored.CertificateHostname != f.prepared.Hostname {
				t.Fatal("transaction did not persist the complete approved certificate plan", err)
			}
			var automated bool
			if err := e.database.pool.QueryRow(t.Context(), `SELECT dns_automation FROM control.service_endpoints
				WHERE service_id=$1 AND retired_at IS NULL`, f.service.ID).Scan(&automated); err != nil || automated != test.automation {
				t.Fatal("plan capture changed the selected endpoint DNS automation", err)
			}
			// plan capture is independent of issuance availability. automatic
			// cases also obtain and acknowledge a real CSR-matching signed leaf.
			if test.automation {
				work := createPlanIssuanceWork(t, e.database, e.now, f.run, f.prepared.CertificatePlan, true, nil)
				if err := e.database.MarkServiceCertificateInstalled(t.Context(), f.service.ID, f.run.RunID, f.run.Token,
					work.ID, f.run.RunNumber, *work.NotAfter, e.now); err != nil {
					t.Fatal("captured plan could not install its actual signed certificate", err)
				}
			}
		})
	}
}

func TestIntegrationCertificateRestoredNamespaceReuseRejectsForeignTeamAndDeeperHostname(t *testing.T) {
	for _, contrast := range []string{"same_team_same_plan", "different_team_rejected", "uncovered_hostname_rejected"} {
		t.Run(contrast, func(t *testing.T) {
			e := newRestoredCertificateEnvironment(t, DomainKindManaged, naming.ManagedURLModeGenerated, false)
			// all services and publisher grants are created through apply and
			// enrollment. no run is assigned a made-up namespace plan.
			owner := naming.SharedPublicURLNamespace(e.domain.CanonicalDomain, true, naming.ManagedURLModeGenerated,
				e.team.DisplayName, e.team.ManagedLabel)
			namespace := "production.reuse." + owner
			deeperHostname := "deep.second." + namespace
			_, replica := e.deployment(t, "reuse", true, map[string]ProjectServiceConfiguration{
				"first":  {Protocol: "http", Target: "localhost:3000", Public: new(true)},
				"second": {Protocol: "http", Target: "localhost:3001", Public: new(true)},
				"deeper": {Protocol: "http", Target: "localhost:3002", Hostname: deeperHostname, Public: new(true)},
			})
			first := e.startAssigned(t, replica, "first")
			want := CertificatePlan{CacheKey: namespace, Scope: namespace, Identifiers: []string{"*." + namespace}, ChallengeMethod: "dns-01"}
			if !reflect.DeepEqual(first.prepared.CertificatePlan, want) {
				t.Fatal("HTTP deployment did not approve its namespace wildcard", first.prepared.CertificatePlan)
			}
			work := createPlanIssuanceWork(t, e.database, e.now, first.run, first.prepared.CertificatePlan, true, nil)
			if err := e.database.MarkServiceCertificateInstalled(t.Context(), first.service.ID, first.run.RunID, first.run.Token,
				work.ID, first.run.RunNumber, *work.NotAfter, e.now); err != nil {
				t.Fatal("originating service install control", err)
			}
			if err := e.database.CloseServiceRun(t.Context(), first.service.ID, first.run.RunID, first.run.Token, e.now); err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode(work.CertificatePEM)
			if block == nil {
				t.Fatal("issuance fixture did not persist a signed leaf")
			}
			leaf, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			var second servicePublicationFixture
			switch contrast {
			case "same_team_same_plan":
				second = e.startAssigned(t, replica, "second")
				if !reflect.DeepEqual(second.prepared.CertificatePlan, want) ||
					second.publisher.ID != first.publisher.ID || second.service.TeamID != first.service.TeamID ||
					leaf.VerifyHostname(second.prepared.Hostname) != nil {
					t.Fatal("positive reuse control changed team, publisher, plan, or covered hostname")
				}
			case "different_team_rejected":
				team, err := e.database.CreateTeam(t.Context(), CreateTeamRequest{
					IdentityID: e.actor, DisplayName: "certificate-other", MemberSlug: "owner",
					IdempotencyKey: "certificate-other", RequestDigest: sha256.Sum256([]byte("certificate-other")),
				}, e.now)
				if err != nil {
					t.Fatal(err)
				}
				other := e
				other.team = team
				_, otherReplica := other.deployment(t, "foreign", true, map[string]ProjectServiceConfiguration{
					"second": {Protocol: "http", Target: "localhost:3001", Public: new(true)},
				})
				second = other.startAssigned(t, otherReplica, "second")
				if second.service.TeamID == first.service.TeamID || second.prepared.DomainID != first.prepared.DomainID {
					t.Fatal("foreign-team contrast did not use another team on the same managed domain")
				}
			case "uncovered_hostname_rejected":
				second = e.startAssigned(t, replica, "deeper")
				if second.prepared.Hostname != deeperHostname || second.publisher.ID != first.publisher.ID ||
					second.service.TeamID != first.service.TeamID || leaf.VerifyHostname(deeperHostname) == nil {
					t.Fatal("deeper contrast did not retain the publisher/team and an actually uncovered hostname")
				}
				if !reflect.DeepEqual(second.prepared.CertificatePlan, CertificatePlan{
					CacheKey: deeperHostname, Scope: deeperHostname, Identifiers: []string{deeperHostname}, ChallengeMethod: "dns-01",
				}) {
					t.Fatal("explicit deeper endpoint silently borrowed the shallow wildcard")
				}
			}
			queries := controlstatedb.New(e.database.pool)
			before, err := queries.LockServiceRun(t.Context(),
				controlstatedb.LockServiceRunParams{ID: second.run.RunID, ServiceID: second.service.ID})
			if err != nil {
				t.Fatal(err)
			}
			err = e.database.MarkServiceCertificateInstalled(t.Context(), second.service.ID, second.run.RunID,
				second.run.Token, work.ID, second.run.RunNumber, *work.NotAfter, e.now)
			if contrast == "same_team_same_plan" {
				if err != nil {
					t.Fatal("same publisher could not reuse its approved namespace certificate", err)
				}
				after, err := queries.LockServiceRun(t.Context(),
					controlstatedb.LockServiceRunParams{ID: second.run.RunID, ServiceID: second.service.ID})
				if err != nil || after.CertificateIssuanceID.String != work.ID || !after.CertificateExpiresAt.Time.Equal(*work.NotAfter) {
					t.Fatal("successful reuse did not persist the exact certificate and expiry", err)
				}
				state, err := e.database.HeartbeatServiceRun(t.Context(), second.service.ID, second.run.RunID, second.run.Token,
					e.now, ServiceRunHealth{Healthy: true, StreamCapacity: 64})
				if err != nil || state.State != "starting" {
					t.Fatal("cached certificate bypassed publisher connection readiness", state.State, err)
				}
			} else {
				if !errors.Is(err, ErrCertificateIssuanceInvalid) {
					t.Fatalf("%s install error=%v, want ErrCertificateIssuanceInvalid", contrast, err)
				}
				after, err := queries.LockServiceRun(t.Context(),
					controlstatedb.LockServiceRunParams{ID: second.run.RunID, ServiceID: second.service.ID})
				if err != nil || !reflect.DeepEqual(after, before) {
					t.Fatal("denied cross-service install changed the destination run", err)
				}
			}
		})
	}
}
