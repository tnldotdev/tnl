package state

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationMemberReservationReceiptsCASAndHTTPOnlyVisitorOwnership(t *testing.T) {
	d, now, administrator, team := newAuthorityTeam(t)
	_, member := allocationVisitorMember(t, d, team.ID, administrator, "reservation-member", TeamRoleMember, now)
	other := addAuthorityMember(t, d, now, administrator, team.ID, "other-reserver", TeamRoleMember)
	domain := deploymentCustomDomain(t, d, ApplyProjectConfigurationRequest{TeamID: team.ID, ActorID: administrator}, now)
	placement := ServicePlacement{Reserve: true, DomainID: domain.ID, Hostname: "preview." + member.MemberSlug + ".custom.example.test"}
	declaration := &ProjectServiceConfiguration{Protocol: "http", Target: "app", Public: new(true)}
	create := func(key string, desired *ProjectServiceConfiguration) (ServiceRecord, error) {
		return d.CreateServiceAt(t.Context(), team.ID, member.IdentityID, "preview", key, placement, now, ServiceMetadata{}, desired)
	}
	first, err := create("first", declaration)
	if err != nil || first.Recovered || first.Endpoint == nil || first.Endpoint.Hostname != placement.Hostname {
		t.Fatal("member could not create the exact authorized service", first, err)
	}
	q := controlstatedb.New(d.pool)
	before, err := q.GetServiceConfiguration(t.Context(), first.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"first", "second"} {
		recovered, err := create(key, declaration)
		if err != nil || !recovered.Recovered || recovered.ID != first.ID || recovered.EndpointRevision != first.EndpointRevision {
			t.Fatal("same-key or different-key reservation did not recover the exact lifetime", recovered, err)
		}
	}
	after, err := q.GetServiceConfiguration(t.Context(), first.ID)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("recovery rewrote encrypted intent", err)
	}
	changed := *declaration
	changed.Target = "ignored-on-recovery.internal:8080"
	recovered, err := create("third", &changed)
	if err != nil || recovered.ID != first.ID {
		t.Fatal("new-key recovery could not retain current intent", recovered, err)
	}
	saved, digest, err := d.GetServiceConfiguration(t.Context(), first.ID, member.IdentityID)
	if err != nil || saved == nil || saved.Target != "app" {
		t.Fatal("recovery applied the creation declaration as an update", saved, err)
	}
	if _, err := create("third", declaration); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("a recovery receipt did not bind its original request", err)
	}
	desired := *saved
	desired.Target = "approved.internal:8080"
	updated, err := d.ConfigureService(t.Context(), first.ID, member.IdentityID, first.ServiceMetadata, &desired,
		ServiceUpdateConditions{ConfigurationDigest: digest}, now)
	if err != nil || updated.ID != first.ID {
		t.Fatal("member could not configure the same service through ordinary CAS", updated, err)
	}
	if _, err := d.ConfigureService(t.Context(), first.ID, member.IdentityID, updated.ServiceMetadata, saved,
		ServiceUpdateConditions{ConfigurationDigest: digest}, now); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("stale configuration digest overwrote current intent", err)
	}
	recovered, err = create("first", declaration)
	if err != nil || recovered.ID != first.ID {
		t.Fatal("uncertain original creation could not recover after a later configuration edit", recovered, err)
	}
	if saved, _, err := d.GetServiceConfiguration(t.Context(), first.ID, member.IdentityID); err != nil || saved.Target != desired.Target {
		t.Fatal("original receipt reset later approved configuration", saved, err)
	}
	if _, _, err := d.ListServices(t.Context(), team.ID, member.IdentityID, ""); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("reservation opened team inventory", err)
	}
	if _, err := d.CreateServiceAt(t.Context(), team.ID, member.IdentityID, "ordinary", "ordinary", ServicePlacement{}, now, ServiceMetadata{Protocol: "http"}, nil); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("reservation opened ordinary team creation", err)
	}
	var grants int
	if err := d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.visitor_grants WHERE service_id=$1`, first.ID).Scan(&grants); err != nil || grants != 0 {
		t.Fatal("member reservation manufactured a connector visitor grant", grants, err)
	}
	if _, err := q.VisitorPermission(t.Context(), controlstatedb.VisitorPermissionParams{
		ResourceKind: "service", ResourceID: first.ID, IdentityID: member.IdentityID, Now: timestamptz(now),
	}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("stored HTTP ownership became generic connector permission", err)
	}
	tx, err := d.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, tx)
	permission, err := d.serviceHTTPIdentityPermission(t.Context(), tx, first.ID, member.IdentityID, now)
	if err != nil || !permission.VisitAllowed || permission.Reason != "owner" {
		t.Fatal("own-namespace HTTP browser permission was not restored", permission, err)
	}
	unrelated, err := d.serviceHTTPIdentityPermission(t.Context(), tx, first.ID, other.IdentityID, now)
	if err != nil || unrelated.VisitAllowed {
		t.Fatal("HTTP ownership became team-wide visitor access", unrelated, err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	var receiptCount int
	if err := d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.service_creation_requests WHERE service_id=$1`, first.ID).Scan(&receiptCount); err != nil || receiptCount != 3 {
		t.Fatal("reservation did not retain its exact operation receipts", receiptCount, err)
	}
	current, err := q.GetServiceConfiguration(t.Context(), first.ID)
	if err != nil || bytes.Equal(before.ConfigurationCiphertext, current.ConfigurationCiphertext) {
		t.Fatal("CAS did not persist the approved replacement", err)
	}
}

func TestIntegrationMemberReservationRejectsForeignNamespaceAndNativeCreation(t *testing.T) {
	d, now, administrator, team := newAuthorityTeam(t)
	member := addAuthorityMember(t, d, now, administrator, team.ID, "reservation-member", TeamRoleMember)
	domain := deploymentCustomDomain(t, d, ApplyProjectConfigurationRequest{TeamID: team.ID, ActorID: administrator}, now)
	for _, test := range []struct {
		name, hostname, protocol string
		worktree                 string
	}{
		{"shared", "shared.custom.example.test", "http", ""},
		{"other membership", "app.owner.custom.example.test", "http", ""},
		{"namespace apex", "reservation-member.custom.example.test", "http", ""},
		{"foreign domain", "app.other.example.test", "http", ""},
		{"worktree", "app.reservation-member.custom.example.test", "http", "checkout"},
		{"native", "db.reservation-member.custom.example.test", "postgres", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := d.CreateServiceAt(t.Context(), team.ID, member.IdentityID, "denied", test.name,
				ServicePlacement{Reserve: true, DomainID: domain.ID, Hostname: test.hostname, WorktreeKey: test.worktree}, now,
				ServiceMetadata{}, &ProjectServiceConfiguration{Protocol: test.protocol, Target: "app"})
			if !errors.Is(err, ErrServiceAccess) && !errors.Is(err, ErrProjectConfigurationInvalid) {
				t.Fatal("reservation accepted an unauthorized namespace, association, or native creation", err)
			}
		})
	}
	var count int
	if err := d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.services WHERE team_id=$1`, team.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("denied reservation left a service", count, err)
	}
}

func TestIntegrationExactReservationRejectsAllocationAndLocalAppAssociations(t *testing.T) {
	f := newServiceManagementFixture(t)
	ctx := t.Context()
	for _, service := range []ServiceRecord{f.allocation} {
		if _, err := f.d.CreateServiceAt(ctx, f.team, f.member.IdentityID, service.Name, "allocation-adoption",
			ServicePlacement{Reserve: true, DomainID: service.DomainID, Hostname: service.Endpoint.Hostname}, f.now,
			ServiceMetadata{}, &ProjectServiceConfiguration{Protocol: "http", Target: "app"}); err == nil {
			t.Fatal("exact reservation adopted a real namespace allocation")
		}
	}
	local, err := f.d.RealizeLocalProjectService(ctx, RealizeLocalProjectServiceRequest{
		TeamID: f.team, ProjectKey: "reserved-local", SourceFingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Service: "web", WorktreeKey: "checkout", ActorID: f.owner, Now: f.now,
		Configuration: ProjectServiceConfiguration{Target: "app", Public: new(true)},
	})
	if err != nil {
		t.Fatal(err)
	}
	saved, err := f.d.GetService(ctx, local.ServiceID, f.owner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.d.CreateServiceAt(ctx, f.team, f.owner, saved.Name, "local-adoption",
		ServicePlacement{Reserve: true, DomainID: saved.DomainID, Hostname: saved.Endpoint.Hostname}, f.now,
		ServiceMetadata{}, &ProjectServiceConfiguration{Protocol: "http", Target: "app"}); err == nil {
		t.Fatal("administrator exact reservation adopted a local-app source")
	}
}

func TestIntegrationMemberReservationScopesServiceNames(t *testing.T) {
	for _, secondName := range []string{"preview-b", "preview"} {
		t.Run(secondName, func(t *testing.T) {
			d, now, administrator, team := newAuthorityTeam(t)
			aliceSession, alice := allocationVisitorMember(t, d, team.ID, administrator, "alice", TeamRoleMember, now)
			bobSession, bob := allocationVisitorMember(t, d, team.ID, administrator, "bob", TeamRoleMember, now)
			domain := deploymentCustomDomain(t, d, ApplyProjectConfigurationRequest{TeamID: team.ID, ActorID: administrator}, now)
			declaration := &ProjectServiceConfiguration{Protocol: "http", Target: "app", Public: new(true)}
			var first ServiceRecord
			for i, input := range []struct {
				session ControlSession
				member  Membership
				name    string
			}{{aliceSession, alice, "preview"}, {bobSession, bob, secondName}} {
				if input.member.Role != TeamRoleMember {
					t.Fatal("reservation fixture requires ordinary members")
				}
				hostname := "preview." + input.member.MemberSlug + "." + domain.CanonicalDomain
				placement := ServicePlacement{Reserve: true, DomainID: domain.ID, Hostname: hostname}
				ctx := WithControlPrincipal(t.Context(), ControlPrincipal{IdentityID: input.member.IdentityID, SessionID: input.session.SessionID})
				saved, err := d.CreateServiceAt(ctx, team.ID, input.member.IdentityID, input.name, "member-reserve-"+input.member.MemberSlug,
					placement, now, ServiceMetadata{}, declaration)
				if err != nil || saved.ID == "" || saved.Recovered || saved.Endpoint == nil || saved.Endpoint.Hostname != hostname {
					t.Fatal("ordinary member could not reserve a scoped service name", saved, err)
				}
				if i == 0 {
					first = saved
					continue
				}
				if saved.ID == first.ID {
					t.Fatal("same-name reservation adopted another member's service")
				}
				// a new operation still recovers only this member's exact service.
				recovered, err := d.CreateServiceAt(ctx, team.ID, input.member.IdentityID, input.name, "member-recover-"+input.member.MemberSlug,
					placement, now, ServiceMetadata{}, declaration)
				if err != nil || !recovered.Recovered || recovered.ID != saved.ID {
					t.Fatal("scoped reservation failed exact recovery", recovered, err)
				}
				placement.Hostname = "other." + input.member.MemberSlug + "." + domain.CanonicalDomain
				if _, err := d.CreateServiceAt(ctx, team.ID, input.member.IdentityID, input.name, "same-scope-other-host",
					placement, now, ServiceMetadata{}, declaration); !errors.Is(err, ErrServiceConflict) {
					t.Fatal("reservation allowed a duplicate name in the same scope", err)
				}
				candidates, err := controlstatedb.New(d.pool).ListServiceReservationCandidates(ctx, controlstatedb.ListServiceReservationCandidatesParams{
					TeamID: text(team.ID), Name: "different-name", NameScope: "member/" + input.member.IdentityID + "/", Hostname: first.Endpoint.Hostname,
				})
				if err != nil || len(candidates) != 1 || candidates[0].ID != first.ID {
					t.Fatal("scoped name filtering removed the exact-host ownership fence", candidates, err)
				}
				placement.Hostname = first.Endpoint.Hostname
				if _, err := d.CreateServiceAt(ctx, team.ID, input.member.IdentityID, "different-name", "foreign-exact-host",
					placement, now, ServiceMetadata{}, declaration); err == nil {
					t.Fatal("reservation adopted another member's exact hostname")
				}
			}
		})
	}
}
