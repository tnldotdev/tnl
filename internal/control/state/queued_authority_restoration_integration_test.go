package state

import (
	"context"
	"crypto/sha256"
	"fmt"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/failure"
)

func TestIntegrationQueuedAuthorityRestoredDNSDefaultSaveAndRelease(t *testing.T) {
	for _, saveFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("save-first=%t", saveFirst), func(t *testing.T) {
			d, now, owner, team := newAuthorityTeam(t)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			domain, err := d.ClaimTeamDomain(ctx, ClaimDomainRequest{
				IdentityID: owner, TeamID: team.ID, IdempotencyKey: "state-b-default",
				RequestDigest: sha256.Sum256([]byte("state-b-default")), Domain: "state-b-default.example.test", MakeDefault: true,
			}, now)
			if err != nil {
				t.Fatal(err)
			}
			q := controlstatedb.New(d.pool)
			before, err := q.GetTeamActorContext(ctx,
				controlstatedb.GetTeamActorContextParams{TeamID: team.ID, IdentityID: owner})
			if err != nil || before.DefaultDomainID.String == domain.ID {
				t.Fatal("pending domain already replaced the default", err)
			}
			work, found, err := d.ClaimDNSAuthorityWork(ctx, "state-b-default", now, time.Minute)
			if err != nil || !found || work.Reference != domain.DNSAuthorityReference {
				t.Fatal("default-domain work was not claimed exactly", found, err)
			}
			original, err := q.GetDNSAuthority(ctx, work.Reference)
			if err != nil {
				t.Fatal(err)
			}
			work.State, work.ProviderZoneID, work.Nameservers = DNSAuthorityReady, "ZSTATEBDEFAULT", []string{"ns-1.example.test"}
			gate, err := d.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			if saveFirst {
				_, err = controlstatedb.New(gate).LockDNSAuthority(ctx, work.Reference)
			} else {
				_, err = controlstatedb.New(gate).LockTeamDomain(ctx,
					controlstatedb.LockTeamDomainParams{DomainID: domain.ID, TeamID: text(team.ID)})
			}
			if err != nil {
				t.Fatal(err)
			}
			saveDone, releaseDone := make(chan error, 1), make(chan error, 1)
			save := func() { _, err := d.SaveDNSAuthorityWork(ctx, work, now); saveDone <- err }
			release := func() { releaseDone <- d.ReleaseTeamDomain(ctx, owner, team.ID, domain.ID, now) }
			first, second := release, save
			firstDone, secondDone := releaseDone, saveDone
			if saveFirst {
				first, second, firstDone, secondDone = save, release, saveDone, releaseDone
			}
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			workers.Go(first)
			pid := waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), firstDone)
			workers.Go(second)
			waitForPostgresBlock(t, ctx, d, pid, secondDone)
			if err := gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			firstErr := awaitIntegrationResult(t, ctx, firstDone)
			secondErr := awaitIntegrationResult(t, ctx, secondDone)
			wantError, wantState, wantDefault := ErrDNSAuthorityWorkStale, "releasing", before.DefaultDomainID.String
			if saveFirst {
				wantError, wantState, wantDefault = ErrAuthorityConflict, "ready", domain.ID
			}
			if firstErr != nil {
				t.Error("first queued DNS operation did not win", firstErr)
			}
			if !failure.Only(secondErr, wantError) {
				t.Error("second queued DNS operation returned the wrong or an independently joined error", secondErr, wantError)
			}
			var domainState, authorityState, actualDefault string
			var consistent bool
			err = d.pool.QueryRow(ctx, `SELECT domain.state,authority.state,COALESCE(team.default_domain_id,''),
				domain.team_id=team.id AND authority.team_id=team.id AND authority.domain_id=domain.id
				AND authority.authority_reference=domain.dns_authority_reference
				AND authority.canonical_domain=domain.canonical_domain
				AND domain.authority_revision=team.policy_revision AND team.policy_revision=$2
				FROM control.domains domain JOIN control.dns_authorities authority
				ON authority.authority_reference=domain.dns_authority_reference
				JOIN control.teams team ON team.id=domain.team_id WHERE domain.id=$1`,
				domain.ID, before.PolicyRevision+1).Scan(&domainState, &authorityState, &actualDefault, &consistent)
			if err != nil || !consistent || domainState != wantState || authorityState != wantState || actualDefault != wantDefault {
				t.Fatal("domain, authority, revision, and exact default pointer disagree", domainState, authorityState, actualDefault, consistent, err)
			}
			stored, err := q.GetDNSAuthority(ctx, work.Reference)
			if err != nil || stored.WorkRevision != int64(work.WorkRevision)+1 {
				t.Fatal("losing operation changed the authority work revision", err)
			}
			wantZone, wantNameservers := original.ProviderZoneID.String, original.Nameservers
			if saveFirst {
				wantZone, wantNameservers = work.ProviderZoneID, work.Nameservers
			}
			if stored.ProviderZoneID.String != wantZone || !slices.Equal(stored.Nameservers, wantNameservers) {
				t.Fatal("losing DNS operation changed provider state")
			}
		})
	}
}

func TestIntegrationQueuedAuthorityRestoredWriterBeforeServiceOperation(t *testing.T) {
	for _, mutation := range []string{"role", "remove", "release"} {
		for _, operation := range []string{"create", "start", "configure", "delete"} {
			t.Run(mutation+"/"+operation, func(t *testing.T) {
				owner, member, domain, fixtures := sessionLockAuthorityFixtures(t)
				f := fixtures[0]
				d, now := f.database, f.now
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel()
				before, digest, err := d.GetServiceConfiguration(ctx, f.service.ID, owner)
				if err != nil || before == nil || f.service.DomainID != domain.ID {
					t.Fatal("queued authority fixture lacks its owned custom-domain declaration", err)
				}
				q := controlstatedb.New(d.pool)
				original, err := q.GetService(ctx, f.service.ID)
				if err != nil || original.DeletedAt.Valid || !original.Enabled {
					t.Fatal("queued authority fixture lacks its original live service", err)
				}
				changed := *before
				changed.Target = "http://127.0.0.1:4000"
				createPlacement := ServicePlacement{
					Reserve: true, DomainID: domain.ID, Hostname: "queued-created." + member.MemberSlug + "." + domain.CanonicalDomain,
				}
				createDeclaration := ProjectServiceConfiguration{Protocol: "http", Target: "localhost:3000"}
				var created ServiceRecord
				mutate := func() error {
					switch mutation {
					case "role":
						_, err := d.SetMembershipRole(ctx, owner, member.TeamID, member.ID, TeamRoleMember, now)
						return err
					case "remove":
						return d.RemoveMembership(ctx, owner, member.TeamID, member.ID, now)
					default:
						return d.ReleaseTeamDomain(ctx, owner, member.TeamID, domain.ID, now)
					}
				}
				operate := func() error {
					switch operation {
					case "create":
						var err error
						created, err = d.CreateServiceAt(ctx, member.TeamID, member.IdentityID, "queued-created",
							"state-b-queued-create", createPlacement, now, ServiceMetadata{}, &createDeclaration)
						return err
					case "start":
						_, err := d.StartServiceRun(ctx, f.service.ID, f.prepared.RunID, f.prepared.RunNumber, f.publisher, now)
						return err
					case "configure":
						_, err := d.ConfigureService(ctx, f.service.ID, member.IdentityID, f.service.ServiceMetadata,
							&changed, ServiceUpdateConditions{ConfigurationDigest: digest}, now)
						return err
					default:
						return d.DeleteService(ctx, f.service.ID, member.IdentityID, now)
					}
				}
				gate, err := d.pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer rollbackTestTransaction(t, gate)
				if _, err := controlstatedb.New(gate).LockService(ctx, f.service.ID); err != nil {
					t.Fatal(err)
				}
				mutationDone, operationDone := make(chan error, 1), make(chan error, 1)
				workers := newIntegrationWorkers(t, cancel)
				defer workers.stop()
				workers.Go(func() { mutationDone <- mutate() })
				writer := waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), mutationDone)
				workers.Go(func() { operationDone <- operate() })
				waitForPostgresBlock(t, ctx, d, writer, operationDone)
				if err := gate.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				mutationErr := awaitIntegrationResult(t, ctx, mutationDone)
				operationErr := awaitIntegrationResult(t, ctx, operationDone)
				var want error = ErrServiceAccess
				// current members retain their own HTTP reservation and stored
				// declaration/cleanup rights. role changes still close the
				// prepared publisher run; release permits cleanup, not new work.
				if mutation == "role" && operation != "start" || mutation == "release" && operation == "delete" {
					want = nil
				}
				if mutationErr != nil {
					t.Error("queued authority writer failed", mutationErr)
				}
				if !failure.Only(operationErr, want) {
					t.Error("queued operation did not use its exact post-mutation rights", operationErr, want)
				}
				var stored controlstatedb.ControlService
				err = d.pool.QueryRow(ctx, `SELECT id,team_id,guest_id,name,name_scope,created_by_identity_id,
					domain_id,certificate_hostname,certificate_scope,protocol,enabled,deleted_at
					FROM control.services WHERE id=$1`, f.service.ID).Scan(
					&stored.ID, &stored.TeamID, &stored.GuestID, &stored.Name, &stored.NameScope,
					&stored.CreatedByIdentityID, &stored.DomainID, &stored.CertificateHostname,
					&stored.CertificateScope, &stored.Protocol, &stored.Enabled, &stored.DeletedAt)
				deleted := operation == "delete" && want == nil
				if err != nil || stored.ID != original.ID || stored.TeamID != original.TeamID ||
					stored.GuestID != original.GuestID || stored.Name != original.Name ||
					stored.NameScope != original.NameScope || stored.CreatedByIdentityID != original.CreatedByIdentityID ||
					stored.DomainID != original.DomainID || stored.CertificateHostname != original.CertificateHostname ||
					stored.CertificateScope != original.CertificateScope || stored.Protocol != original.Protocol ||
					stored.DeletedAt.Valid != deleted ||
					deleted && (stored.Enabled || stored.DeletedAt.Time.Before(now)) {
					t.Fatal("queued cleanup result was not durable", deleted, err)
				}
				visible, err := q.GetService(ctx, f.service.ID)
				if deleted {
					if !failure.Only(err, pgx.ErrNoRows) {
						t.Fatal("deleted tombstone remained visible through the live service query", err)
					}
				} else if err != nil || visible.ID != original.ID || visible.DeletedAt.Valid {
					t.Fatal("retained live service disappeared from the live service query", err)
				}
				var closed int
				runIDs := []string{fixtures[0].prepared.RunID, fixtures[1].prepared.RunID}
				if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM control.service_runs WHERE id=ANY($1::text[])
					AND state='closed' AND closed_at IS NOT NULL AND NOT assignments_open AND started_at IS NULL`,
					runIDs).Scan(&closed); err != nil || closed != 2 {
					t.Error("writer/queued start did not retain both exact never-started closure fences", closed, err)
				}
				assertRestoredAssignmentState(t, ctx, d.pool, 0)
				if !deleted {
					after, nextDigest, err := d.GetServiceConfiguration(ctx, f.service.ID, owner)
					expected := before
					if operation == "configure" && want == nil {
						normalized, normalizeErr := normalizeServiceConfiguration(original.Name, &changed)
						if normalizeErr != nil || normalized.Target != "127.0.0.1:4000" {
							t.Fatal("queued declaration expectation did not normalize its target", normalizeErr)
						}
						expected = normalized
					}
					if err != nil || !reflect.DeepEqual(after, expected) ||
						(operation == "configure" && want == nil) == (nextDigest == digest) {
						t.Error("queued declaration edit or denial changed the wrong stored intent", err)
					}
				}
				var role string
				var removed bool
				if err := d.pool.QueryRow(ctx, `SELECT role,removed_at IS NOT NULL FROM control.team_memberships
					WHERE id=$1`, member.ID).Scan(&role, &removed); err != nil ||
					removed != (mutation == "remove") || mutation == "role" && role != string(TeamRoleMember) {
					t.Error("authority writer did not commit the intended membership state", role, removed, err)
				}
				if mutation == "release" {
					var domainState, authorityState string
					if err := d.pool.QueryRow(ctx, `SELECT domain.state,authority.state FROM control.domains domain
						JOIN control.dns_authorities authority ON authority.authority_reference=domain.dns_authority_reference
						WHERE domain.id=$1`, domain.ID).Scan(&domainState, &authorityState); err != nil ||
						domainState != "releasing" || authorityState != "releasing" || stored.Enabled {
						t.Error("domain release did not durably disable new work", domainState, authorityState, err)
					}
				}
				if operation == "create" {
					var receipts int
					if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM control.service_creation_requests
						WHERE created_by_identity_id=$1 AND idempotency_key='state-b-queued-create'`,
						member.IdentityID).Scan(&receipts); err != nil || (receipts == 1) != (want == nil) || receipts > 1 {
						t.Error("queued reservation outcome and creation receipt disagree", receipts, err)
					}
					if want == nil {
						if created.ID == "" || created.DomainID != domain.ID || created.Endpoint == nil ||
							created.Endpoint.Hostname != createPlacement.Hostname {
							t.Error("downgraded member lost its exact HTTP reservation")
						}
						var grants int
						if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM control.visitor_grants WHERE service_id=$1`,
							created.ID).Scan(&grants); err != nil || grants != 0 {
							t.Error("member reservation manufactured visitor grants", grants, err)
						}
						_, err := d.CreateServiceAt(ctx, member.TeamID, member.IdentityID, "ordinary-denied",
							"state-b-ordinary-denied", ServicePlacement{}, now, ServiceMetadata{Protocol: "http"}, nil)
						if !failure.Only(err, ErrServiceAccess) {
							t.Error("member reservation incorrectly opened administrator-only ordinary creation", err)
						}
					}
				}
				if mutation == "remove" && operation == "delete" {
					if err := d.DeleteService(ctx, f.service.ID, owner, now); err != nil {
						t.Error("removed member denial also removed the administrator's cleanup right", err)
					}
				}
			})
		}
	}
}
