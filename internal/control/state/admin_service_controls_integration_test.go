package state

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func setServiceMaintenance(t *testing.T, d *Database, actor string, name MaintenanceControlName, allowed bool, now time.Time) {
	t.Helper()
	if _, err := d.SetMaintenanceControl(t.Context(), name, allowed, actor, mustOpaqueID(t, opaqueid.RequestPrefix), now); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationServiceCreationMaintenanceCoversInsertionOwners(t *testing.T) {
	for _, owner := range []string{"standalone", "local", "apply", "deployment", "namespace", "temporary"} {
		t.Run(owner, func(t *testing.T) {
			var d *Database
			var now time.Time
			var actor string
			var create func(string) (string, error)
			if owner == "temporary" {
				f := newDeploymentPublicationFixture(t)
				d, now, actor = f.d, f.now, f.project.ActorID
				_, _, access, _ := f.approve(t, nil, "restricted")
				requests := map[string]AllocateDeploymentPublicationRequest{
					"original": f.allocation(t, access), "new": f.allocation(t, access),
				}
				create = func(key string) (string, error) {
					service, err := d.AllocateDeploymentPublication(t.Context(), requests[key])
					return service.ID, err
				}
			} else {
				d, now = newControlStateIntegrationDatabase(t, "admin_creation_"+owner)
				r := appliedProjectRequest(t, d, now)
				actor = r.ActorID
				switch owner {
				case "standalone":
					create = func(key string) (string, error) {
						service, err := d.CreateServiceAt(t.Context(), r.TeamID, r.ActorID, key, key, ServicePlacement{}, now, ServiceMetadata{Protocol: "tcp"}, nil)
						return service.ID, err
					}
				case "local":
					create = func(key string) (string, error) {
						service, err := d.RealizeLocalProjectService(t.Context(), RealizeLocalProjectServiceRequest{
							TeamID: r.TeamID, ActorID: r.ActorID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint,
							Service: "web", WorktreeKey: key, Configuration: r.Configuration.Services["web"], Now: now,
						})
						return service.ServiceID, err
					}
				case "apply":
					create = func(key string) (string, error) {
						request := selectedProjectRequest(r, "production")
						request.ProjectKey = key
						applied, err := d.ApplyProjectConfiguration(t.Context(), request)
						if err != nil {
							return "", err
						}
						return applied.Services[0].ServiceID, nil
					}
				case "deployment":
					if _, err := d.ApplyProjectConfiguration(t.Context(), selectedProjectRequest(r, "production")); err != nil {
						t.Fatal(err)
					}
					create = func(key string) (string, error) {
						deployment, err := d.CreateDeployment(t.Context(), CreateDeploymentRequest{
							DeploymentScope: DeploymentScope{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID},
							Name:            key, IdempotencyKey: key, Targets: map[string]DeploymentTarget{"web": {Address: "localhost:3000"}}, Now: now,
						})
						if err != nil {
							return "", err
						}
						return deployment.Services["web"].ID, nil
					}
				case "namespace":
					domain, err := controlstatedb.New(d.pool).FindManagedDomain(t.Context())
					if err != nil {
						t.Fatal(err)
					}
					scope := PublisherScope{TeamID: r.TeamID, Kind: "namespace", DomainID: domain.ID}
					enrollment := publisherEnrollment(t, d, CreatePublicURLRequest{TeamID: r.TeamID, ActingIdentityID: r.ActorID, DomainID: domain.ID}, scope, now)
					public, _, err := ed25519.GenerateKey(rand.Reader)
					if err != nil {
						t.Fatal(err)
					}
					publisher, err := d.RedeemPublisherEnrollment(t.Context(), enrollment.Key, public, now)
					if err != nil {
						t.Fatal(err)
					}
					invocations := map[string]string{"original": mustOpaqueID(t, opaqueid.InvocationPrefix), "new": mustOpaqueID(t, opaqueid.InvocationPrefix)}
					create = func(key string) (string, error) {
						service, err := d.AllocatePublisherService(t.Context(), publisher, AllocateServiceRequest{
							Invocation: invocations[key], Configuration: ProjectServiceConfiguration{Target: "localhost:3000"},
						}, now)
						return service.ID, err
					}
				}
			}
			original, err := create("original")
			if err != nil || original == "" {
				t.Fatal("initial service creation failed", err)
			}
			setServiceMaintenance(t, d, actor, MaintenanceControlServiceCreation, false, now)
			recovered, err := create("original")
			if err != nil || recovered != original {
				t.Fatal("maintenance blocked exact service recovery", err)
			}
			var before, after int
			if err := d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.services`).Scan(&before); err != nil {
				t.Fatal(err)
			}
			if id, err := create("new"); !errors.Is(err, ErrServiceCreationGated) || id != "" {
				t.Fatal("new service bypassed maintenance or returned an allocation", err)
			}
			if err := d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.services`).Scan(&after); err != nil || before != after {
				t.Fatal("paused creation persisted a service", err)
			}
			setServiceMaintenance(t, d, actor, MaintenanceControlServiceCreation, true, now)
			if id, err := create("new"); err != nil || id == "" || id == original {
				t.Fatal("paused attempt consumed its request or allocation key", err)
			}
		})
	}
}

func TestIntegrationGuestServiceCreationMaintenancePreservesRecoveryAndNumber(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "admin_guest_creation")
	session, err := createTestControlSession(t.Context(), d, "routes.example.test", time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	actor := session.Identity.Identity.ID
	guest := newGuestTrialForTest(t, d, now)
	now = guestOperationTime(guest)
	request := AllocateGuestDemoServiceRequest{Credential: guestCredentialForTest(guest),
		IdempotencyKey: "original", Target: guestLoopbackTarget(t), Now: now}
	first, err := d.AllocateGuestDemoService(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	setServiceMaintenance(t, d, actor, MaintenanceControlServiceCreation, false, now)
	again, err := d.AllocateGuestDemoService(t.Context(), request)
	if err != nil || again.ID != first.ID {
		t.Fatal("maintenance blocked exact guest allocation recovery", err)
	}
	if err := d.DeleteService(WithGuestServiceCredential(t.Context(), request.Credential), first.ID, "", now); err != nil {
		t.Fatal("maintenance blocked guest cleanup", err)
	}
	request.IdempotencyKey = "new"
	var before, after int64
	if err := d.pool.QueryRow(t.Context(), `SELECT last_demo_number FROM control.guest_trials WHERE id=$1`, guest.ID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if service, err := d.AllocateGuestDemoService(t.Context(), request); !errors.Is(err, ErrServiceCreationGated) || service.ID != "" {
		t.Fatal("new guest service bypassed maintenance", err)
	}
	if err := d.pool.QueryRow(t.Context(), `SELECT last_demo_number FROM control.guest_trials WHERE id=$1`, guest.ID).Scan(&after); err != nil || before != after {
		t.Fatal("paused guest creation advanced its demo number", err)
	}
	setServiceMaintenance(t, d, actor, MaintenanceControlServiceCreation, true, now)
	if service, err := d.AllocateGuestDemoService(t.Context(), request); err != nil || service.ID == first.ID {
		t.Fatal("paused guest request key could not create after resume", err)
	}
}

func TestIntegrationServiceRunMaintenanceOnlyBlocksNewAdmission(t *testing.T) {
	for _, protocol := range []string{"http", "tcp"} {
		t.Run(protocol, func(t *testing.T) {
			d, now, request, _, service := serviceReleaseProject(t, protocol, false)
			publisher := serviceReleasePublisher(t, d, request, now)
			input := ServiceRunRequest{Metadata: service.ServiceMetadata}
			prepared, err := d.PrepareServiceRun(t.Context(), service.ID, publisher, "original", now, input)
			if err != nil {
				t.Fatal(err)
			}
			setServiceMaintenance(t, d, request.ActorID, MaintenanceControlServiceRunCreation, false, now)
			recovered, err := d.PrepareServiceRun(t.Context(), service.ID, publisher, "original", now, input)
			if err != nil || !reflect.DeepEqual(recovered, prepared) {
				t.Fatal("maintenance blocked exact preparation recovery", err)
			}
			if _, err := d.PrepareServiceRun(t.Context(), service.ID, publisher, "new", now, input); !errors.Is(err, ErrServiceRunCreationGated) {
				t.Fatal("maintenance allowed a new run preparation", err)
			}
			if _, err := d.StartServiceRun(t.Context(), service.ID, prepared.RunID, prepared.RunNumber, publisher, now); !errors.Is(err, ErrServiceRunCreationGated) {
				t.Fatal("preparing before pause bypassed first-start maintenance", err)
			}
			var slots int
			if err := d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.service_connection_slots WHERE service_run_id=$1`, prepared.RunID).Scan(&slots); err != nil || slots != 0 {
				t.Fatal("paused first start reserved connection slots", err)
			}
			setServiceMaintenance(t, d, request.ActorID, MaintenanceControlServiceRunCreation, true, now)
			started, err := d.StartServiceRun(t.Context(), service.ID, prepared.RunID, prepared.RunNumber, publisher, now)
			if err != nil {
				t.Fatal(err)
			}
			setServiceMaintenance(t, d, request.ActorID, MaintenanceControlServiceRunCreation, false, now)
			rebound, err := d.StartServiceRun(t.Context(), service.ID, prepared.RunID, prepared.RunNumber, publisher, now)
			if err != nil || rebound.RunID != started.RunID || !reflect.DeepEqual(rebound.Connections, started.Connections) {
				t.Fatal("maintenance blocked already-started recovery", err)
			}
			if _, err := d.HeartbeatServiceRun(t.Context(), service.ID, rebound.RunID, rebound.Token, now, ServiceRunHealth{StreamCapacity: 1}); err != nil {
				t.Fatal("maintenance blocked run renewal", err)
			}
			if err := d.CloseServiceRun(t.Context(), service.ID, rebound.RunID, rebound.Token, now); err != nil {
				t.Fatal("maintenance blocked run cleanup", err)
			}
			setServiceMaintenance(t, d, request.ActorID, MaintenanceControlServiceRunCreation, true, now)
			next, err := d.PrepareServiceRun(t.Context(), service.ID, publisher, "new", now, input)
			if err != nil || next.RunNumber != prepared.RunNumber+1 {
				t.Fatal("paused preparation consumed its key or run number", err)
			}
		})
	}
}

func TestIntegrationServiceCreationMaintenancePauseLinearizesWithInsert(t *testing.T) {
	for _, first := range []string{"pause", "insert"} {
		t.Run(first, func(t *testing.T) {
			d, now := newControlStateIntegrationDatabase(t, "admin_creation_race")
			r := oidcRouteRequest(t, d, now)
			ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			gate, err := d.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			if first == "pause" {
				if _, err := gate.Exec(ctx, `SELECT allowed FROM control.maintenance_controls WHERE operation='service_creation' FOR UPDATE`); err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				workers.Go(func() {
					_, err := d.CreateServiceAt(ctx, r.TeamID, r.ActingIdentityID, "raced", "raced", ServicePlacement{}, now, ServiceMetadata{Protocol: "tcp"}, nil)
					done <- err
				})
				waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), done)
				if _, err := gate.Exec(ctx, `UPDATE control.maintenance_controls SET allowed=false WHERE operation='service_creation'`); err != nil {
					t.Fatal(err)
				}
				if err := gate.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				if err := awaitIntegrationResult(t, ctx, done); !errors.Is(err, ErrServiceCreationGated) {
					t.Fatal("insert overtook the paused maintenance row", err)
				}
			} else {
				// block after the real insertion owner has taken the shared gate.
				if _, err := gate.Exec(ctx, `SELECT pg_advisory_xact_lock(727041)`); err != nil {
					t.Fatal(err)
				}
				if _, err := d.pool.Exec(ctx, `CREATE FUNCTION control.admin_insert_wait() RETURNS trigger LANGUAGE plpgsql AS $$
				    BEGIN PERFORM pg_advisory_xact_lock(727041); RETURN NEW; END $$;
				    CREATE TRIGGER admin_insert_wait BEFORE INSERT ON control.services FOR EACH ROW EXECUTE FUNCTION control.admin_insert_wait()`); err != nil {
					t.Fatal(err)
				}
				created, paused := make(chan error, 1), make(chan error, 1)
				workers.Go(func() {
					_, err := d.CreateServiceAt(ctx, r.TeamID, r.ActingIdentityID, "raced", "raced", ServicePlacement{}, now, ServiceMetadata{Protocol: "tcp"}, nil)
					created <- err
				})
				inserter := waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), created)
				workers.Go(func() {
					_, err := d.SetMaintenanceControl(ctx, MaintenanceControlServiceCreation, false, r.ActingIdentityID, "race-pause", now)
					paused <- err
				})
				waitForPostgresBlock(t, ctx, d, inserter, paused)
				if err := gate.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				if err := awaitIntegrationResult(t, ctx, created); err != nil {
					t.Fatal("admitted insert did not finish before pause", err)
				}
				if err := awaitIntegrationResult(t, ctx, paused); err != nil {
					t.Fatal(err)
				}
			}
			var count int
			if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM control.services`).Scan(&count); err != nil {
				t.Fatal(err)
			}
			want := 0
			if first == "insert" {
				want = 1
			}
			if count != want {
				t.Fatal("maintenance/insert did not linearize", count)
			}
		})
	}
}
