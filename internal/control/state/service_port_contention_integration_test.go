package state

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/tcpport"
)

func TestIntegrationServicePortClaimsCoordinateOnlyChosenPort(t *testing.T) {
	for _, collision := range []bool{false, true} {
		name := "independent"
		if collision {
			name = "collision"
		}
		t.Run(name, func(t *testing.T) {
			d, now, owner, team := newAuthorityTeam(t)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			const firstPort, lastPort = 25443, 25444
			if err := d.ConfigureIngressServicePorts(ctx, PrimaryIngressPoolID, []tcpport.Range{{First: firstPort, Last: lastPort}}); err != nil {
				t.Fatal(err)
			}
			service := func(name string) ServiceRecord {
				t.Helper()
				s, err := d.CreateServiceAt(ctx, team.ID, owner, name, name, ServicePlacement{}, now,
					ServiceMetadata{Protocol: "tcp"}, &ProjectServiceConfiguration{Protocol: "tcp", Target: "localhost:3000", Public: new(false)})
				if err != nil {
					t.Fatal(err)
				}
				return s
			}
			first, second := service("first"), service("second")
			var preferred int
			if err := d.pool.QueryRow(ctx, `SELECT port FROM generate_series($2::int,$3::int) port ORDER BY md5($1||'/'||port::text) LIMIT 1`,
				second.ID, firstPort, lastPort).Scan(&preferred); err != nil {
				t.Fatal(err)
			}
			held := preferred
			if !collision {
				held = firstPort + lastPort - preferred
			}
			gate, err := d.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			if _, err := gate.Exec(ctx, `SELECT id FROM control.ingress_pools WHERE id=$1 FOR SHARE`, PrimaryIngressPoolID); err != nil {
				t.Fatal(err)
			}
			if _, err := gate.Exec(ctx, `INSERT INTO control.service_port_claims(service_id,ingress_pool_id,port,claimed_at) VALUES($1,$2,$3,$4)`,
				first.ID, PrimaryIngressPoolID, held, now); err != nil {
				t.Fatal(err)
			}
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			done := make(chan error, 1)
			var allocated int
			workers.Go(func() {
				tx, err := d.pool.Begin(ctx)
				if err == nil {
					defer rollbackTestTransaction(t, tx)
					allocated, err = allocateServicePort(ctx, tx, second.ID, PrimaryIngressPoolID, true, now)
					if err == nil {
						err = tx.Commit(ctx)
					}
				}
				done <- err
			})
			if collision {
				waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), done)
			} else {
				progress, stop := context.WithTimeout(ctx, 2*time.Second)
				defer stop()
				if err := awaitIntegrationResult(t, progress, done); err != nil || allocated != preferred {
					t.Fatal("a claim blocked an unrelated port", allocated, err)
				}
			}
			edit := make(chan error, 1)
			if !collision {
				workers.Go(func() {
					edit <- d.ConfigureIngressServicePorts(ctx, PrimaryIngressPoolID, []tcpport.Range{{First: preferred, Last: preferred}})
				})
				waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), edit)
			}
			if err := gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if collision {
				if err := awaitIntegrationResult(t, ctx, done); err != nil || allocated == held {
					t.Fatal("collision did not retry the remaining port", allocated, err)
				}
			} else if err := awaitIntegrationResult(t, ctx, edit); !errors.Is(err, ErrServicePortsInUse) {
				t.Fatal("inventory edit discarded a concurrently committed claim", err)
			}
			var claims int
			if err := d.pool.QueryRow(ctx, `SELECT count(DISTINCT port) FROM control.service_port_claims WHERE state='held'`).Scan(&claims); err != nil || claims != 2 {
				t.Fatal("concurrent allocation lost or duplicated a port", claims, err)
			}
		})
	}
}
