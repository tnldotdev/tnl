package state

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/naming/tcpport"
)

func TestIntegrationIngressPortInventory(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "ingress_port_inventory")
	ctx := t.Context()
	sparse := make([]tcpport.Range, 0, 32256)
	for port := 1024; port <= 65535; port += 2 {
		sparse = append(sparse, tcpport.Range{First: port, Last: port})
	}
	for _, test := range []struct {
		name         string
		ranges, want []tcpport.Range
	}{
		{"empty", nil, nil},
		{"adjacent", []tcpport.Range{{First: 20001, Last: 20001}, {First: 20000, Last: 20000}}, []tcpport.Range{{First: 20000, Last: 20001}}},
		{"full", []tcpport.Range{{First: 1024, Last: 65535}}, []tcpport.Range{{First: 1024, Last: 65535}}},
		{"sparse", sparse, sparse},
	} {
		t.Run(test.name, func(t *testing.T) {
			registration := IngressRegistration{IngressID: test.name, IngressRunID: test.name + "-run", ProtocolVersion: 1, ConnectionCapacity: 1, IngressPoolID: "ingress-a", HTTPS: true, ServicePortRanges: test.ranges}
			lease, err := d.RegisterIngress(ctx, registration, now, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			var stored pgtype.Multirange[pgtype.Range[pgtype.Int4]]
			var revision uint64
			var size int
			if err := d.pool.QueryRow(ctx, `SELECT service_port_ranges, ingress_lease_revision, pg_column_size(service_port_ranges) FROM control.ingress_leases WHERE ingress_id=$1`, registration.IngressID).Scan(&stored, &revision, &size); err != nil {
				t.Fatal(err)
			}
			inventory, err := ingressPortInventory(stored)
			if err != nil || !slices.Equal(inventory.Ranges(), test.want) || revision != lease.IngressLeaseRevision {
				t.Fatalf("stored ranges or revision differ: %d ranges, revision %d, %v", len(stored), revision, err)
			}
			if test.name == "full" && size > 64 {
				t.Fatalf("full inventory expanded to %d bytes", size)
			}
			// equivalent ranges renew the same process; changed coverage cannot.
			registration.ServicePortRanges = test.want
			renewed, err := d.RegisterIngress(ctx, registration, now.Add(time.Second), time.Minute)
			if err != nil || renewed.IngressLeaseRevision != lease.IngressLeaseRevision {
				t.Fatal("equivalent inventory changed the lease", renewed, err)
			}
			registration.ServicePortRanges = []tcpport.Range{{First: 30001, Last: 30001}}
			if _, err := d.RegisterIngress(ctx, registration, now.Add(2*time.Second), time.Minute); !errors.Is(err, ErrIngressAlreadyRunning) {
				t.Fatal("same process changed its port coverage", err)
			}
			// prove SQL membership agrees on every port, including holes and bounds.
			var mismatches int
			if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM generate_series(1023,65536) AS p(port)
				CROSS JOIN control.ingress_leases l WHERE l.ingress_id=$1 AND
				(p.port <@ l.service_port_ranges) <> (CASE $1
					WHEN 'empty' THEN false
					WHEN 'adjacent' THEN p.port BETWEEN 20000 AND 20001
					WHEN 'full' THEN p.port BETWEEN 1024 AND 65535
					WHEN 'sparse' THEN p.port BETWEEN 1024 AND 65535 AND p.port%2=0 END)`, registration.IngressID).Scan(&mismatches); err != nil || mismatches != 0 {
				t.Fatal("stored membership differs", mismatches, err)
			}
		})
	}
	for _, invalid := range []string{"{[443,444)}", "{[65536,65537)}", "{(,20000)}", "{[20000,)}"} {
		_, err := d.pool.Exec(ctx, `UPDATE control.ingress_leases SET service_port_ranges=$1::int4multirange WHERE ingress_id='full'`, invalid)
		var constraint *pgconn.PgError
		if !errors.As(err, &constraint) || constraint.Code != "23514" {
			t.Fatalf("stored invalid range %q: %v", invalid, err)
		}
	}
	for _, invalid := range [][]tcpport.Range{
		{{First: 1023, Last: 1024}}, {{First: 65535, Last: 65536}}, {{First: 20001, Last: 20000}},
		{{First: 20000, Last: 20010}, {First: 20010, Last: 20020}},
	} {
		_, err := d.RegisterIngress(ctx, IngressRegistration{IngressID: "invalid", IngressRunID: "invalid-run", ProtocolVersion: 1, ConnectionCapacity: 1, IngressPoolID: "ingress-a", ServicePortRanges: invalid}, now, time.Minute)
		if !errors.Is(err, tcpport.ErrInventory) {
			t.Fatal("state accepted invalid inventory", invalid, err)
		}
	}
}
