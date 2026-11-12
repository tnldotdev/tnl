package state

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	ingresspool "github.com/tnldotdev/tnl/internal/ingress/pool"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/naming/tcpport"
)

func testIngressPool(t *testing.T, id, address string, ports int) ingresspool.Configuration {
	t.Helper()
	inventory, err := tcpport.NewInventory([]tcpport.Range{{First: 25000, Last: 25000 + ports - 1}})
	if err != nil {
		t.Fatal(err)
	}
	return ingresspool.Configuration{ID: ingresspool.ID(id), IPv4Address: netip.MustParseAddr(address), Ports: inventory}
}

func retainedEnvironmentPool(t *testing.T, d *Database, e Environment) string {
	t.Helper()
	var pool string
	if err := d.pool.QueryRow(t.Context(), `SELECT assignment.ingress_pool_id FROM control.project_publisher_groups assignment JOIN control.environments environment ON environment.group_id=assignment.id WHERE environment.id=$1`, e.ID).Scan(&pool); err != nil {
		t.Fatal(err)
	}
	return pool
}

func TestIntegrationPublisherGroupPoolPlacement(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "group_pool_placement")
	ctx := t.Context()
	pools := []ingresspool.Configuration{testIngressPool(t, "ingress-a", "192.0.2.10", 3), testIngressPool(t, "ingress-b", "192.0.2.20", 4)}
	if err := d.ConfigureIngressPools(ctx, pools, now); err != nil {
		t.Fatal(err)
	}
	r := retainedEnvironmentProject(t, d, now)
	definition := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"api": {Protocol: "http"}, "shell": {Protocol: "tcp"}})
	targets := EnvironmentTargets{"api": {Address: "localhost:3000"}, "shell": {Address: "localhost:22"}}
	var environments []Environment
	pinnedPools := map[string]string{}
	for i, name := range []string{"tractor-a", "tractor-b", "tractor-c"} {
		e, _ := createTestEnvironment(t, d, r, name, definition.Revision, targets)
		environments = append(environments, e)
		want := "ingress-b"
		if i == 0 {
			want = "ingress-a"
		}
		pool := retainedEnvironmentPool(t, d, e)
		if pool != want {
			t.Fatal("wrong whole-environment placement", pool, want)
		}
		pinnedPools[e.ID] = pool
	}
	request := CreateEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, SourceFingerprint: r.SourceFingerprint, Name: "tractor-d", DefinitionRevision: definition.Revision, Targets: targets, IdempotencyKey: "tractor-d", Now: now}
	if _, err := d.CreateEnvironment(ctx, request); !errors.Is(err, ErrServicePortsExhausted) {
		t.Fatal("partial whole-environment allocation", err)
	}
	grown := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"api": {Protocol: "http"}, "shell": {Protocol: "tcp"}, "metrics": {Protocol: "http"}})
	growth := ApplyEnvironmentsRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, Now: now}
	for _, e := range environments {
		growth.Items = append(growth.Items, EnvironmentApplication{EnvironmentID: e.ID, ExpectedRevision: e.MutationRevision, DefinitionRevision: grown.Revision, Targets: EnvironmentTargets{"api": {Address: "localhost:3000"}, "shell": {Address: "localhost:22"}, "metrics": {Address: "localhost:9090"}}})
	}
	before := privateOwnershipSnapshot(t, d)
	if _, err := d.ApplyEnvironments(ctx, growth); !errors.Is(err, ErrServicePortsExhausted) {
		t.Fatal("growth moved a pinned environment", err)
	}
	if !reflect.DeepEqual(before, privateOwnershipSnapshot(t, d)) {
		t.Fatal("failed allocation changed saved state")
	}
	for _, public := range []bool{true, false} {
		batch := ApplyEnvironmentsRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, Now: now}
		for _, e := range environments {
			batch.Items = append(batch.Items, EnvironmentApplication{EnvironmentID: e.ID, ExpectedRevision: e.MutationRevision, DefinitionRevision: e.AppliedDefinitionRevision, Public: &public})
		}
		updated, err := d.ApplyEnvironments(ctx, batch)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range updated {
			var old Environment
			for _, candidate := range environments {
				if candidate.ID == e.ID {
					old = candidate
				}
			}
			if pool := retainedEnvironmentPool(t, d, e); pool != pinnedPools[e.ID] {
				t.Fatal("environment changed pools")
			}
			for i, s := range e.Services {
				prior := old.Services[i]
				if s.ServiceID != prior.ServiceID || s.Port != prior.Port || s.Hostname != prior.Hostname || s.Public != public {
					t.Fatal("reachability changed reserved endpoint")
				}
			}
		}
		environments = updated
	}
	_, err := d.pool.Exec(ctx, `UPDATE control.project_publisher_groups SET ingress_pool_id='ingress-a' WHERE id=(SELECT group_id FROM control.environments WHERE id=$1)`, environments[1].ID)
	var constraint *pgconn.PgError
	if !errors.As(err, &constraint) || constraint.Code != "23514" {
		t.Fatal("placement not pinned outside apply", err)
	}
	pools[0] = testIngressPool(t, "ingress-a", "192.0.2.10", 4)
	pools[1] = testIngressPool(t, "ingress-b", "192.0.2.20", 6)
	if err := d.ConfigureIngressPools(ctx, pools, now); err != nil {
		t.Fatal(err)
	}
	for i := range growth.Items {
		for _, e := range environments {
			if e.ID == growth.Items[i].EnvironmentID {
				growth.Items[i].ExpectedRevision = e.MutationRevision
			}
		}
	}
	updated, err := d.ApplyEnvironments(ctx, growth)
	if err != nil || len(updated) != 3 {
		t.Fatal("expanded pinned pools did not allow growth", err)
	}
	for _, e := range updated {
		if len(e.Services) != 3 {
			t.Fatal("fleet growth incomplete")
		}
	}
}

func TestIntegrationPublisherGroupPoolsConcurrentCreation(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "group_pool_concurrent")
	pools := []ingresspool.Configuration{testIngressPool(t, "ingress-a", "192.0.2.10", 2), testIngressPool(t, "ingress-b", "192.0.2.20", 2)}
	if err := d.ConfigureIngressPools(t.Context(), pools, now); err != nil {
		t.Fatal(err)
	}
	r := retainedEnvironmentProject(t, d, now)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	workers := newIntegrationWorkers(t, cancel)
	type outcome struct {
		current Environment
		err     error
	}
	done := make(chan outcome, 3)
	start := make(chan struct{})
	for i := range 3 {
		project := r
		project.ProjectKey = fmt.Sprintf("project-%d", i)
		teamRequest := authorityTeamRequest(r.ActorID)
		teamRequest.DisplayName = fmt.Sprintf("pool-team-%d", i)
		teamRequest.IdempotencyKey = teamRequest.DisplayName
		team, err := d.CreateTeam(ctx, teamRequest, now)
		if err != nil {
			t.Fatal(err)
		}
		project.TeamID = team.ID
		definition := environmentDefinition(t, d, project, map[string]ServiceDefinitionService{"api": {Protocol: "http"}, "shell": {Protocol: "tcp"}})
		request := CreateEnvironmentRequest{TeamID: project.TeamID, ProjectKey: project.ProjectKey, ActorID: project.ActorID, SourceFingerprint: project.SourceFingerprint, Name: "equipment", DefinitionRevision: definition.Revision, Targets: EnvironmentTargets{"api": {Address: "localhost:3000"}, "shell": {Address: "localhost:22"}}, IdempotencyKey: "equipment", Now: now}
		workers.Go(func() {
			select {
			case <-start:
			case <-ctx.Done():
				return
			}
			current, err := d.CreateEnvironment(ctx, request)
			done <- outcome{current, err}
		})
	}
	close(start)
	seen := map[string]bool{}
	failed := 0
	for range 3 {
		v := awaitIntegrationResult(t, ctx, done)
		if errors.Is(v.err, ErrServicePortsExhausted) {
			failed++
			continue
		}
		if v.err != nil || len(v.current.Services) != 2 {
			t.Fatal(v.current, v.err)
		}
		pool := retainedEnvironmentPool(t, d, v.current)
		if seen[pool] {
			t.Fatal("two environments shared full pool")
		}
		seen[pool] = true
	}
	if len(seen) != 2 || failed != 1 {
		t.Fatal(seen, failed)
	}
	var claims int
	if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM control.service_port_claims WHERE state='held'`).Scan(&claims); err != nil || claims != 4 {
		t.Fatal("partial reservation survived", claims, err)
	}
}

func TestIntegrationPublisherGroupPoolConfigurationSafety(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "group_pool_configuration")
	ctx := t.Context()
	pools := []ingresspool.Configuration{testIngressPool(t, "ingress-a", "192.0.2.10", 2), testIngressPool(t, "ingress-b", "192.0.2.20", 4)}
	if err := d.ConfigureIngressPools(ctx, pools, now); err != nil {
		t.Fatal(err)
	}
	r := retainedEnvironmentProject(t, d, now)
	definition := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"api": {Protocol: "http"}, "shell": {Protocol: "tcp"}})
	targets := EnvironmentTargets{"api": {Address: "localhost:3000"}, "shell": {Address: "localhost:22"}}
	createTestEnvironment(t, d, r, "first", definition.Revision, targets)
	second, _ := createTestEnvironment(t, d, r, "second", definition.Revision, targets)
	bad := append([]ingresspool.Configuration(nil), pools...)
	bad[0] = testIngressPool(t, "ingress-a", "192.0.2.10", 3)
	bad[1].IPv4Address = netip.MustParseAddr("192.0.2.30")
	if err := d.ConfigureIngressPools(ctx, bad, now); !errors.Is(err, ErrIngressPoolPinned) {
		t.Fatal("changed saved public address", err)
	}
	var ports int
	if err := d.pool.QueryRow(ctx, `SELECT sum(last_port-first_port+1) FROM control.ingress_service_port_ranges WHERE ingress_pool_id='ingress-a'`).Scan(&ports); err != nil || ports != 2 {
		t.Fatal("failed configuration expanded inventory", err)
	}
	bad = append([]ingresspool.Configuration(nil), pools...)
	bad[1] = testIngressPool(t, "ingress-b", "192.0.2.20", 1)
	if err := d.ConfigureIngressPools(ctx, bad, now); !errors.Is(err, ErrServicePortsInUse) {
		t.Fatal("removed held port", err)
	}
	if err := d.ConfigureIngressPools(ctx, pools[:1], now); err != nil {
		t.Fatal(err)
	}
	pool, err := d.GetIngressPool(ctx, "ingress-b")
	if err != nil || pool.State != IngressPoolDraining || pool.IPv4Address != pools[1].IPv4Address {
		t.Fatal("drain erased pool", err)
	}
	current, err := d.ApplyEnvironment(ctx, ApplyEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, EnvironmentApplication: EnvironmentApplication{EnvironmentID: second.ID, ExpectedRevision: second.MutationRevision, DefinitionRevision: second.AppliedDefinitionRevision, Public: new(true)}, Now: now})
	if err != nil || retainedEnvironmentPool(t, d, current) != "ingress-b" {
		t.Fatal("draining pool lost existing publication", err)
	}
	one := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"api": {Protocol: "http"}})
	request := CreateEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, SourceFingerprint: r.SourceFingerprint, Name: "third", DefinitionRevision: one.Revision, Targets: EnvironmentTargets{"api": {Address: "localhost:3000"}}, IdempotencyKey: "third", Now: now}
	if _, err := d.CreateEnvironment(ctx, request); !errors.Is(err, ErrServicePortsExhausted) {
		t.Fatal("new environment entered draining pool", err)
	}
	if err := d.ConfigureIngressPools(ctx, pools, now); err != nil {
		t.Fatal(err)
	}
	third, err := d.CreateEnvironment(ctx, request)
	if err != nil || retainedEnvironmentPool(t, d, third) != "ingress-b" {
		t.Fatal("re-enabled pool unavailable", err)
	}
}

func TestIntegrationPublisherGroupPoolRetainedService(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "group_pool_retained")
	ctx := t.Context()
	if err := d.ConfigureIngressPools(ctx, []ingresspool.Configuration{testIngressPool(t, "ingress-a", "192.0.2.10", 1), testIngressPool(t, "ingress-b", "192.0.2.20", 1)}, now); err != nil {
		t.Fatal(err)
	}
	r := retainedEnvironmentProject(t, d, now)
	first, _ := retainedServiceEnvironment(t, d, r, "first", map[string]EnvironmentServicePublication{"api": {Protocol: "http", Target: "localhost:3000"}})
	second, _ := retainedServiceEnvironment(t, d, r, "second", map[string]EnvironmentServicePublication{"shell": {Protocol: "tcp", Target: "localhost:22"}})
	// reservation mechanics remain reusable below environment ownership. probe
	// retained reservations there without inventing a cross-environment move API.
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := allocateServicePort(ctx, tx, first.Services[0].ServiceID, "ingress-b", now); !errors.Is(err, ErrServicePoolPinned) {
		t.Fatal("retained service moved pools", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	tx, err = d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	id, err := opaqueid.New("pgrp_")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO control.project_publisher_groups(id,team_id,project_key,name) VALUES($1,$2,$3,'retained-reservation')`, id, r.TeamID, r.ProjectKey); err != nil {
		t.Fatal(err)
	}
	if err := ensurePublisherGroupIngressPool(ctx, tx, id, 0, []string{first.Services[0].ServiceID}, []string{"ingress-a", "ingress-b"}); err != nil {
		t.Fatal("retained reservation needed free port", err)
	}
	var pool string
	if err := tx.QueryRow(ctx, `SELECT ingress_pool_id FROM control.project_publisher_groups WHERE id=$1`, id).Scan(&pool); err != nil || pool != "ingress-a" {
		t.Fatal("reservation not inherited", err)
	}
	if port, err := allocateServicePort(ctx, tx, first.Services[0].ServiceID, pool, now); err != nil || port != first.Services[0].Port {
		t.Fatal("retained endpoint replaced reservation", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	tx, err = d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `INSERT INTO control.project_publisher_groups(id,team_id,project_key,name) VALUES($1,$2,$3,'mixed-reservations')`, id, r.TeamID, r.ProjectKey); err != nil {
		t.Fatal(err)
	}
	if err := ensurePublisherGroupIngressPool(ctx, tx, id, 0, []string{first.Services[0].ServiceID, second.Services[0].ServiceID}, []string{"ingress-a", "ingress-b"}); !errors.Is(err, ErrServicePoolPinned) {
		t.Fatal("combined reservations from different pools", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	current, err := d.GetEnvironment(ctx, r.TeamID, r.ProjectKey, first.ID, r.ActorID)
	if err != nil || !reflect.DeepEqual(current, first) {
		t.Fatal("rejected reservation mutation committed", err)
	}
}
