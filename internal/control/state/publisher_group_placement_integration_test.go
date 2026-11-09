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

func TestIntegrationPublisherGroupPoolPlacement(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "group_pool_placement")
	ctx := t.Context()
	pools := []ingresspool.Configuration{testIngressPool(t, "ingress-a", "192.0.2.10", 3), testIngressPool(t, "ingress-b", "192.0.2.20", 4)}
	if err := d.ConfigureIngressPools(ctx, pools, now); err != nil {
		t.Fatal(err)
	}
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{"tractor": {Template: true}}, Services: map[string]ProjectServiceConfiguration{
		"api": {PublisherGroup: "tractor", Target: "localhost:3000"}, "shell": {PublisherGroup: "tractor", Protocol: "tcp", Target: "localhost:22"},
	}}
	current, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tractor-a", "tractor-b", "tractor-c"} {
		current, err = d.CreatePublisherGroup(ctx, r.TeamID, r.ProjectKey, name, "tractor", r.ActorID, current.Revision, true, now)
		if err != nil {
			t.Fatal(err)
		}
	}
	for i, group := range current.Groups {
		want := "ingress-b"
		if i == 0 {
			want = "ingress-a"
		}
		if group.IngressPoolID != want {
			t.Fatalf("group %s pool=%s, want %s", group.Name, group.IngressPoolID, want)
		}
	}
	// one port left in A is not enough for a whole two-service tractor. neither
	// create nor a fleet-wide addition may leave a partially committed allocation.
	if _, err := d.CreatePublisherGroup(ctx, r.TeamID, r.ProjectKey, "tractor-d", "tractor", r.ActorID, current.Revision, true, now); !errors.Is(err, ErrServicePortsExhausted) {
		t.Fatal(err)
	}
	r.ExpectedRevision = current.Revision
	r.Configuration.Services["metrics"] = ProjectServiceConfiguration{PublisherGroup: "tractor", Target: "localhost:9090"}
	if _, err := d.ApplyProjectConfiguration(ctx, r); !errors.Is(err, ErrServicePortsExhausted) {
		t.Fatal("fleet growth moved a pinned group", err)
	}
	after, err := d.GetProjectConfiguration(ctx, r.TeamID, r.ProjectKey, r.ActorID)
	if err != nil || !reflect.DeepEqual(after, current) {
		t.Fatal("failed allocation changed saved state", after, err)
	}
	delete(r.Configuration.Services, "metrics")
	// switching reachability and changing targets retain the saved pool,
	// hostname and port, including groups outside the team's default pool.
	for _, public := range []bool{true, false} {
		r.Configuration.PublisherGroups["tractor"] = ProjectPublisherGroup{Template: true, Public: public}
		updated, err := d.ApplyProjectConfiguration(ctx, r)
		if err != nil {
			t.Fatal(err)
		}
		for i, s := range updated.Services {
			before := current.Services[i]
			if s.ServiceID != before.ServiceID || s.Port != before.Port || s.Hostname != before.Hostname || s.Public != public {
				t.Fatal("reachability changed reserved endpoint", before, s)
			}
		}
		for i, g := range updated.Groups {
			if g.IngressPoolID != current.Groups[i].IngressPoolID {
				t.Fatal("group changed pools", g)
			}
		}
		current = updated
		r.ExpectedRevision = current.Revision
	}
	// the database rejects accidental reassignment even outside apply.
	_, err = d.pool.Exec(ctx, `UPDATE control.project_publisher_groups SET ingress_pool_id='ingress-a' WHERE id=$1`, current.Groups[1].ID)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
		t.Fatal("group placement was not pinned", err)
	}
	// expanding a pinned pool, not adding an unrelated pool, makes fleet growth
	// possible without replacing any endpoint.
	pools[0] = testIngressPool(t, "ingress-a", "192.0.2.10", 4)
	pools[1] = testIngressPool(t, "ingress-b", "192.0.2.20", 6)
	if err := d.ConfigureIngressPools(ctx, pools, now); err != nil {
		t.Fatal(err)
	}
	r.Configuration.Services["metrics"] = ProjectServiceConfiguration{PublisherGroup: "tractor", Target: "localhost:9090"}
	if updated, err := d.ApplyProjectConfiguration(ctx, r); err != nil || len(updated.Services) != 9 {
		t.Fatal(updated, err)
	}
}

func TestIntegrationPublisherGroupPoolsConcurrentCreation(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "group_pool_concurrent")
	pools := []ingresspool.Configuration{testIngressPool(t, "ingress-a", "192.0.2.10", 2), testIngressPool(t, "ingress-b", "192.0.2.20", 2)}
	if err := d.ConfigureIngressPools(t.Context(), pools, now); err != nil {
		t.Fatal(err)
	}
	r := appliedProjectRequest(t, d, now)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	workers := newIntegrationWorkers(t, cancel)
	type outcome struct {
		current AppliedProjectConfiguration
		err     error
	}
	done := make(chan outcome, 3)
	start := make(chan struct{})
	for i := range 3 {
		request := r
		request.ProjectKey = fmt.Sprintf("project-%d", i)
		request.ProjectLabel = request.ProjectKey
		teamRequest := authorityTeamRequest(r.ActorID)
		teamRequest.DisplayName = fmt.Sprintf("pool-team-%d", i)
		teamRequest.IdempotencyKey = teamRequest.DisplayName
		team, err := d.CreateTeam(ctx, teamRequest, now)
		if err != nil {
			t.Fatal(err)
		}
		request.TeamID = team.ID
		request.Configuration = ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{"equipment": {}}, Services: map[string]ProjectServiceConfiguration{
			"api": {PublisherGroup: "equipment", Target: "localhost:3000"}, "shell": {PublisherGroup: "equipment", Protocol: "tcp", Target: "localhost:22"},
		}}
		workers.Go(func() {
			select {
			case <-start:
			case <-ctx.Done():
				return
			}
			current, err := d.ApplyProjectConfiguration(ctx, request)
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
		if v.err != nil || len(v.current.Groups) != 1 {
			t.Fatal(v.current, v.err)
		}
		id := v.current.Groups[0].IngressPoolID
		if seen[id] {
			t.Fatal("two groups shared one full pool", id)
		}
		seen[id] = true
	}
	if len(seen) != 2 || failed != 1 {
		t.Fatal(seen, failed)
	}
	var claims int
	if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM control.service_port_claims WHERE state='held'`).Scan(&claims); err != nil || claims != 4 {
		t.Fatal("partial reservations survived", claims, err)
	}
}

func TestIntegrationPublisherGroupPoolConfigurationSafety(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "group_pool_configuration")
	ctx := t.Context()
	pools := []ingresspool.Configuration{testIngressPool(t, "ingress-a", "192.0.2.10", 2), testIngressPool(t, "ingress-b", "192.0.2.20", 4)}
	if err := d.ConfigureIngressPools(ctx, pools, now); err != nil {
		t.Fatal(err)
	}
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{"first": {}, "second": {}}, Services: map[string]ProjectServiceConfiguration{
		"first-api": {PublisherGroup: "first", Target: "localhost:3000"}, "first-shell": {PublisherGroup: "first", Protocol: "tcp", Target: "localhost:22"},
		"second-api": {PublisherGroup: "second", Target: "localhost:3000"}, "second-shell": {PublisherGroup: "second", Protocol: "tcp", Target: "localhost:22"},
	}}
	current, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	bad := append([]ingresspool.Configuration(nil), pools...)
	bad[0] = testIngressPool(t, "ingress-a", "192.0.2.10", 3)
	bad[1].IPv4Address = netip.MustParseAddr("192.0.2.30")
	if err := d.ConfigureIngressPools(ctx, bad, now); !errors.Is(err, ErrIngressPoolPinned) {
		t.Fatal("changed a saved public address", err)
	}
	var ports int
	if err := d.pool.QueryRow(ctx, `SELECT sum(last_port-first_port+1) FROM control.ingress_service_port_ranges WHERE ingress_pool_id='ingress-a'`).Scan(&ports); err != nil || ports != 2 {
		t.Fatal("failed configuration partially expanded inventory", ports, err)
	}
	bad = append([]ingresspool.Configuration(nil), pools...)
	bad[1] = testIngressPool(t, "ingress-b", "192.0.2.20", 1)
	if err := d.ConfigureIngressPools(ctx, bad, now); !errors.Is(err, ErrServicePortsInUse) {
		t.Fatal("removed a held port", err)
	}
	// omission drains B without erasing its address or reservations. existing
	// groups can still switch reachability, but new groups cannot enter it.
	if err := d.ConfigureIngressPools(ctx, pools[:1], now); err != nil {
		t.Fatal(err)
	}
	pool, err := d.GetIngressPool(ctx, "ingress-b")
	if err != nil || pool.State != IngressPoolDraining || pool.IPv4Address != pools[1].IPv4Address {
		t.Fatal(pool, err)
	}
	r.ExpectedRevision = current.Revision
	g := r.Configuration.PublisherGroups["second"]
	g.Public = true
	r.Configuration.PublisherGroups["second"] = g
	current, err = d.ApplyProjectConfiguration(ctx, r)
	if err != nil || current.Groups[1].IngressPoolID != "ingress-b" {
		t.Fatal(current, err)
	}
	r.ExpectedRevision = current.Revision
	r.Configuration.PublisherGroups["third"] = ProjectPublisherGroup{}
	r.Configuration.Services["third-api"] = ProjectServiceConfiguration{PublisherGroup: "third", Target: "localhost:3000"}
	if _, err := d.ApplyProjectConfiguration(ctx, r); !errors.Is(err, ErrServicePortsExhausted) {
		t.Fatal("new group entered draining pool", err)
	}
	if err := d.ConfigureIngressPools(ctx, pools, now); err != nil {
		t.Fatal(err)
	}
	if current, err := d.ApplyProjectConfiguration(ctx, r); err != nil || current.Groups[2].IngressPoolID != "ingress-b" {
		t.Fatal("re-enabled pool stayed unavailable", current, err)
	}
}

func TestIntegrationPublisherGroupPoolRetainedService(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "group_pool_retained")
	ctx := t.Context()
	if err := d.ConfigureIngressPools(ctx, []ingresspool.Configuration{testIngressPool(t, "ingress-a", "192.0.2.10", 1), testIngressPool(t, "ingress-b", "192.0.2.20", 1)}, now); err != nil {
		t.Fatal(err)
	}
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{"first": {}, "second": {}}, Services: map[string]ProjectServiceConfiguration{
		"api": {PublisherGroup: "first", Target: "localhost:3000"}, "shell": {PublisherGroup: "second", Protocol: "tcp", Target: "localhost:22"},
	}}
	current, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	r.ExpectedRevision = current.Revision
	api := r.Configuration.Services["api"]
	api.PublisherGroup = "second"
	r.Configuration.Services["api"] = api
	if _, err := d.ApplyProjectConfiguration(ctx, r); !errors.Is(err, ErrServicePoolPinned) {
		t.Fatal("retained service moved to another pool without a reservation", err)
	}
	after, err := d.GetProjectConfiguration(ctx, r.TeamID, r.ProjectKey, r.ActorID)
	if err != nil || !reflect.DeepEqual(after, current) {
		t.Fatal("cross-pool reassignment partially committed", after, err)
	}
	// a new group can inherit the saved service's existing pool even when it has
	// no unused ports. no new reservation is needed for that retained service.
	r.Configuration.PublisherGroups["third"] = ProjectPublisherGroup{}
	api.PublisherGroup = "third"
	r.Configuration.Services["api"] = api
	after, err = d.ApplyProjectConfiguration(ctx, r)
	if err != nil || after.Groups[2].IngressPoolID != "ingress-a" || after.Services[0].ServiceID != current.Services[0].ServiceID || after.Services[0].Port != current.Services[0].Port {
		t.Fatal("retained service did not keep its reservation", after, err)
	}
	r.ExpectedRevision = after.Revision
	r.Configuration.PublisherGroups["fourth"] = ProjectPublisherGroup{}
	for name, s := range r.Configuration.Services {
		s.PublisherGroup = "fourth"
		r.Configuration.Services[name] = s
	}
	if _, err := d.ApplyProjectConfiguration(ctx, r); !errors.Is(err, ErrServicePoolPinned) {
		t.Fatal("new group combined reservations from different pools", err)
	}
}
