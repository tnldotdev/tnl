package state

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/httpprotection"
	"github.com/tnldotdev/tnl/internal/policy/ippolicy"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/testutil/ipdigest"
)

func newProtectionServiceFixture(t *testing.T, settings httpprotection.Settings) serviceHTTPFixture {
	t.Helper()
	f := newServiceHTTPFixture(t)
	local, err := f.database.RealizeLocalProjectService(t.Context(), RealizeLocalProjectServiceRequest{
		TeamID: f.project.TeamID, ActorID: f.project.ActorID, ProjectKey: f.project.ProjectKey,
		SourceFingerprint: f.project.SourceFingerprint, Service: "protection", WorktreeKey: "protection",
		DNSAutomation: true, Now: f.now,
		Configuration: ProjectServiceConfiguration{Target: "localhost:3000", Public: new(true),
			HTTP: &config.HTTPService{Protection: &settings}},
	})
	if err != nil {
		t.Fatal(err)
	}
	f.service, err = f.database.GetService(t.Context(), local.ServiceID, f.project.ActorID)
	if err != nil {
		t.Fatal(err)
	}
	f.run = f.publish(t, f.service)
	// keep publisher authority current while these tests advance mitigation
	// clocks. run/relay expiration has separate owner tests.
	if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.service_runs SET publisher_expires_at=$2 WHERE id=$1`, f.run.RunID, f.now.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.ReadPublisherVisitorPolicy(t.Context(), visitorscope.Scope{Kind: visitorscope.Service, ID: f.service.ID}, f.run.RunID, f.run.RunNumber, f.run.Token, 0, f.now); err != nil {
		t.Fatal(err)
	}
	return f
}

func rejectionEvidence(now time.Time) httpprotection.Rejections {
	return httpprotection.Rejections{SourceDigest: ipdigest.Hash("192.0.2.1"), StartedAt: now.Add(-time.Second), EndedAt: now, Count: 10, RuleIDs: []int{942100}}
}

func setProtectionSettings(t *testing.T, f serviceHTTPFixture, settings httpprotection.Settings) {
	t.Helper()
	ctx := t.Context()
	tx, err := f.database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err := lockServiceAdmission(ctx, tx, f.service.ID); err != nil {
		t.Fatal(err)
	}
	declaration, err := f.database.serviceConfiguration(ctx, controlstatedb.New(tx), f.service.ID)
	if err != nil || declaration == nil || declaration.HTTP == nil {
		t.Fatal("fixture has no HTTP declaration", err)
	}
	declaration.HTTP.Protection = &settings
	if err := f.database.saveServiceConfiguration(ctx, tx, f.service.ID, *declaration); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationHTTPProtectionServiceAdmissionAndRestart(t *testing.T) {
	f := newProtectionServiceFixture(t, httpprotection.Settings{TemporaryBlocks: true})
	d, now, run := f.database, f.now, f.run
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: f.service.ID}
	evidence := rejectionEvidence(now)
	key, err := d.readServiceIPKey(t.Context(), controlstatedb.New(d.pool), scope.ID, temporaryBlockIPKeyPurpose)
	if err != nil {
		t.Fatal(err)
	}
	evidence.SourceDigest, err = ippolicy.HashAddress([32]byte(key), netip.MustParseAddr("192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	report := func() error {
		return d.ReportHTTPProtectionRejections(t.Context(), scope, run.RunID, run.RunNumber, run.Token, evidence, now)
	}
	if err := report(); err != nil {
		t.Fatal(err)
	}
	policy, err := d.ReadPublisherVisitorPolicy(t.Context(), scope, run.RunID, run.RunNumber, run.Token, 0, now)
	if err != nil || len(policy.TemporaryBlocks) != 1 {
		t.Fatal("service policy lost accepted blocks", err)
	}
	lease, err := d.RegisterIngress(t.Context(), IngressRegistration{
		IngressID: "protection", IngressRunID: mustOpaqueID(t, opaqueid.IngressRunPrefix),
		IngressPoolID: PrimaryIngressPoolID, HTTPS: true, ProtocolVersion: 1, ConnectionCapacity: 64,
	}, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := d.ReadIngressServices(t.Context(), lease.IngressLeaseIdentity, now)
	if err != nil || len(snapshot.Runs) != 1 || snapshot.Runs[0].ServiceID != scope.ID {
		t.Fatal("ingress snapshot lost the protected service", err)
	}
	blocks, err := httpprotection.DecodeBlocks(snapshot.Runs[0].TemporaryBlockKey, snapshot.Runs[0].TemporaryBlocks)
	if err != nil || !blocks.Blocked(netip.MustParseAddr("192.0.2.1"), now) ||
		blocks.Blocked(netip.MustParseAddr("192.0.2.2"), now) {
		t.Fatal("ingress snapshot lost or widened the source block", err)
	}
	if _, err := d.serviceHTTPSourcePolicy(t.Context(), controlstatedb.New(d.pool), f.service.ID, netip.MustParseAddr("192.0.2.1")); err != nil {
		t.Fatal("public mitigation changed connector source policy", err)
	}
	if err := d.CloseServiceRun(t.Context(), run.ServiceID, run.RunID, run.Token, now); err != nil {
		t.Fatal(err)
	}
	if err := report(); err == nil {
		t.Fatal("closed run retained reporting authority")
	}
	run = f.publish(t, f.service)
	policy, err = d.ReadPublisherVisitorPolicy(t.Context(), scope, run.RunID, run.RunNumber, run.Token, 0, now)
	if err != nil || len(policy.TemporaryBlocks) != 1 {
		t.Fatal("replacement run lost the service-scoped block", err)
	}
}

func TestIntegrationHTTPProtectionFixedExpiryFreshnessAndAuthority(t *testing.T) {
	f := newProtectionServiceFixture(t, httpprotection.Settings{TemporaryBlocks: true})
	d, now, run := f.database, f.now, f.run
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: f.service.ID}
	report := func(e httpprotection.Rejections, at time.Time) error {
		return d.ReportHTTPProtectionRejections(t.Context(), scope, run.RunID, run.RunNumber, run.Token, e, at)
	}
	read := func(at time.Time) []httpprotection.TemporaryBlock {
		t.Helper()
		blocks, err := readHTTPTemporaryBlocks(t.Context(), controlstatedb.New(d.pool), scope, at)
		if err != nil {
			t.Fatal(err)
		}
		return blocks
	}
	evidence := rejectionEvidence(now)
	if err := report(evidence, now); err != nil {
		t.Fatal(err)
	}
	blocks := read(now)
	if len(blocks) != 1 || !blocks[0].ExpiresAt.Equal(now.Add(time.Minute)) {
		t.Fatal("block did not have a fixed one-minute expiry", blocks)
	}
	if err := report(evidence, now.Add(5*time.Second)); err != nil || !read(now)[0].ExpiresAt.Equal(blocks[0].ExpiresAt) {
		t.Fatal("retry extended the block", err)
	}
	if err := report(evidence, now.Add(11*time.Second)); !errors.Is(err, ErrVisitorPolicy) {
		t.Fatal("stale evidence recreated a penalty", err)
	}
	if len(read(now.Add(time.Minute))) != 0 {
		t.Fatal("block survived its expiry")
	}
	for _, window := range [][3]time.Duration{{59 * time.Second, 61 * time.Second, 61 * time.Second}, {51 * time.Second, 111 * time.Second, 121 * time.Second}} {
		delayed := evidence
		delayed.StartedAt, delayed.EndedAt = now.Add(window[0]), now.Add(window[1])
		if err := report(delayed, now.Add(window[2])); err != nil || len(read(now.Add(window[2]))) != 0 {
			t.Fatal("evidence crossing the previous block recreated it", err)
		}
	}
	fresh := rejectionEvidence(now.Add(123 * time.Second))
	if err := report(fresh, fresh.EndedAt); err != nil || len(read(fresh.EndedAt)) != 1 {
		t.Fatal("fresh evidence could not create a new fixed block", err)
	}
	for _, bad := range []struct {
		scope  visitorscope.Scope
		number int64
		token  string
	}{
		{visitorscope.Scope{Kind: visitorscope.Service, ID: mustOpaqueID(t, opaqueid.ServicePrefix)}, run.RunNumber, run.Token},
		{scope, run.RunNumber + 1, run.Token}, {scope, run.RunNumber, "wrong-token"},
	} {
		if err := d.ReportHTTPProtectionRejections(t.Context(), bad.scope, run.RunID, bad.number, bad.token, evidence, now); err == nil {
			t.Fatal("report escaped its service, run number, or credential")
		}
	}
	var identity, grant string
	if err := d.pool.QueryRow(t.Context(), `SELECT publisher_identity_id,publisher_grant_id FROM control.service_runs WHERE id=$1`, run.RunID).Scan(&identity, &grant); err != nil {
		t.Fatal(err)
	}
	if err := d.RevokePublisherGrant(t.Context(), f.project.TeamID, identity, grant, f.project.ActorID, now); err != nil {
		t.Fatal(err)
	}
	if err := report(evidence, now); err == nil {
		t.Fatal("revoked publisher retained report authority")
	}
}

func TestIntegrationHTTPProtectionQuotasAndCleanup(t *testing.T) {
	f := newProtectionServiceFixture(t, httpprotection.Settings{TemporaryBlocks: true})
	d, now, run := f.database, f.now, f.run
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: f.service.ID}
	for n := range httpprotection.MaxBlocks - 1 {
		if _, err := d.pool.Exec(t.Context(), `INSERT INTO control.http_temporary_blocks VALUES($1,$2,$3,$4)`,
			scope.ID, ipdigest.Hash(fmt.Sprintf("198.51.100.%d", n)), now.Add(time.Minute), now); err != nil {
			t.Fatal(err)
		}
	}
	var workers sync.WaitGroup
	results := make(chan error, 8)
	for n := range 8 {
		workers.Go(func() {
			e := rejectionEvidence(now)
			e.SourceDigest = ipdigest.Hash(netip.AddrFrom4([4]byte{203, 0, 113, byte(n)}).String())
			results <- d.ReportHTTPProtectionRejections(t.Context(), scope, run.RunID, run.RunNumber, run.Token, e, now)
		})
	}
	workers.Wait()
	close(results)
	accepted := 0
	for err := range results {
		if err == nil {
			accepted++
		} else if !errors.Is(err, ErrHTTPProtectionCapacity) {
			t.Fatal(err)
		}
	}
	if accepted != 1 {
		t.Fatal("concurrent reports exceeded the service quota", accepted)
	}
	if _, err := d.ExpireServiceRuns(t.Context(), now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	count, err := controlstatedb.New(d.pool).CountHTTPTemporaryBlocks(t.Context(), scope.ID)
	if err != nil || count != 0 {
		t.Fatal("service maintenance retained expired mitigation history", count, err)
	}
}

func TestIntegrationHTTPProtectionDisabledModes(t *testing.T) {
	f := newProtectionServiceFixture(t, httpprotection.Settings{TemporaryBlocks: true})
	lease, err := f.database.RegisterIngress(t.Context(), IngressRegistration{
		IngressID: "disabled-protection", IngressRunID: mustOpaqueID(t, opaqueid.IngressRunPrefix),
		IngressPoolID: PrimaryIngressPoolID, HTTPS: true, ProtocolVersion: 1, ConnectionCapacity: 64,
	}, f.now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: f.service.ID}
	if err := f.database.ReportHTTPProtectionRejections(t.Context(), scope, f.run.RunID, f.run.RunNumber, f.run.Token, rejectionEvidence(f.now), f.now); err != nil {
		t.Fatal(err)
	}
	for _, settings := range []httpprotection.Settings{{}, {TemporaryBlocks: true, WAF: httpprotection.Detect}, {TemporaryBlocks: true, WAF: httpprotection.Off}} {
		setProtectionSettings(t, f, settings)
		if err := f.database.ReportHTTPProtectionRejections(t.Context(), scope, f.run.RunID, f.run.RunNumber, f.run.Token, rejectionEvidence(f.now), f.now); !errors.Is(err, ErrHTTPProtectionDisabled) {
			t.Fatal("disabled mode accepted evidence", err)
		}
		policy, err := f.database.ReadPublisherVisitorPolicy(t.Context(), scope, f.run.RunID, f.run.RunNumber, f.run.Token, 0, f.now)
		if err != nil || len(policy.TemporaryBlocks) != 0 {
			t.Fatal("disabled settings retained block enforcement", err)
		}
		snapshot, err := f.database.ReadIngressServices(t.Context(), lease.IngressLeaseIdentity, f.now)
		if err != nil || len(snapshot.Runs) != 1 || len(snapshot.Runs[0].TemporaryBlocks) != 0 {
			t.Fatal("disabled mode retained ingress source blocks", err)
		}
	}
}
