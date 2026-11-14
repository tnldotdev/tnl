package state

import (
	"encoding/json"
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
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
)

func TestIntegrationHTTPProtectionSavedServicePublicAdmissionOnly(t *testing.T) {
	d, now, _, leases := newPublishRunPrerequisites(t)
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{"production": {Public: true}}, Services: map[string]ProjectServiceConfiguration{
		"web": {PublisherGroup: "production", Target: "app:3000", HTTP: &config.HTTPService{Protection: &httpprotection.Settings{TemporaryBlocks: true}}},
	}}
	applied, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := d.IssuePublisherGroupEnrollment(t.Context(), r.TeamID, r.ProjectKey, "production", r.ActorID, 1, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	replica := enrollAppliedGroup(t, d, r, enrollment, now)
	assignment := replica.assignments.Services[0]
	access := groupAssignmentAccess(t, d, replica, assignment, now)
	prep, err := d.PrepareServiceRun(t.Context(), assignment.ServiceID, access.PublisherIdentity, "protection", now, ServiceMetadata{Protocol: "http", TrustRevision: assignment.TrustRevision})
	if err != nil {
		t.Fatal(err)
	}
	run, err := d.StartServiceRun(t.Context(), assignment.ServiceID, prep.RunID, prep.RunNumber, access.PublisherIdentity, now)
	if err != nil {
		t.Fatal(err)
	}
	installPrivateTestCertificate(t, d, prep, run, now)
	for _, slot := range run.Connections {
		lease := leases[slot.RelayServiceID].RelayLeaseIdentity
		if _, err := d.ClaimServicePublisherConnection(t.Context(), slot.PublisherConnectionID, run.ServiceID, run.RunID, run.RunNumber, slot.Revision, slot.Credential, lease, now); err != nil {
			t.Fatal(err)
		}
		if _, err := d.ReadyServicePublisherConnection(t.Context(), slot.PublisherConnectionID, run.RunID, run.RunNumber, slot.Revision, lease, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := d.HeartbeatServiceRun(t.Context(), run.ServiceID, run.RunID, run.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil {
		t.Fatal(err)
	}
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: run.ServiceID}
	if err := d.ReportHTTPProtectionRejections(t.Context(), scope, run.RunID, run.RunNumber, run.Token, rejectionEvidence(now), now); err != nil {
		t.Fatal(err)
	}
	if err := d.PrepareVisitorSigningKeys(t.Context(), testVisitorIssuer, now); err != nil {
		t.Fatal(err)
	}
	policy, err := d.ReadPublisherVisitorPolicy(t.Context(), scope, run.RunID, run.RunNumber, run.Token, 0, now)
	if err != nil || len(policy.TemporaryBlocks) != 1 {
		t.Fatal("service policy did not project accepted blocks", err)
	}
	port := applied.Services[0].Port
	lease, err := d.RegisterIngress(t.Context(), IngressRegistration{IngressID: "protection", IngressRunID: mustOpaqueID(t, opaqueid.IngressRunPrefix), IngressPoolID: PrimaryIngressPoolID, ServicePorts: []int32{int32(port)}, ProtocolVersion: 1, ConnectionCapacity: 64}, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	admit := func(source string) error {
		_, err := d.AdmitPublicServiceVisitor(t.Context(), lease.IngressLeaseIdentity, PrimaryIngressPoolID, mustOpaqueID(t, opaqueid.VisitorConnectionPrefix), port, netip.MustParseAddr(source), now)
		return err
	}
	if err := admit("192.0.2.1"); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("public service admitted a blocked source", err)
	}
	if err := admit("192.0.2.2"); err != nil {
		t.Fatal("public service block widened to a neighboring IP", err)
	}
	q := controlstatedb.New(d.pool)
	if err := d.serviceHTTPSourceAllowed(t.Context(), q, run.ServiceID, netip.MustParseAddr("192.0.2.1")); err != nil {
		t.Fatal("HTTP mitigation leaked into connector source policy", err)
	}
	if err := d.publicHTTPSourceAllowed(t.Context(), q, run.ServiceID, netip.MustParseAddr("192.0.2.1"), now.Add(time.Minute)); err != nil {
		t.Fatal("public service block did not expire", err)
	}
	service := r.Configuration.Services["web"]
	service.HTTP.Protection.WAF = httpprotection.Detect
	r.Configuration.Services["web"] = service
	r.ExpectedRevision = applied.Revision
	if _, err := d.ApplyProjectConfiguration(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	if err := d.publicHTTPSourceAllowed(t.Context(), q, run.ServiceID, netip.MustParseAddr("192.0.2.1"), now); err != nil {
		t.Fatal("leaving block mode retained public service enforcement", err)
	}
	if err := d.ReportHTTPProtectionRejections(t.Context(), scope, run.RunID, run.RunNumber, run.Token, rejectionEvidence(now), now); err == nil {
		t.Fatal("old service settings retained report authority")
	}
}

func TestIntegrationHTTPProtectionRoutingProjectionAndRestart(t *testing.T) {
	f, auth := finalVisitorRun(t, "http")
	d, now := f.database, f.now
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.publish_runs SET http_protection='{"temporary_blocks":true}' WHERE id=$1`, auth.PublishRunID); err != nil {
		t.Fatal(err)
	}
	prepareServingPublisher(t, *f)
	scope := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: auth.PublicURLID}
	evidence := rejectionEvidence(now)
	report := func() error {
		return d.ReportHTTPProtectionRejections(t.Context(), scope, auth.PublishRunID, int64(auth.PublishRunNumber), auth.PublishRunToken.String(), evidence, now)
	}
	if err := report(); err != nil {
		t.Fatal(err)
	}
	var payload []byte
	var revision int64
	readProjection := func() IngressRoutingTableProjection {
		t.Helper()
		if err := d.pool.QueryRow(t.Context(), `SELECT id,projection FROM control.ingress_routing_table_events WHERE public_url_id=$1 AND event_kind='public_url_upsert' ORDER BY id DESC LIMIT 1`, auth.PublicURLID).Scan(&revision, &payload); err != nil {
			t.Fatal(err)
		}
		var projection IngressRoutingTableProjection
		if err := json.Unmarshal(payload, &projection); err != nil {
			t.Fatal(err)
		}
		return projection
	}
	projected := readProjection()
	if len(projected.TemporaryBlocks) != 1 || projected.TemporaryBlocks[0].SourceIP != evidence.SourceIP || len(projected.PublisherConnections) != 2 {
		t.Fatal("routing update lost blocks or connected relays", projected)
	}
	before := revision
	if err := report(); err != nil {
		t.Fatal(err)
	}
	readProjection()
	if revision != before {
		t.Fatal("duplicate report produced another routing update")
	}
	if err := d.PrepareVisitorSigningKeys(t.Context(), testVisitorIssuer, now); err != nil {
		t.Fatal(err)
	}
	if err := d.ClosePublishRun(t.Context(), auth.PublishRunID, auth.PublishRunToken, now); err != nil {
		t.Fatal(err)
	}
	if err := report(); err == nil {
		t.Fatal("closed run retained reporting authority")
	}
	request := f.request
	request.IdempotencyKey = "replacement"
	url, err := controlstatedb.New(d.pool).GetFeedbackPublicURL(t.Context(), auth.PublicURLID)
	if err != nil {
		t.Fatal(err)
	}
	request.ExpectedMutationRevision = uint64(url.MutationRevision)
	for _, enabled := range []bool{true, false} {
		request.HTTPProtection.TemporaryBlocks = enabled
		setup, err := d.CreatePublishRun(t.Context(), request, now, time.Hour, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		policy, err := d.ReadPublisherVisitorPolicy(t.Context(), scope, setup.PublishRunID, int64(setup.PublishRunNumber), setup.PublishRunToken.String(), 0, now)
		if err != nil || (len(policy.TemporaryBlocks) == 1) != enabled {
			t.Fatal("restart lost resource blocks or ignored new settings", enabled, err)
		}
		if !enabled {
			break
		}
		next := PublishRunAuthentication{PublicURLID: auth.PublicURLID, PublishRunID: setup.PublishRunID, PublishRunNumber: setup.PublishRunNumber, PublishRunToken: setup.PublishRunToken}
		if err := d.ClosePublishRun(t.Context(), next.PublishRunID, next.PublishRunToken, now); err != nil {
			t.Fatal(err)
		}
		url, err = controlstatedb.New(d.pool).GetFeedbackPublicURL(t.Context(), auth.PublicURLID)
		if err != nil {
			t.Fatal(err)
		}
		request.ExpectedMutationRevision, request.IdempotencyKey = uint64(url.MutationRevision), "disabled"
	}
}

func rejectionEvidence(now time.Time) httpprotection.Rejections {
	return httpprotection.Rejections{SourceIP: "192.0.2.1", StartedAt: now.Add(-time.Second), EndedAt: now, Count: 10, RuleIDs: []int{942100}}
}

func TestIntegrationHTTPProtectionRunSettingsAndIdempotency(t *testing.T) {
	d, now, request, _ := newPublishRunPrerequisites(t)
	request.HTTPProtection.TemporaryBlocks = true
	setup, err := d.CreatePublishRun(t.Context(), request, now, time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := controlstatedb.New(d.pool).GetPublishRun(t.Context(), setup.PublishRunID)
	var settings httpprotection.Settings
	if err != nil || json.Unmarshal(stored.HttpProtection, &settings) != nil || !settings.BlocksSources() {
		t.Fatal("run creation lost effective protection", err)
	}
	retry, err := d.CreatePublishRun(t.Context(), request, now, time.Hour, time.Minute)
	if err != nil || retry.PublishRunID != setup.PublishRunID || retry.PublishRunToken != setup.PublishRunToken {
		t.Fatal("identical protection changed retry credentials", err)
	}
	request.HTTPProtection.TemporaryBlocks = false
	if _, err := d.CreatePublishRun(t.Context(), request, now, time.Hour, time.Minute); !errors.Is(err, ErrPublishRunIdempotency) {
		t.Fatal("changed protection reused idempotency key", err)
	}
}

func TestIntegrationHTTPProtectionFixedExpiryFreshnessAndResourceScope(t *testing.T) {
	f, auth := finalVisitorRun(t, "http")
	d, now := f.database, f.now
	scope := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: auth.PublicURLID}
	setMode := func(raw string) {
		t.Helper()
		if _, err := d.pool.Exec(t.Context(), `UPDATE control.publish_runs SET http_protection=$2::jsonb WHERE id=$1`, auth.PublishRunID, raw); err != nil {
			t.Fatal(err)
		}
	}
	report := func(e httpprotection.Rejections, at time.Time) error {
		return d.ReportHTTPProtectionRejections(t.Context(), scope, auth.PublishRunID, int64(auth.PublishRunNumber), auth.PublishRunToken.String(), e, at)
	}
	evidence := rejectionEvidence(now)
	if err := report(evidence, now); !errors.Is(err, ErrHTTPProtectionDisabled) {
		t.Fatal("default settings enabled source blocks", err)
	}
	setMode(`{"temporary_blocks":true}`)
	if err := d.PrepareVisitorSigningKeys(t.Context(), testVisitorIssuer, now); err != nil {
		t.Fatal(err)
	}
	if err := report(evidence, now); err != nil {
		t.Fatal(err)
	}
	read := func(at time.Time) []httpprotection.TemporaryBlock {
		t.Helper()
		policy, err := d.ReadPublisherVisitorPolicy(t.Context(), scope, auth.PublishRunID, int64(auth.PublishRunNumber), auth.PublishRunToken.String(), 0, at)
		if err != nil {
			t.Fatal(err)
		}
		return policy.TemporaryBlocks
	}
	blocks := read(now)
	if len(blocks) != 1 || blocks[0].SourceIP != evidence.SourceIP || !blocks[0].ExpiresAt.Equal(now.Add(time.Minute)) {
		t.Fatal("report did not retain a fixed resource/IP expiry", blocks)
	}
	if err := report(evidence, now.Add(5*time.Second)); err != nil {
		t.Fatal("retry did not recover a lost response", err)
	}
	if got := read(now.Add(5 * time.Second)); len(got) != 1 || !got[0].ExpiresAt.Equal(blocks[0].ExpiresAt) {
		t.Fatal("retry extended a block", got)
	}
	if err := report(evidence, now.Add(11*time.Second)); !errors.Is(err, ErrVisitorPolicy) {
		t.Fatal("stale queued evidence recreated a penalty", err)
	}
	for _, raw := range []string{`{}`, `{"temporary_blocks":true,"waf":"detect"}`, `{"temporary_blocks":true,"waf":"off"}`} {
		setMode(raw)
		if len(read(now)) != 0 || !errors.Is(report(evidence, now), ErrHTTPProtectionDisabled) {
			t.Fatal("disabled settings enforced or accepted temporary blocks", raw)
		}
	}
	setMode(`{"temporary_blocks":true}`)
	if len(read(now.Add(time.Minute))) != 0 {
		t.Fatal("expired records remained active")
	}
	staleWindow := evidence
	staleWindow.StartedAt, staleWindow.EndedAt = now.Add(59*time.Second), now.Add(61*time.Second)
	if err := report(staleWindow, staleWindow.EndedAt); err != nil {
		t.Fatal(err)
	}
	if len(read(staleWindow.EndedAt)) != 0 {
		t.Fatal("rejections during the previous block counted toward replacement")
	}
	// even the oldest accepted window must not cross an earlier expiry after
	// ordinary cleanup would otherwise have forgotten that block.
	delayed := rejectionEvidence(now)
	delayed.StartedAt, delayed.EndedAt = now.Add(51*time.Second), now.Add(111*time.Second)
	if err := report(delayed, now.Add(121*time.Second)); err != nil || len(read(now.Add(121*time.Second))) != 0 {
		t.Fatal("delayed evidence recreated a block after early history cleanup", err)
	}
	fresh := rejectionEvidence(now.Add(123 * time.Second))
	if err := report(fresh, fresh.EndedAt); err != nil {
		t.Fatal(err)
	}
	if len(read(fresh.EndedAt)) != 1 {
		t.Fatal("fresh evidence after expiry did not create a new block")
	}
	other := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: mustOpaqueID(t, "url_")}
	if err := d.ReportHTTPProtectionRejections(t.Context(), other, auth.PublishRunID, int64(auth.PublishRunNumber), auth.PublishRunToken.String(), evidence, now); err == nil {
		t.Fatal("report escaped its resource")
	}
	if err := d.ReportHTTPProtectionRejections(t.Context(), scope, auth.PublishRunID, int64(auth.PublishRunNumber+1), auth.PublishRunToken.String(), evidence, now); err == nil {
		t.Fatal("report escaped its run number")
	}
	if err := d.ReportHTTPProtectionRejections(t.Context(), scope, auth.PublishRunID, int64(auth.PublishRunNumber), "wrong-token", evidence, now); err == nil {
		t.Fatal("report accepted another credential")
	}
}

func TestIntegrationHTTPProtectionQuotasSerializeAndCleanup(t *testing.T) {
	f, auth := finalVisitorRun(t, "http")
	d, now := f.database, f.now
	scope := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: auth.PublicURLID}
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.publish_runs SET http_protection='{"temporary_blocks":true}' WHERE id=$1`, auth.PublishRunID); err != nil {
		t.Fatal(err)
	}
	for n := range httpprotection.MaxBlocks - 1 {
		_, err := d.pool.Exec(t.Context(), `INSERT INTO control.http_temporary_blocks VALUES('public_url',$1,$2,$3,$4)`, scope.ID, fmt.Sprintf("198.51.100.%d", n), now.Add(time.Minute), now)
		if err != nil {
			t.Fatal(err)
		}
	}
	var workers sync.WaitGroup
	results := make(chan error, 8)
	for n := range 8 {
		workers.Go(func() {
			e := rejectionEvidence(now)
			e.SourceIP = netip.AddrFrom4([4]byte{203, 0, 113, byte(n)}).String()
			results <- d.ReportHTTPProtectionRejections(t.Context(), scope, auth.PublishRunID, int64(auth.PublishRunNumber), auth.PublishRunToken.String(), e, now)
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
		t.Fatal("concurrent reports exceeded the resource quota", accepted)
	}
	if err := d.ExpireVisitorPermissions(t.Context(), now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	count, err := controlstatedb.New(d.pool).CountHTTPTemporaryBlocks(t.Context(), controlstatedb.CountHTTPTemporaryBlocksParams{ResourceKind: "public_url", ResourceID: scope.ID})
	if err != nil || count != 0 {
		t.Fatal("existing maintenance did not prune expired mitigation state", count, err)
	}
}

func TestIntegrationHTTPProtectionPublisherRevocationFencesReports(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "protection_authority")
	creation := oidcRouteRequest(t, d, now)
	url := createTestPublicURL(t, d, creation, now)
	registerCertificatePlanRelays(t, d, now)
	identity, private := reviewPublisher(t, d, url, creation.ActingIdentityID, now)
	request := reviewRunRequest(t, d, identity, private, url, "protection")
	request.HTTPProtection.TemporaryBlocks = true
	setup, err := d.CreatePublishRun(t.Context(), request, now, time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	scope := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: url.ID}
	report := func() error {
		return d.ReportHTTPProtectionRejections(t.Context(), scope, setup.PublishRunID, int64(setup.PublishRunNumber), setup.PublishRunToken.String(), rejectionEvidence(now), now)
	}
	if err := report(); err != nil {
		t.Fatal(err)
	}
	if err := d.RevokePublisherGrant(t.Context(), url.TeamID, identity.ID, identity.GrantID, creation.ActingIdentityID, now); err != nil {
		t.Fatal(err)
	}
	if err := report(); !errors.Is(err, ErrPublishRunCredential) {
		t.Fatal("revoked publisher retained report authority", err)
	}
}
