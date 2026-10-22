package controlstate

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/policy/publisherprovenance"
	publisheridentity "github.com/tnldotdev/tnl/internal/security/publisherproof"
)

func TestIntegrationPublisherDiagnosticsFreshness(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "publisher_diagnostics")
	ctx := t.Context()
	m := observability.New("control")
	t.Cleanup(func() { _ = m.Shutdown(t.Context()) })
	d.Instrument(m)
	ctx = observability.WithMetrics(ctx, m)
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{Publishers: map[string]ProjectPublisherGroup{"remote": {}}, Services: map[string]ProjectServiceConfiguration{"api": {Publisher: "remote", Target: "localhost:3000"}}}
	project, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := d.IssuePublisherGroupEnrollment(ctx, r.TeamID, r.ProjectKey, "remote", r.ActorID, 1, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	replica := enrollAppliedGroup(t, d, r, enrollment, now)
	const audience = "https://control.example/v1/publisher-runtime"
	const run = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	observe := func(action string, epoch int64) error {
		proof, err := publisheridentity.Sign(replica.member.PublisherIdentityID, replica.member.KeyID, publisheridentity.RuntimeScope(replica.member.GroupID, action, run, epoch, publisherprovenance.Digest(nil)), audience, replica.private, now)
		if err != nil {
			t.Fatal(err)
		}
		result, err := d.PublisherRuntime(ctx, PublisherRuntimeRequest{PublisherIdentityID: replica.member.PublisherIdentityID, ScopeID: replica.member.GroupID, ProcessRunID: run, Action: action, Assertion: proof, Audience: audience, ExpectedEpoch: epoch, Now: now})
		if err == nil && result.GroupLease != nil {
			replica.lease = *result.GroupLease
		}
		return err
	}
	if err := observe("start", 0); err != nil {
		t.Fatal(err)
	}
	if err := observe("renew", 0); !errors.Is(err, ErrPublisherRuntimeStale) {
		t.Fatal("stale runtime was not rejected", err)
	}
	if err := d.AcknowledgePublisherGroupConfiguration(ctx, replica.lease.AccessToken, project.Revision, project.ConfigurationHash, true, now); err != nil {
		t.Fatal(err)
	}
	read := func() PublisherGroupMemberStatus {
		t.Helper()
		status, err := d.GetProjectConfiguration(ctx, r.TeamID, r.ProjectKey, r.ActorID)
		if err != nil || len(status.Members) != 1 {
			t.Fatal(status, err)
		}
		return status.Members[0]
	}
	status := read()
	if !status.Healthy || status.CurrentRevision != 1 || status.ObservedRevision != 1 || status.AcknowledgedAt == nil || !status.AcknowledgedAt.Equal(now) || status.SnapshotAt.Before(now) || status.Runtime == nil || !status.Runtime.Active {
		t.Fatal("fresh acknowledgement unavailable", status)
	}
	restartedAt := now.Add(time.Second)
	const replacement = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	proof, err := publisheridentity.Sign(replica.member.PublisherIdentityID, replica.member.KeyID, publisheridentity.RuntimeScope(replica.member.GroupID, "start", replacement, 1, publisherprovenance.Digest(nil)), audience, replica.private, restartedAt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.PublisherRuntime(ctx, PublisherRuntimeRequest{PublisherIdentityID: replica.member.PublisherIdentityID, ScopeID: replica.member.GroupID, ProcessRunID: replacement, Action: "start", Assertion: proof, Audience: audience, ExpectedEpoch: 1, Now: restartedAt}); err != nil {
		t.Fatal(err)
	}
	status = read()
	if status.Healthy || status.Runtime == nil || !status.Runtime.Active || status.AcknowledgedAt != nil {
		t.Fatal("replacement runtime inherited its predecessor's healthy acknowledgement", status)
	}
	r.ExpectedRevision = project.Revision
	r.Configuration.Publishers["remote"] = ProjectPublisherGroup{Description: "changed"}
	if _, err := d.ApplyProjectConfiguration(ctx, r); err != nil {
		t.Fatal(err)
	}
	status = read()
	if status.Healthy || status.CurrentRevision != 2 || status.ObservedRevision != 1 || status.AcknowledgedAt != nil {
		t.Fatal("old acknowledgement became current", status)
	}
	if _, err := d.pool.Exec(ctx, `UPDATE control.publisher_runtimes SET lease_expires_at=$2 WHERE publisher_identity_id=$1`, replica.member.PublisherIdentityID, restartedAt.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	// inspect at an expired deadline using the state reader's explicit clock.
	status.Runtime, err = publisherRuntimeStatus(ctx, controlstatedb.New(d.pool), replica.member.PublisherIdentityID, restartedAt.Add(2*time.Second))
	if err != nil || status.Runtime.Active || !status.Runtime.LastSeenAt.Equal(restartedAt) {
		t.Fatal("expired runtime retained readiness or changed last seen", status.Runtime, err)
	}
	w := httptest.NewRecorder()
	m.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(w.Body.String(), `tnl_reason="stale"`) || !strings.Contains(w.Body.String(), "tnl_control_publisher_runtime_duration_seconds_count") {
		t.Fatal("signed runtime stale result missing")
	}
}
