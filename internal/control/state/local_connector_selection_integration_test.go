package state

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestIntegrationAppliedProjectLocalConnectorVisitorBinding(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "local_connector_binding")
	base := oidcRouteRequest(t, d, now)
	ctx := t.Context()
	if _, err := d.pool.Exec(ctx, `UPDATE control.teams SET kind='organization' WHERE id=$1`, base.TeamID); err != nil {
		t.Fatal(err)
	}
	member := addAuthorityMember(t, d, now, base.ActingIdentityID, base.TeamID, "connector-reader", TeamRoleMember)
	local := RealizeLocalProjectServiceRequest{TeamID: base.TeamID, ProjectKey: "orders-project", SourceFingerprint: strings.Repeat("a", 64), Service: "orders", WorktreeKey: "checkout-a", ActorID: base.ActingIdentityID, Configuration: ProjectServiceConfiguration{Name: "database", Target: "http://secret-target.internal:3000", Access: &ProjectServiceAccess{Team: true}}, Now: now}
	manual, err := d.CreateServiceAt(ctx, base.TeamID, base.ActingIdentityID, "orders", "manual-orders", ServicePlacement{}, now, ServiceMetadata{Protocol: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	first, err := d.RealizeLocalProjectService(ctx, local)
	if err != nil {
		t.Fatal(err)
	}
	local.WorktreeKey = "checkout-b"
	second, err := d.RealizeLocalProjectService(ctx, local)
	if err != nil || first.ServiceID == second.ServiceID || first.ServiceID == manual.ID || second.ServiceID == manual.ID {
		t.Fatal("worktrees or same-name service shared an identity", err)
	}
	other, err := d.CreateTeam(ctx, authorityTeamRequest(base.ActingIdentityID), now)
	if err != nil {
		t.Fatal(err)
	}
	local.TeamID = other.ID
	third, err := d.RealizeLocalProjectService(ctx, local)
	if err != nil || third.ServiceID == second.ServiceID {
		t.Fatal("teams shared an identity", err)
	}
	request := GetLocalProjectServiceRequest{TeamID: base.TeamID, ProjectKey: local.ProjectKey, SourceFingerprint: local.SourceFingerprint, Service: local.Service, WorktreeKey: "checkout-a", ActorID: member.IdentityID, Now: now}
	// the reader has ordinary team visitor access but cannot realize or read config.
	local.TeamID, local.ActorID = base.TeamID, member.IdentityID
	if _, err = d.RealizeLocalProjectService(ctx, local); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("ordinary visitor unexpectedly has management access", err)
	}
	if _, err = d.GetProjectConfiguration(ctx, request.TeamID, request.ProjectKey, member.IdentityID); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("ordinary visitor read project configuration", err)
	}
	// a read must not allocate resources, revisions, grants, or publisher runs.
	snapshot := func() string {
		t.Helper()
		var data string
		if err := d.pool.QueryRow(ctx, `SELECT jsonb_build_array(
		    (SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM control.services s),
		    (SELECT jsonb_agg(to_jsonb(g) ORDER BY id) FROM control.visitor_grants g),
		    (SELECT jsonb_agg(to_jsonb(l) ORDER BY team_id,project_key,service,worktree_key) FROM control.local_project_services l),
		    (SELECT count(*) FROM control.service_runs),
		    (SELECT count(*) FROM control.publisher_grants))::text`).Scan(&data); err != nil {
			t.Fatal(err)
		}
		return data
	}
	before := snapshot()
	for _, expected := range []LocalProjectService{first, second} {
		request.WorktreeKey = expected.WorktreeKey
		got, err := d.GetLocalProjectService(ctx, request)
		if err != nil || !reflect.DeepEqual(got, expected) {
			t.Fatal("visitor lookup lost exact provenance/metadata", got, err)
		}
		data, err := json.Marshal(got)
		if err != nil || strings.Contains(string(data), "secret-target") || strings.Contains(string(data), "configuration") || strings.Contains(string(data), "credential") {
			t.Fatal("visitor lookup exposed management data", string(data), err)
		}
	}
	for _, test := range []struct {
		name string
		edit func(*GetLocalProjectServiceRequest)
		want error
	}{
		{"unrealized worktree", func(r *GetLocalProjectServiceRequest) { r.WorktreeKey = "checkout-missing" }, ErrServiceAccess},
		{"another project", func(r *GetLocalProjectServiceRequest) { r.ProjectKey = "another-project" }, ErrServiceAccess},
		{"another service", func(r *GetLocalProjectServiceRequest) { r.Service = "database" }, ErrServiceAccess},
		{"cross team", func(r *GetLocalProjectServiceRequest) { r.TeamID = other.ID }, ErrServiceAccess},
		{"ungranted identity", func(r *GetLocalProjectServiceRequest) { r.ActorID = "missing-person" }, ErrServiceAccess},
		{"stale fingerprint", func(r *GetLocalProjectServiceRequest) { r.SourceFingerprint = strings.Repeat("b", 64) }, ErrProjectSourceConflict},
		{"unauthorized collision", func(r *GetLocalProjectServiceRequest) {
			r.SourceFingerprint = strings.Repeat("b", 64)
			r.ActorID = "missing-person"
		}, ErrServiceAccess},
		{"invalid fingerprint", func(r *GetLocalProjectServiceRequest) { r.SourceFingerprint = "invalid" }, ErrProjectConfigurationInvalid},
		{"invalid project", func(r *GetLocalProjectServiceRequest) { r.ProjectKey = "../orders" }, ErrProjectConfigurationInvalid},
		{"invalid service", func(r *GetLocalProjectServiceRequest) { r.Service = "ORDERS" }, ErrProjectConfigurationInvalid},
		{"empty worktree", func(r *GetLocalProjectServiceRequest) { r.WorktreeKey = "" }, ErrProjectConfigurationInvalid},
		{"invalid worktree", func(r *GetLocalProjectServiceRequest) { r.WorktreeKey = "checkout\n" }, ErrProjectConfigurationInvalid},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := request
			test.edit(&r)
			got, err := d.GetLocalProjectService(ctx, r)
			if !errors.Is(err, test.want) || got.ServiceID != "" {
				t.Fatal("lookup crossed scope or returned the wrong error", got, err)
			}
		})
	}
	if after := snapshot(); after != before {
		t.Fatal("visitor selection changed management state")
	}
	// expiry and revocation take effect on each lookup, even with unchanged provenance.
	if _, err = d.pool.Exec(ctx, `UPDATE control.visitor_grants SET expires_at=$2 WHERE service_id=$1 AND kind='team'`, second.ServiceID, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	request.Now = now.Add(time.Second)
	if _, err = d.GetLocalProjectService(ctx, request); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("expired visitor grant exposed a bound ID", err)
	}
	request.Now = now
	if err = d.RemoveMembership(ctx, base.ActingIdentityID, base.TeamID, member.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, err = d.GetLocalProjectService(ctx, request); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("removed membership exposed a bound ID", err)
	}
	request.ActorID = base.ActingIdentityID
	if _, err = d.pool.Exec(ctx, `UPDATE control.visitor_grants SET revoked_at=$2 WHERE service_id=$1`, second.ServiceID, now); err != nil {
		t.Fatal(err)
	}
	if _, err = d.GetLocalProjectService(ctx, request); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("manager bypassed revoked ordinary visitor access", err)
	}
}
