package state

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
)

func TestIntegrationSharedPublicURLHTTPPolicyApplyPreservesBoundResources(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "shared_http_input")
	creation := oidcRouteRequest(t, d, now)
	u := createTestPublicURL(t, d, creation, now)
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{Services: map[string]ProjectServiceConfiguration{"web": {
		Target: "app", Access: &ProjectServiceAccess{Team: true},
		PublicURL: &ProjectServicePublicURL{Hostname: u.CanonicalHostname, Access: &ProjectPublicAccess{Mode: "restricted"},
			Limits: &ProjectPublicLimits{HTTP: &ProjectHTTPApplicationLimits{Total: new(100), Concurrency: new(3)}}},
	}}}
	local := RealizeLocalProjectServiceRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint,
		Service: "web", WorktreeKey: "checkout", ActorID: r.ActorID, PublicURLID: u.ID, Configuration: r.Configuration.Services["web"], Now: now}
	bound, err := d.RealizeLocalProjectService(t.Context(), local)
	if err != nil || bound.ServiceID != u.ID {
		t.Fatal("realize original public URL", err)
	}
	first, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	enrollment := publisherEnrollment(t, d, creation, PublisherScope{TeamID: r.TeamID, Kind: "saved_public_url", PublicURLID: u.ID}, now)
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.RedeemPublisherEnrollment(t.Context(), enrollment.Key, public, now); err != nil {
		t.Fatal(err)
	}
	snapshot := func() []byte {
		t.Helper()
		var data []byte
		err := d.pool.QueryRow(t.Context(), `SELECT jsonb_build_object(
			'url',(SELECT to_jsonb(u) FROM control.public_urls u WHERE id=$1),
			'bindings',(SELECT jsonb_agg(to_jsonb(b)) FROM control.local_project_services b WHERE public_url_id=$1),
			'publishers',(SELECT jsonb_agg(to_jsonb(g) ORDER BY id) FROM control.publisher_grants g WHERE public_url_id=$1),
			'visitors',(SELECT jsonb_agg(to_jsonb(g) ORDER BY id) FROM control.visitor_grants g WHERE public_url_id=$1))`, u.ID).Scan(&data)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	before := snapshot()
	s := r.Configuration.Services["web"]
	s.PublicURL = &ProjectServicePublicURL{Hostname: u.CanonicalHostname}
	s.HTTP = &config.HTTPService{Access: &config.Access{Mode: "restricted"}, Limits: &config.WorkLimits{Total: new(100), Concurrency: new(3)}}
	r.Configuration.Services["web"] = s
	r.ExpectedRevision = first.Revision
	after, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil || after.Revision != first.Revision || after.ConfigurationHash != first.ConfigurationHash {
		t.Fatal("syntax-only apply changed the saved configuration", err)
	}
	if !bytes.Equal(before, snapshot()) {
		t.Fatal("syntax-only apply changed the resource, binding or grants")
	}
	local.Configuration = s
	restarted, err := d.RealizeLocalProjectService(t.Context(), local)
	if err != nil || restarted.ServiceID != u.ID || restarted.Hostname != bound.Hostname {
		t.Fatal("shared HTTP policy realization replaced the bound resource", err)
	}
}
