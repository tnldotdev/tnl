package controlapi

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	controlclient "github.com/tnldotdev/tnl/internal/client/control"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/policy/publisherprovenance"
	publisheridentity "github.com/tnldotdev/tnl/internal/security/publisherproof"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestIntegrationPublisherRuntimeDeployment(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	ctx := t.Context()
	dsn := testutil.NewDisposablePostgresDatabaseURL(t, "deployment_runtime")
	if err := controlstate.Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	d, err := controlstate.Open(ctx, dsn, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	session, err := controltest.Session(ctx, d, "example.test", time.Hour, 24*time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	team := session.Identity.Memberships[0].TeamID
	const server = "https://control.example"
	h, err := NewHandler(Config{ControlURL: server}, d, d, nil)
	if err != nil {
		t.Fatal(err)
	}
	transport := &runtimeHTTPTransport{handler: h, peer: "8.8.8.8:1234"}
	httpClient := &http.Client{Transport: transport}
	owner, err := controlclient.New(server, httpClient, session.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	client, err := controlclient.New(server, httpClient, "")
	if err != nil {
		t.Fatal(err)
	}
	group := "production"
	applied, err := owner.ApplyProjectConfiguration(ctx, "deployment", controlv1.ApplyProjectConfigurationRequest{TeamId: team, SourceFingerprint: strings.Repeat("a", 64), Configuration: controlv1.ProjectConfiguration{Publishers: map[string]controlv1.ProjectPublisherGroup{group: {}}, Services: map[string]controlv1.ProjectServiceConfiguration{"api": {Publisher: &group, Target: "api.internal:3000"}}}})
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := owner.CreatePublisherGroupEnrollment(ctx, "deployment", group, controlv1.CreatePublisherGroupEnrollmentRequest{TeamId: team, MaxMembers: 2, ExpiresIn: 600})
	if err != nil {
		t.Fatal(err)
	}
	public, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	member, err := client.RedeemPublisherGroupEnrollment(ctx, enrollment.EnrollmentKey, public)
	if err != nil {
		t.Fatal(err)
	}
	otherPublic, otherKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	other, err := client.RedeemPublisherGroupEnrollment(ctx, enrollment.EnrollmentKey, otherPublic)
	if err != nil {
		t.Fatal(err)
	}
	report := controlv1.PublisherDeploymentReport{DeploymentId: "aws-" + strings.Repeat("a", 40), Provider: "aws", ReplicaKey: "replica-1", Instance: "aws-instance", Image: "ghcr.io/tnldotdev/tnl@sha256:" + strings.Repeat("a", 64), SoftwareVersion: "v1.2.3", TemplateVersion: "2", TemplateSha256: strings.Repeat("b", 64)}
	request := func(m controlv1.PublisherGroupMember, key ed25519.PrivateKey, action controlv1.PublisherRuntimeRequestAction, run string, epoch int64, report *controlv1.PublisherDeploymentReport) controlv1.PublisherRuntimeRequest {
		t.Helper()
		scope := publisheridentity.RuntimeScope(m.GroupId, string(action), run, epoch, publisherprovenance.Digest(report))
		proof, err := publisheridentity.Sign(m.PublisherIdentityId, m.KeyId, scope, server+"/v1/publisher-runtime", key, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return controlv1.PublisherRuntimeRequest{PublisherIdentityId: m.PublisherIdentityId, ScopeId: m.GroupId, ProcessRunId: run, ExpectedEpoch: epoch, Action: action, Assertion: proof, Deployment: report}
	}
	read := func(id string) *controlv1.PublisherRuntimeStatus {
		t.Helper()
		page, err := owner.ListPublisherIdentities(ctx, team, "")
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range page.Identities {
			if p.Id == id {
				return p.Runtime
			}
		}
		t.Fatal("publisher missing from authorized status")
		return nil
	}
	runA, runB := strings.Repeat("a", 32), strings.Repeat("b", 32)
	if _, err := client.PublisherRuntime(ctx, request(member, key, controlv1.RuntimeInspect, runA, 0, &report)); err != nil {
		t.Fatal(err)
	}
	if read(member.PublisherIdentityId) != nil {
		t.Fatal("inspect or enrollment recorded deployment")
	}
	// changing a field or removing the report without resigning cannot create an observation.
	for _, remove := range []bool{false, true} {
		copy := report
		r := request(member, key, controlv1.RuntimeStart, runA, 0, &copy)
		if remove {
			r.Deployment = nil
		} else {
			copy.TemplateSha256 = strings.Repeat("c", 64)
		}
		if _, err := client.PublisherRuntime(ctx, r); !errors.Is(err, controlclient.ErrUnauthenticated) {
			t.Fatal("unsigned deployment change accepted", err)
		}
	}
	for _, field := range []string{"team_id", "group_id", "publisher_identity_id"} {
		r := request(member, key, controlv1.RuntimeStart, runA, 0, &report)
		data, _ := json.Marshal(r)
		var body map[string]any
		if json.Unmarshal(data, &body) != nil {
			t.Fatal("fixture JSON")
		}
		body["deployment"].(map[string]any)[field] = "private-foreign-tenant"
		data, _ = json.Marshal(body)
		response, err := httpClient.Post(server+"/v1/publisher-runtime", "application/json", bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != 400 {
			t.Fatal("payload accepted tenant authority", field, response.StatusCode)
		}
	}
	firstRequest := request(member, key, controlv1.RuntimeStart, runA, 0, &report)
	if _, err := client.PublisherRuntime(ctx, firstRequest); err != nil {
		t.Fatal(err)
	}
	first := read(member.PublisherIdentityId)
	if first == nil || first.Deployment == nil || first.TeamId != team || first.PublisherIdentityId != member.PublisherIdentityId || first.Deployment.GroupId != member.GroupId || first.Deployment.Evidence != "publisher_reported" || first.Deployment.Report != report || first.Deployment.FirstObservedAt.IsZero() || first.Deployment.ObservedAt.Before(first.Deployment.FirstObservedAt) {
		t.Fatal("deployment observation lost server identity or receipt times")
	}
	if _, err := client.PublisherRuntime(ctx, firstRequest); !errors.Is(err, controlclient.ErrUnauthenticated) {
		t.Fatal("assertion replay accepted", err)
	}
	if _, err := client.PublisherRuntime(ctx, request(member, key, controlv1.RuntimeStart, runA, 0, &report)); err != nil {
		t.Fatal("lost-start recovery", err)
	}
	if !reflect.DeepEqual(first, read(member.PublisherIdentityId)) {
		t.Fatal("lost start rewrote observation")
	}
	changed := report
	changed.TemplateSha256 = strings.Repeat("c", 64)
	changed.SoftwareVersion = "v1.2.4"
	if _, err := client.PublisherRuntime(ctx, request(member, key, controlv1.RuntimeRenew, runA, 1, &changed)); !errors.Is(err, controlclient.ErrStatusConflict) {
		t.Fatal("renew changed process report", err)
	}
	if _, err := client.PublisherRuntime(ctx, request(member, key, controlv1.RuntimeStart, runA, 0, &changed)); !errors.Is(err, controlclient.ErrStatusConflict) {
		t.Fatal("lost start changed process report", err)
	}
	if _, err := client.PublisherRuntime(ctx, request(member, key, controlv1.RuntimeRenew, runA, 1, &report)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.PublisherRuntime(ctx, request(member, key, controlv1.RuntimeStop, runA, 1, &report)); err != nil {
		t.Fatal(err)
	}
	if stopped := read(member.PublisherIdentityId); stopped.Active || stopped.Deployment == nil {
		t.Fatal("stop discarded deployment evidence")
	}
	if _, err := client.PublisherRuntime(ctx, request(member, key, controlv1.RuntimeStart, runB, 1, &changed)); err != nil {
		t.Fatal("replacement did not report new software", err)
	}
	replaced := read(member.PublisherIdentityId)
	if replaced.Deployment.Report != changed || !replaced.Deployment.FirstObservedAt.Equal(first.Deployment.FirstObservedAt) || !replaced.Deployment.ObservedAt.After(first.Deployment.ObservedAt) {
		t.Fatal("replacement changed binding history or lost fresh report")
	}
	for _, next := range []*controlv1.PublisherDeploymentReport{nil, &report} {
		if next != nil {
			copy := *next
			copy.ReplicaKey = "replica-2"
			next = &copy
		}
		if _, err := client.PublisherRuntime(ctx, request(member, key, controlv1.RuntimeStart, strings.Repeat("c", 32), 2, next)); !errors.Is(err, controlclient.ErrStatusConflict) {
			t.Fatal("publisher silently rebound deployment", err)
		}
	}
	if _, err := client.PublisherRuntime(ctx, request(other, otherKey, controlv1.RuntimeStart, runA, 0, &report)); !errors.Is(err, controlclient.ErrStatusConflict) {
		t.Fatal("another publisher claimed observed replica", err)
	}
	if read(other.PublisherIdentityId) != nil {
		t.Fatal("conflicting replica recorded runtime")
	}
	second := report
	second.ReplicaKey = "replica-2"
	second.Instance = "aws-second"
	if _, err := client.PublisherRuntime(ctx, request(other, otherKey, controlv1.RuntimeStart, runA, 0, &second)); err != nil {
		t.Fatal("independent replica", err)
	}
	wrong := request(member, key, controlv1.RuntimeRenew, runB, 2, &changed)
	wrong.ScopeId = "pgrp_foreign"
	if _, err := client.PublisherRuntime(ctx, wrong); !errors.Is(err, controlclient.ErrUnauthenticated) {
		t.Fatal("foreign group accepted", err)
	}
	wrong = request(member, key, controlv1.RuntimeRenew, runB, 2, &changed)
	wrong.PublisherIdentityId = other.PublisherIdentityId
	if _, err := client.PublisherRuntime(ctx, wrong); !errors.Is(err, controlclient.ErrUnauthenticated) {
		t.Fatal("another publisher identity accepted the original signing key", err)
	}
	if _, err := owner.RenamePublisherGroup(ctx, "deployment", group, controlv1.RenamePublisherGroupRequest{TeamId: team, Name: "live", ExpectedRevision: applied.Revision}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(replaced, read(member.PublisherIdentityId)) {
		t.Fatal("group rename changed observed deployment")
	}
	project, err := owner.GetProjectConfiguration(ctx, team, "deployment")
	if err != nil || len(project.Members) != 2 || project.Members[0].Runtime == nil || project.Members[0].Runtime.Deployment == nil {
		t.Fatal("applied project omitted provenance", err)
	}
	metadata, err := owner.GetProjectPublicMetadata(ctx, team, "deployment")
	if err != nil {
		t.Fatal(err)
	}
	publicJSON, _ := json.Marshal(metadata)
	if bytes.Contains(publicJSON, []byte("publisher_reported")) || bytes.Contains(publicJSON, []byte(report.TemplateSha256)) || bytes.Contains(publicJSON, []byte(report.DeploymentId)) {
		t.Fatal("deployment report leaked into browser-safe metadata")
	}
	if _, err := owner.GetProjectConfiguration(ctx, "team_foreign", "deployment"); !errors.Is(err, controlclient.ErrNotFound) {
		t.Fatal("foreign team read deployment", err)
	}
	if err := owner.RevokePublisherGroupMember(ctx, team, "deployment", "live", member.PublisherIdentityId); err != nil {
		t.Fatal(err)
	}
	if _, err := client.PublisherRuntime(ctx, request(member, key, controlv1.RuntimeRenew, runB, 2, &changed)); !errors.Is(err, controlclient.ErrUnauthenticated) {
		t.Fatal("revoked publisher wrote observation", err)
	}
	if revoked := read(member.PublisherIdentityId); revoked.Active || revoked.Deployment == nil || revoked.Deployment.Report != changed {
		t.Fatal("revocation lost or activated historical report")
	}
}
