package state

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestIntegrationPostQuantumPublicURLPersistsAcrossReadsAndRuns(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "post_quantum_public_url")
	request := oidcRouteRequest(t, database, now)
	request.RequirePostQuantum = true
	request.AllowedIPPrefixes = []string{}
	publicURL := createTestPublicURL(t, database, request, now)
	for name, read := range map[string]func() (PublicURL, error){
		"identity": func() (PublicURL, error) {
			return database.GetPublicURL(t.Context(), request.ActingIdentityID, publicURL.ID)
		},
		"authorization": func() (PublicURL, error) { return database.GetPublicURLForAuthorization(t.Context(), publicURL.ID) },
		"hostname": func() (PublicURL, error) {
			return database.GetAuthorizedPublicURLByHostname(t.Context(), publicURL.TeamID, publicURL.CanonicalHostname)
		},
		"retry": func() (PublicURL, error) { return database.CreatePublicURL(t.Context(), request, now) },
	} {
		t.Run(name, func(t *testing.T) {
			u, err := read()
			if err != nil || !u.RequirePostQuantum {
				t.Fatalf("saved requirement lost: %+v, %v", u, err)
			}
		})
	}
	page, err := database.ListPublicURLs(t.Context(), request.ActingIdentityID, publicURL.TeamID, "")
	if err != nil || len(page.PublicURLs) != 1 || !page.PublicURLs[0].RequirePostQuantum {
		t.Fatalf("list lost saved requirement: %+v, %v", page, err)
	}
	update := AuthorizedPublicURLUpdateRequest{PublicURLID: publicURL.ID, TeamID: publicURL.TeamID, ActingIdentityID: request.ActingIdentityID,
		Target: publicURL.Target, AllowedIPPrefixes: request.AllowedIPPrefixes, PolicyRevision: uint64(publicURL.PolicyRevision), ExpectedMutationRevision: publicURL.MutationRevision}
	updated, err := database.UpdateAuthorizedPublicURL(t.Context(), update, now)
	if err != nil || !updated.RequirePostQuantum {
		t.Fatalf("omitted requirement was cleared: %+v, %v", updated, err)
	}
	update.ExpectedMutationRevision = updated.MutationRevision
	update.RequirePostQuantum = new(false)
	insertTestPublishRun(t, database, testPublishRun{ID: "run_post_quantum", PublicURLID: publicURL.ID, TeamID: publicURL.TeamID,
		MembershipID: publicURL.MembershipID, ActingIdentityID: request.ActingIdentityID, CertificateCacheKey: "post-quantum", CertificateScope: "route",
		CertificateIdentifiers: []string{publicURL.CanonicalHostname}, ChallengeMethod: "dns-01", CreatedAt: now, ExpiresAt: now.Add(time.Minute)})
	if _, err := database.UpdateAuthorizedPublicURL(t.Context(), update, now); !errors.Is(err, ErrPublishRunOpen) {
		t.Fatalf("live run's TLS requirement changed: %v", err)
	}
	updated, err = database.UpdateAuthorizedPublicURL(t.Context(), update, now.Add(2*time.Minute))
	if err != nil || updated.RequirePostQuantum {
		t.Fatalf("explicit false was not saved after the run expired: %+v, %v", updated, err)
	}
}

func TestIntegrationPostQuantumAppliedPublicURLPolicy(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "post_quantum_applied_url")
	request := oidcRouteRequest(t, database, now)
	publicURL := createTestPublicURL(t, database, request, now)
	service := ProjectServiceConfiguration{Target: "app", PublicURL: &ProjectServicePublicURL{}}
	local := RealizeLocalProjectServiceRequest{TeamID: request.TeamID, ProjectKey: "post-quantum", SourceFingerprint: strings.Repeat("a", 64), Service: "web", WorktreeKey: "checkout", ActorID: request.ActingIdentityID, PublicURLID: publicURL.ID, Configuration: service, Now: now}
	if _, err := database.RealizeLocalProjectService(t.Context(), local); err != nil {
		t.Fatal(err)
	}
	apply := ApplyProjectConfigurationRequest{TeamID: request.TeamID, ProjectKey: local.ProjectKey, SourceFingerprint: local.SourceFingerprint, ActorID: request.ActingIdentityID,
		Deployment: "local", ServiceDeclarations: map[string]string{"web": "http"},
		Configuration: ProjectConfiguration{Services: map[string]ProjectServiceConfiguration{"web": service}}, Now: now}
	applied, err := database.ApplyProjectConfiguration(t.Context(), apply)
	if err != nil {
		t.Fatal(err)
	}
	apply.ExpectedRevision = applied.Revision
	service.PublicURL.RequirePostQuantum = new(true)
	service.PublicURL.Access = &ProjectPublicAccess{Mode: string(VisitorAccessAnonymous)}
	apply.Configuration.Services["web"] = service
	applied, err = database.ApplyProjectConfiguration(t.Context(), apply)
	if err != nil {
		t.Fatal(err)
	}
	u, err := database.GetPublicURLForAuthorization(t.Context(), publicURL.ID)
	if err != nil || !u.RequirePostQuantum || u.AccessMode != VisitorAccessAnonymous {
		t.Fatalf("apply lost TLS or access policy: %+v, %v", u, err)
	}
	apply.ExpectedRevision = applied.Revision
	service.PublicURL.RequirePostQuantum = nil
	applied, err = database.ApplyProjectConfiguration(t.Context(), apply)
	if err != nil {
		t.Fatal(err)
	}
	u, err = database.GetPublicURLForAuthorization(t.Context(), publicURL.ID)
	if err != nil || !u.RequirePostQuantum {
		t.Fatalf("apply omission cleared saved policy: %+v, %v", u, err)
	}
	insertTestPublishRun(t, database, testPublishRun{ID: "run_post_quantum_applied", PublicURLID: u.ID, TeamID: u.TeamID,
		MembershipID: u.MembershipID, ActingIdentityID: request.ActingIdentityID, CertificateCacheKey: "post-quantum-applied", CertificateScope: "route",
		CertificateIdentifiers: []string{u.CanonicalHostname}, ChallengeMethod: "dns-01", CreatedAt: now, ExpiresAt: now.Add(time.Minute)})
	apply.ExpectedRevision = applied.Revision
	service.PublicURL.RequirePostQuantum = new(false)
	if _, err := database.ApplyProjectConfiguration(t.Context(), apply); !errors.Is(err, ErrPublishRunOpen) {
		t.Fatalf("apply changed TLS policy during a run: %v", err)
	}
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.publish_runs SET closed_at=$2,state='closed',close_reason='test' WHERE id=$1`, "run_post_quantum_applied", now); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ApplyProjectConfiguration(t.Context(), apply); err != nil {
		t.Fatal(err)
	}
	u, err = database.GetPublicURLForAuthorization(t.Context(), publicURL.ID)
	if err != nil || u.RequirePostQuantum {
		t.Fatalf("apply did not clear explicit false: %+v, %v", u, err)
	}
}
