package controlstate

import (
	"crypto/ed25519"
	"crypto/rand"
	"slices"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/naming"
)

func TestIntegrationPrivateManagedLocalNamespacesAndCapturedPlans(t *testing.T) {
	d, now, _, _ := newPublishRunPrerequisites(t)
	r := appliedProjectRequest(t, d, now)
	declaration := ProjectServiceConfiguration{Name: "orders", Protocol: "postgres", Target: "db.internal:5432"}
	request := RealizeLocalProjectServiceRequest{TeamID: r.TeamID, ActorID: r.ActorID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint, Service: "orders", WorktreeKey: "source-worktree-a", WorktreeLabel: "feature-a", Configuration: declaration, Now: now}
	first, err := d.RealizeLocalProjectService(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if first.PrivateService == nil || first.PrivateService.ManagedTLS == nil {
		t.Fatal("local service has no mandatory native TLS identity")
	}
	record, err := d.GetPrivateService(t.Context(), first.ServiceID, r.ActorID)
	if err != nil {
		t.Fatal(err)
	}
	var domain, kind, label, slug string
	if err = d.pool.QueryRow(t.Context(), `SELECT domain.canonical_domain,domain.kind,member.managed_label,reservation.member_slug FROM control.private_services service JOIN control.domains domain ON domain.id=service.domain_id JOIN control.team_memberships member ON member.team_id=service.team_id AND member.identity_id=$2 AND member.removed_at IS NULL JOIN control.member_slug_reservations reservation ON reservation.id=member.slug_reservation_id WHERE service.id=$1`, record.ID, r.ActorID).Scan(&domain, &kind, &label, &slug); err != nil {
		t.Fatal(err)
	}
	want := "orders.feature-a." + naming.MemberNamespace(domain, kind == "managed", label, slug)
	if record.ManagedTLS.Hostname != want || record.ManagedTLS.Port < 1024 || record.DomainID == "" {
		t.Fatalf("local namespace or endpoint capture: %+v want %s", record, want)
	}
	request.WorktreeKey, request.WorktreeLabel = "source-worktree-b", "feature-b"
	other, err := d.RealizeLocalProjectService(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if other.ServiceID == first.ServiceID || other.PrivateService.ManagedTLS.Hostname == want || other.PrivateService.ManagedTLS.Port == record.ManagedTLS.Port {
		t.Fatal("worktrees share a service, port or certificate identity")
	}
	request.WorktreeKey, request.WorktreeLabel = "source-worktree-a", "feature-a"
	if _, err = d.pool.Exec(t.Context(), `UPDATE control.teams SET default_domain_id=NULL WHERE id=$1`, r.TeamID); err != nil {
		t.Fatal(err)
	}
	retry, err := d.RealizeLocalProjectService(t.Context(), request)
	if err != nil || retry.ServiceID != first.ServiceID || *retry.PrivateService.ManagedTLS != *record.ManagedTLS {
		t.Fatal("default changes renamed a captured endpoint", retry, err)
	}
	if _, err = d.pool.Exec(t.Context(), `UPDATE control.teams SET default_domain_id=$2 WHERE id=$1`, r.TeamID, record.DomainID); err != nil {
		t.Fatal(err)
	}
	creation := oidcRouteRequest(t, d, now)
	enrollment := publisherEnrollment(t, d, creation, PublisherScope{TeamID: r.TeamID, Kind: "private_service", PrivateServiceID: record.ID}, now)
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	access, err := d.RedeemPublisherEnrollment(t.Context(), enrollment.Key, public, now)
	if err != nil {
		t.Fatal(err)
	}
	prep, err := d.PreparePrivateServiceRun(t.Context(), record.ID, access, "managed-local", now, record.PrivateServiceMetadata)
	if err != nil {
		t.Fatal(err)
	}
	if prep.Hostname != want || prep.ServicePort != record.ManagedTLS.Port || prep.DomainID != record.DomainID || prep.CertificatePlan.Scope != want || !slices.Equal(prep.CertificatePlan.Identifiers, []string{want}) {
		t.Fatalf("local certificate authority widened: %+v", prep)
	}
	scoped, err := d.GetPrivateServiceForPublisher(t.Context(), record.ID, access, now)
	if err != nil || scoped.Source == nil || scoped.Source.SourceFingerprint != r.SourceFingerprint || scoped.Source.WorktreeKey != request.WorktreeKey {
		t.Fatal("publisher lost exact local provenance", scoped, err)
	}
	changed := request
	changed.SourceFingerprint = strings.Repeat("b", 64)
	if _, err = d.RealizeLocalProjectService(t.Context(), changed); err == nil {
		t.Fatal("another source adopted the endpoint")
	}
}
