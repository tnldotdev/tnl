package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/naming"
)

func TestIntegrationHostedPreviewCertificateScope(t *testing.T) {
	e := newRestoredCertificateEnvironment(t, DomainKindManaged, naming.ManagedURLModeGenerated, false)
	d, ctx := e.database, t.Context()
	issue := func() PublisherIdentity {
		t.Helper()
		enrollment, err := d.IssuePublisherEnrollment(ctx, CreatePublisherEnrollmentRequest{
			Scope:    PublisherScope{Kind: "namespace", TeamID: e.team.ID, DomainID: e.domain.ID},
			EditorID: e.actor, EditorMembershipID: e.member.ID, PolicyRevision: uint64(e.member.PolicyRevision),
			Name: "tnl", Kind: "installed", Preview: true, Now: e.now,
		})
		if err != nil {
			t.Fatal(err)
		}
		key, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		publisher, err := d.RedeemPublisherEnrollment(ctx, enrollment.Key, key, e.now)
		if err != nil {
			t.Fatal(err)
		}
		return publisher
	}
	original, replacement := issue(), issue()
	if original.Scope.Namespace == replacement.Scope.Namespace ||
		!naming.PreviewParent(original.Scope.Namespace, e.domain.CanonicalDomain) {
		t.Fatalf("bad publisher parents: %s / %s", original.Scope.Namespace, replacement.Scope.Namespace)
	}
	fingerprint := strings.Repeat("a", 64)
	local := RealizeLocalProjectServiceRequest{
		TeamID: e.team.ID, ActorID: e.actor, Service: "app", ProjectKey: "local-" + fingerprint[:48],
		SourceFingerprint: fingerprint, WorktreeKey: fingerprint, WorktreeLabel: "zelda-perf", Now: e.now,
		PreviewPublisher: original.ID, DNSAutomation: true, Configuration: ProjectServiceConfiguration{Target: "app", Public: new(true)},
	}
	worktree, err := d.RealizeLocalProjectService(ctx, local)
	if err != nil {
		t.Fatal(err)
	}
	if parent, ok := naming.PreviewHostname(worktree.Hostname, e.domain.CanonicalDomain); !ok || parent != original.Scope.Namespace {
		t.Fatalf("opaque worktree allocated outside its preview parent: %s", worktree.Hostname)
	}
	local.PreviewPublisher, local.WorktreeLabel = replacement.ID, "zelda-faster"
	if again, err := d.RealizeLocalProjectService(ctx, local); err != nil || again.Hostname != worktree.Hostname || again.ServiceID != worktree.ServiceID {
		t.Fatalf("publisher replacement changed the worktree's saved address: %#v, %v", again, err)
	}
	create := func(name string) ServiceRecord {
		t.Helper()
		service, err := d.CreateServiceAt(ctx, e.team.ID, e.actor, name, name,
			ServicePlacement{PreviewPublisher: original.ID, DNSAutomation: true},
			e.now, ServiceMetadata{Protocol: "http"}, &ProjectServiceConfiguration{Target: "app", Public: new(true)})
		if err != nil {
			t.Fatal(err)
		}
		return service
	}
	var previous ACMEOrderWork
	for _, service := range []ServiceRecord{create("one"), create("two")} {
		hostname := service.Endpoint.Hostname
		parent, ok := naming.PreviewHostname(hostname, e.domain.CanonicalDomain)
		if !ok || parent != original.Scope.Namespace {
			t.Fatalf("hostname = %s, parent = %s", hostname, parent)
		}
		f := servicePublicationFixture{database: d, now: e.now, service: service, publisher: original}
		f.start(t, "original", e.now)
		if got := f.prepared.CertificatePlan; !slices.Equal(got.Identifiers, []string{"*." + parent}) || got.CacheKey != parent {
			t.Fatalf("preview plan = %#v", got)
		}
		if previous.ID == "" {
			work := createPlanIssuanceWork(t, d, e.now, f.run, f.prepared.CertificatePlan, true, nil)
			if err := d.MarkServiceCertificateInstalled(ctx, service.ID, f.run.RunID, f.run.Token, work.ID, f.run.RunNumber, *work.NotAfter, e.now); err != nil {
				t.Fatal("preview wildcard could not be installed:", err)
			}
			previous = work
		} else if err := d.MarkServiceCertificateInstalled(ctx, service.ID, f.run.RunID, f.run.Token, previous.ID, f.run.RunNumber, *previous.NotAfter, e.now); err != nil {
			t.Fatal("another preview under the same parent could not reuse the certificate:", err)
		}
		foreign := f
		foreign.publisher = replacement
		if _, err := d.PrepareServiceRun(ctx, service.ID, foreign.publisher, "foreign", e.now, ServiceRunRequest{Metadata: service.ServiceMetadata}); !errors.Is(err, ErrServiceAccess) {
			t.Fatalf("foreign preview parent authorized: %v", err)
		}
		if err := d.CloseServiceRun(ctx, service.ID, f.run.RunID, f.run.Token, e.now); err != nil {
			t.Fatal(err)
		}
		exact := e.startNative(t, service)
		if got := exact.prepared.CertificatePlan; !slices.Equal(got.Identifiers, []string{hostname}) {
			t.Fatalf("replacement did not receive an exact plan: %#v", got)
		}
	}
}

func TestIntegrationHostedNamedAddressSurvivesDomainDefault(t *testing.T) {
	e := newRestoredCertificateEnvironment(t, DomainKindCustom, naming.ManagedURLModeGenerated, false)
	d, ctx := e.database, t.Context()
	aya := addAuthorityMember(t, d, e.now, e.actor, e.team.ID, "aya", TeamRoleMember)
	if aya.ManagedLabel != e.team.ManagedLabel {
		t.Fatal("member did not inherit the team's assigned suffix")
	}
	reserve := func(domain, hostname, key string) ServiceRecord {
		t.Helper()
		s, err := d.CreateServiceAt(ctx, e.team.ID, aya.IdentityID, "app", key,
			ServicePlacement{DomainID: domain, Hostname: hostname, Reserve: true, UseSavedAddress: true}, e.now,
			ServiceMetadata{Protocol: "http"}, &ProjectServiceConfiguration{Target: "app", Public: new(true)})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	hosted := reserve(e.team.DefaultDomainID, "app.aya."+e.team.ManagedLabel+".tunnels.example.test", "first")
	if _, err := d.SetTeamDefaultDomain(ctx, e.actor, e.team.ID, e.domain.ID, e.now); err != nil {
		t.Fatal(err)
	}
	reuse := reserve(e.domain.ID, "app.aya."+e.domain.CanonicalDomain, "reuse")
	if reuse.ID != hosted.ID || reuse.Endpoint.Hostname != hosted.Endpoint.Hostname {
		t.Fatalf("changed default replaced the named service: %#v", reuse)
	}
	if got, err := d.GetServiceByHostname(ctx, e.team.ID, hosted.Endpoint.Hostname, aya.IdentityID); err != nil || got.ID != hosted.ID {
		t.Fatalf("owner could not resume its exact service: %#v, %v", got, err)
	}
	other := addAuthorityMember(t, d, e.now, e.actor, e.team.ID, "ken", TeamRoleMember)
	if _, err := d.GetServiceByHostname(ctx, e.team.ID, hosted.Endpoint.Hostname, other.IdentityID); !errors.Is(err, ErrServiceAccess) {
		t.Fatalf("unrelated member obtained exact service management: %v", err)
	}
}

func TestIntegrationHostedWorktreesReserveMemberNames(t *testing.T) {
	e := newRestoredCertificateEnvironment(t, DomainKindCustom, naming.ManagedURLModeGenerated, false)
	d, ctx := e.database, t.Context()
	realize := func(key, label string) LocalProjectService {
		t.Helper()
		fingerprint := strings.Repeat(key, 64)
		service, err := d.RealizeLocalProjectService(ctx, RealizeLocalProjectServiceRequest{
			TeamID: e.team.ID, ActorID: e.actor, Service: "app", ProjectKey: "local-" + fingerprint[:48],
			SourceFingerprint: fingerprint, WorktreeKey: fingerprint, WorktreeLabel: label, Now: e.now,
			Configuration: ProjectServiceConfiguration{DomainID: e.domain.ID, Target: "app", Public: new(true)},
		})
		if err != nil {
			t.Fatal(err)
		}
		return service
	}
	first := realize("a", "zelda-perf")
	second := realize("b", "zelda-perf")
	if first.Hostname != "app-zelda-perf."+e.member.MemberSlug+"."+e.domain.CanonicalDomain ||
		first.Hostname == second.Hostname || !strings.HasPrefix(second.Hostname, "app-zelda-perf-") {
		t.Fatalf("worktree hostnames = %s, %s", first.Hostname, second.Hostname)
	}
	if moved := realize("a", "zelda-faster"); moved.ServiceID != first.ServiceID || moved.Hostname != first.Hostname {
		t.Fatalf("moving the worktree changed its saved endpoint: %#v", moved)
	}
	if _, err := d.CreateServiceAt(ctx, e.team.ID, e.actor, "reserved", "reserved",
		ServicePlacement{DomainID: e.domain.ID, Hostname: "app.production.zelda.deploy." + e.domain.CanonicalDomain},
		e.now, ServiceMetadata{Protocol: "http"}, &ProjectServiceConfiguration{Target: "app", Public: new(true)}); !errors.Is(err, ErrServiceAccess) {
		t.Fatalf("standalone service acquired the reserved branch: %v", err)
	}
}
