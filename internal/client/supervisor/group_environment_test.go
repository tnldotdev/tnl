package supervisor

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	publisherdiscovery "github.com/tnldotdev/tnl/internal/publisher/target/discovery"
	"github.com/tnldotdev/tnl/internal/publisher/target/discovery/rdsroots"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

var errGroupEnvironmentPrepared = errors.New("group service preparation recorded")

type groupEnvironmentControl struct {
	publisheridentity.ServiceControl
	service      controlv1.Service
	reads        int
	onRead       func()
	declarations []controlv1.ServiceRunDeclaration
}

func (c *groupEnvironmentControl) GetPublisherService(_ context.Context, access string) (controlv1.Service, error) {
	if access != "test-access-never-log" {
		return controlv1.Service{}, publisheridentity.ErrScope
	}
	c.reads++
	if c.onRead != nil {
		c.onRead()
	}
	return c.service, nil
}

func (c *groupEnvironmentControl) PrepareServiceRun(_ context.Context, serviceID, key, access string, declaration controlv1.ServiceRunDeclaration) (controlv1.ServiceRunPreparation, error) {
	if serviceID != c.service.Id || !opaqueid.Valid(key, opaqueid.IdempotencyPrefix) || access != "test-access-never-log" {
		return controlv1.ServiceRunPreparation{}, publisheridentity.ErrScope
	}
	c.declarations = append(c.declarations, declaration)
	return controlv1.ServiceRunPreparation{}, errGroupEnvironmentPrepared
}

func groupEnvironmentFixture(t *testing.T, cloud bool) (GroupPublisher, controlv1.EnvironmentPublication, controlv1.EnvironmentPublisherAssignment, *groupEnvironmentControl, *atomic.Int32) {
	t.Helper()
	job, _, private := kindFixture(t, KindGroup)
	newID := func(prefix string) string {
		t.Helper()
		id, err := opaqueid.New(prefix)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	publication := controlv1.EnvironmentPublication{EnvironmentId: job.GroupMember.EnvironmentId, MutationRevision: 7, ConfigurationHash: strings.Repeat("a1", 32)}
	assignment := controlv1.EnvironmentPublisherAssignment{
		Service: "database", ServiceId: newID(opaqueid.ServicePrefix), GrantId: newID(opaqueid.PublisherGrantPrefix), TrustRevision: 3,
		Configuration: controlv1.EnvironmentServicePublication{Protocol: controlv1.ServiceProtocol("tcp")},
	}
	control := &groupEnvironmentControl{service: controlv1.Service{
		Id: assignment.ServiceId, TeamId: job.GroupMember.TeamId, Enabled: true, Protocol: assignment.Configuration.Protocol, TrustRevision: assignment.TrustRevision,
		Endpoint: &controlv1.ServiceEndpoint{Hostname: "database.services.example", Port: 443},
	}}
	identity := authorityv1.PublisherEnrollmentResult{ClientId: job.GroupMember.PublisherIdentityId, KeyId: job.GroupMember.KeyId, TeamId: job.GroupMember.TeamId, GrantId: assignment.GrantId, Kind: authorityv1.Service, ServiceId: &assignment.ServiceId}
	public := private.Public().(ed25519.PublicKey)
	publisher := GroupPublisher{
		Member: *job.GroupMember, Private: private,
		Control:   publisheridentity.NativeControl{PublicURLControl: &jobControl{}, Services: control},
		Authority: &jobAuthority{identity: identity, public: public},
	}
	calls := new(atomic.Int32)
	if !cloud {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		assignment.Configuration.Target = listener.Addr().String()
		return publisher, publication, assignment, control, calls
	}
	assignment.Configuration.Protocol = controlv1.ServiceProtocol("postgres")
	assignment.Configuration.TargetDiscovery = &controlv1.ProjectTargetDiscovery{Type: controlv1.Rds, Region: "us-east-1", Instance: new("database")}
	control.service.Protocol = assignment.Configuration.Protocol
	ca, err := rdsroots.Bundle("us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(ca))
	resolver, err := publisherdiscovery.New(discoveryCall(func(_ context.Context, request publisherdiscovery.Request) (publisherdiscovery.ResolvedTarget, error) {
		calls.Add(1)
		want := publisherdiscovery.Request{Type: "rds", Region: "us-east-1", Instance: "database", Endpoint: "writer", Protocol: "postgres"}
		if request != want {
			return publisherdiscovery.ResolvedTarget{}, errors.New("group assignment discovery selector changed")
		}
		return publisherdiscovery.ResolvedTarget{
			Address: "database.example.test:5432", ServerName: "database.example.test", Protocol: request.Protocol,
			CA: ca, CADigest: hex.EncodeToString(sum[:]), ARN: "arn:aws:rds:us-east-1:123456789012:db:database", ResourceID: "db-immutable",
		}, nil
	}), publisherdiscovery.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(resolver.Close)
	publisher.Discovery = resolver
	return publisher, publication, assignment, control, calls
}

func TestGroupPublisherEnvironmentPreparationKeepsAssignmentSnapshot(t *testing.T) {
	for _, target := range []string{"static", "cloud"} {
		t.Run(target, func(t *testing.T) {
			publisher, publication, assignment, control, discoveryCalls := groupEnvironmentFixture(t, target == "cloud")
			want := publication
			replacement := controlv1.EnvironmentPublication{EnvironmentId: "env_" + strings.Repeat("z", 22), MutationRevision: want.MutationRevision + 1, ConfigurationHash: strings.Repeat("b2", 32)}
			// metadata reads happen after construction and again during preparation.
			// changing the caller's pointer must not change the worker's fence.
			control.onRead = func() { publication = replacement }
			err := publisher.Publish(t.Context(), publication, assignment, nil)
			if !errors.Is(err, errGroupEnvironmentPrepared) {
				t.Fatalf("publication did not reach control preparation: %v", err)
			}
			if control.reads < 3 || len(control.declarations) != 1 {
				t.Fatalf("metadata reads = %d, preparations = %d", control.reads, len(control.declarations))
			}
			got := control.declarations[0].Environment
			if got == nil || *got != want || got == &publication {
				t.Fatalf("prepared environment = %+v, want independent assignment snapshot %+v", got, want)
			}
			if publication != replacement {
				t.Fatal("metadata lookup did not exercise caller snapshot replacement")
			}
			if target == "cloud" && discoveryCalls.Load() != 1 {
				t.Fatalf("cloud discovery calls = %d, want 1", discoveryCalls.Load())
			}
		})
	}
}

func TestGroupPublisherEnvironmentPreparationRejectsMissingEnvelope(t *testing.T) {
	for _, target := range []string{"static", "cloud"} {
		t.Run(target, func(t *testing.T) {
			publisher, _, assignment, control, calls := groupEnvironmentFixture(t, target == "cloud")
			if err := publisher.Publish(t.Context(), controlv1.EnvironmentPublication{}, assignment, nil); err == nil {
				t.Fatalf("publication without environment envelope was accepted")
			}
			if len(control.declarations) != 0 || control.reads != 0 || calls.Load() != 0 {
				t.Fatalf("missing envelope reached metadata/discovery/preparation")
			}
		})
	}
}

func TestGroupPublisherEnvironmentPreparationRejectsMalformedFence(t *testing.T) {
	for _, target := range []string{"static", "cloud"} {
		t.Run(target, func(t *testing.T) {
			for _, malformed := range []struct {
				name   string
				change func(*controlv1.EnvironmentPublication)
			}{
				{"wrong-id-kind", func(value *controlv1.EnvironmentPublication) { value.EnvironmentId = "svc_" + strings.Repeat("a", 22) }},
				{"zero-revision", func(value *controlv1.EnvironmentPublication) { value.MutationRevision = 0 }},
				{"negative-revision", func(value *controlv1.EnvironmentPublication) { value.MutationRevision = -1 }},
				{"short-hash", func(value *controlv1.EnvironmentPublication) { value.ConfigurationHash = strings.Repeat("a", 63) }},
				{"uppercase-hash", func(value *controlv1.EnvironmentPublication) { value.ConfigurationHash = strings.Repeat("A", 64) }},
				{"nonhex-hash", func(value *controlv1.EnvironmentPublication) { value.ConfigurationHash = strings.Repeat("z", 64) }},
			} {
				t.Run(malformed.name, func(t *testing.T) {
					publisher, publication, assignment, control, discoveryCalls := groupEnvironmentFixture(t, target == "cloud")
					malformed.change(&publication)
					if err := publisher.Publish(t.Context(), publication, assignment, nil); err == nil {
						t.Fatalf("malformed environment fence was not rejected: %v", err)
					}
					if control.reads != 0 || len(control.declarations) != 0 || discoveryCalls.Load() != 0 {
						t.Fatalf("malformed fence reached metadata/discovery/preparation: %d/%d/%d", control.reads, discoveryCalls.Load(), len(control.declarations))
					}
				})
			}
		})
	}
}

func TestGroupPublisherEnvironmentPreparationRejectsMalformedAssignment(t *testing.T) {
	for _, malformed := range []struct {
		name   string
		change func(*GroupPublisher, *controlv1.EnvironmentPublisherAssignment)
	}{
		{"empty-service-name", func(_ *GroupPublisher, a *controlv1.EnvironmentPublisherAssignment) { a.Service = "" }},
		{"invalid-service-name", func(_ *GroupPublisher, a *controlv1.EnvironmentPublisherAssignment) { a.Service = "Bad.Name" }},
		{"invalid-service-id", func(_ *GroupPublisher, a *controlv1.EnvironmentPublisherAssignment) {
			a.ServiceId = "url_not-a-service"
		}},
		{"invalid-grant-id", func(_ *GroupPublisher, a *controlv1.EnvironmentPublisherAssignment) { a.GrantId = "invalid-grant" }},
		{"missing-protocol", func(_ *GroupPublisher, a *controlv1.EnvironmentPublisherAssignment) { a.Configuration.Protocol = "" }},
		{"invalid-protocol", func(_ *GroupPublisher, a *controlv1.EnvironmentPublisherAssignment) {
			a.Configuration.Protocol = "redis"
		}},
		{"missing-trust-revision", func(_ *GroupPublisher, a *controlv1.EnvironmentPublisherAssignment) { a.TrustRevision = 0 }},
		{"foreign-environment", func(p *GroupPublisher, _ *controlv1.EnvironmentPublisherAssignment) {
			p.Member.EnvironmentId = "env_foreign"
		}},
		{"invalid-project", func(p *GroupPublisher, _ *controlv1.EnvironmentPublisherAssignment) {
			p.Member.ProjectKey = "Bad.Project"
		}},
		{"invalid-publisher", func(p *GroupPublisher, _ *controlv1.EnvironmentPublisherAssignment) {
			p.Member.PublisherIdentityId = "invalid-publisher"
		}},
		{"invalid-key", func(p *GroupPublisher, _ *controlv1.EnvironmentPublisherAssignment) { p.Member.KeyId = "invalid-key" }},
		{"missing-team", func(p *GroupPublisher, _ *controlv1.EnvironmentPublisherAssignment) { p.Member.TeamId = "" }},
	} {
		t.Run(malformed.name, func(t *testing.T) {
			publisher, publication, assignment, control, discoveryCalls := groupEnvironmentFixture(t, false)
			malformed.change(&publisher, &assignment)
			if err := publisher.Publish(t.Context(), publication, assignment, nil); err == nil {
				t.Fatal("malformed assignment was accepted")
			}
			if control.reads != 0 || len(control.declarations) != 0 || discoveryCalls.Load() != 0 {
				t.Fatal("malformed assignment reached metadata, discovery or preparation")
			}
		})
	}
}
