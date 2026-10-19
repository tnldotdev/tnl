package publisherjob

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/privatepublisher"
	"github.com/tnldotdev/tnl/internal/privatetrust"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/internal/projectpublisher"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func kindFixture(t *testing.T, kind Kind) (Job, authorityv1.PublisherEnrollmentResult, ed25519.PrivateKey) {
	t.Helper()
	job, identity, key := fixture(t, "validation")
	job.Kind = kind
	id := func(prefix string) string {
		t.Helper()
		value, err := opaqueid.New(prefix)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	switch kind {
	case KindPrivateService, KindConnector:
		job.PublicURLID, job.PrivateServiceID = "", id(opaqueid.PrivateServicePrefix)
		job.Protocol, job.Target, job.TrustRevision = config.ProtocolTCP, "127.0.0.1:5432", 1
		identity.Kind, identity.PublicUrlId, identity.PrivateServiceId = authorityv1.PrivateService, nil, &job.PrivateServiceID
		if kind == KindConnector {
			job.PublisherID, job.GrantID = "", ""
			job.IdentityID, job.StateDir = id(opaqueid.IdentityPrefix), t.TempDir()
		}
	case KindGroup:
		job.GroupInstance = "replica-1"
		job.PublicURLID, job.GrantID, job.Target, job.Protocol = "", "", "", ""
		job.GroupMember = &controlv1.PublisherGroupMember{PublisherIdentityId: job.PublisherID, KeyId: identity.KeyId,
			TeamId: identity.TeamId, ProjectKey: "project-one", GroupName: "cluster", GroupId: id("pgrp_")}
	}
	return job, identity, key
}

func installKind(t *testing.T, registry *Registry, kind Kind, job Job, identity authorityv1.PublisherEnrollmentResult, key ed25519.PrivateKey) error {
	t.Helper()
	switch kind {
	case KindGroup:
		return registry.InstallGroup(t.Context(), job, *job.GroupMember, key)
	case KindConnector:
		return registry.InstallConnector(t.Context(), job)
	default:
		return registry.Install(t.Context(), job, identity, key)
	}
}

func userRegistry(t *testing.T) *Registry {
	t.Helper()
	options := testOptions(t)
	options.User = true
	registry, err := Open(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.Close() })
	return registry
}

func requireScopeFailure(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrScope) {
		t.Fatalf("expected scope rejection, got %v", err)
	}
	typed, ok := failure.Of(err)
	if !ok || typed.Reason() != failure.InvalidTunnelFlags || !blockedFailure(err) {
		t.Fatalf("scope rejection lost its failure code or retry policy: %v", err)
	}
}

func TestInstalledJobKindProtocolMatrix(t *testing.T) {
	for _, kind := range []Kind{KindPublicURL, KindPrivateService, KindConnector, KindGroup} {
		name := string(kind)
		if kind == KindPublicURL {
			name = "public"
		}
		t.Run(name, func(t *testing.T) {
			for _, protocol := range []config.ProtocolName{"", config.ProtocolHTTP, config.ProtocolTCP, config.ProtocolMySQL, config.ProtocolPostgres, "redis", "HTTP"} {
				t.Run(string(protocol), func(t *testing.T) {
					registry := userRegistry(t)
					job, identity, key := kindFixture(t, kind)
					job.Protocol = protocol
					if kind == KindPrivateService && protocol == config.ProtocolHTTP {
						job.Target = "http://127.0.0.1:3000"
					}
					privateProtocol := protocol == config.ProtocolHTTP || protocol == config.ProtocolTCP || protocol == config.ProtocolMySQL || protocol == config.ProtocolPostgres
					valid := kind == KindPublicURL && protocol == config.ProtocolHTTP || kind == KindGroup && protocol == "" ||
						(kind == KindPrivateService || kind == KindConnector) && privateProtocol
					err := installKind(t, registry, kind, job, identity, key)
					if !valid {
						requireScopeFailure(t, err)
					} else if err != nil {
						t.Fatal(err)
					}
					jobs, err := registry.List(t.Context())
					if err != nil {
						t.Fatal(err)
					}
					if !valid && len(jobs) != 0 || valid && (len(jobs) != 1 || jobs[0].Kind != kind || jobs[0].Protocol != protocol) {
						t.Fatalf("installation crossed the kind/protocol boundary: %+v", jobs)
					}
				})
			}
		})
	}
}

func TestInstallationRejectsCrossKindMetadata(t *testing.T) {
	for _, kind := range []Kind{KindPublicURL, KindPrivateService, KindConnector, KindGroup} {
		name := string(kind)
		if kind == KindPublicURL {
			name = "public"
		}
		t.Run(name, func(t *testing.T) {
			registry := userRegistry(t)
			base, identity, key := kindFixture(t, kind)
			mutations := map[string]func(*Job){
				"unknown kind": func(j *Job) { j.Kind = "unknown" },
				"server trust": func(j *Job) { j.ServerCAPEM = []byte("not a certificate") },
			}
			if kind != KindGroup {
				mutations["group metadata"] = func(j *Job) { j.GroupMember = &controlv1.PublisherGroupMember{} }
			}
			if kind != KindConnector {
				mutations["visitor identity"] = func(j *Job) { j.IdentityID = "visitor" }
				mutations["visitor state"] = func(j *Job) { j.StateDir = t.TempDir() }
			}
			if kind != KindPrivateService {
				mutations["project"] = func(j *Job) { j.Project = &projectconfig.Project{} }
				mutations["project service"] = func(j *Job) { j.ProjectService = "database" }
				mutations["publisher pool"] = func(j *Job) { j.PublisherPool = true }
			}
			if kind == KindPublicURL || kind == KindGroup {
				mutations["private trust"] = func(j *Job) { j.Trust = &privatetrust.Snapshot{} }
				mutations["private revision"] = func(j *Job) { j.TrustRevision = 1 }
				mutations["private service"] = func(j *Job) { j.PrivateServiceID = "private" }
			} else {
				mutations["public URL"] = func(j *Job) { j.PublicURLID = "public" }
				mutations["missing trust revision"] = func(j *Job) { j.TrustRevision = 0 }
				mutations["publisher target TLS"] = func(j *Job) { j.TargetTLSName = "target.example" }
				mutations["publisher target CA"] = func(j *Job) { j.TargetCAPEM = []byte("unexpected") }
			}
			if kind == KindGroup || kind == KindConnector {
				mutations["publisher grant"] = func(j *Job) { j.GrantID = identity.GrantId }
				mutations["publisher limits"] = func(j *Job) { j.Limits.Concurrency = 10 }
			} else {
				mutations["missing publisher"] = func(j *Job) { j.PublisherID = "" }
				mutations["missing grant"] = func(j *Job) { j.GrantID = "" }
			}
			if kind == KindGroup {
				mutations["target"] = func(j *Job) { j.Target = "127.0.0.1:5432" }
				mutations["target trust"] = func(j *Job) { j.TargetTLSName = "target.example" }
				mutations["group signer"] = func(j *Job) {
					member := *j.GroupMember
					member.PublisherIdentityId = "other-publisher"
					j.GroupMember = &member
				}
				mutations["group key"] = func(j *Job) {
					member := *j.GroupMember
					member.KeyId = "invalid-key"
					j.GroupMember = &member
				}
			}
			if kind == KindConnector {
				mutations["publisher identity"] = func(j *Job) { j.PublisherID = identity.ClientId }
				mutations["missing visitor identity"] = func(j *Job) { j.IdentityID = "" }
			}
			if kind == KindPrivateService {
				mutations["orphan project service"] = func(j *Job) { j.ProjectService = "database" }
			}
			for name, mutate := range mutations {
				t.Run(name, func(t *testing.T) {
					job := base
					mutate(&job)
					requireScopeFailure(t, installKind(t, registry, kind, job, identity, key))
				})
			}
			jobs, err := registry.List(t.Context())
			if err != nil || len(jobs) != 0 {
				t.Fatalf("rejected installation wrote desired state: %+v %v", jobs, err)
			}
			profile, err := registry.Profile(t.Context(), base.Server)
			if err != nil {
				t.Fatal(err)
			}
			if _, found, err := profile.PublisherSigningIdentity(t.Context(), "job:"+base.ID); err != nil || found {
				t.Fatalf("rejected installation wrote signing credentials: found=%v, %v", found, err)
			}
		})
	}
}

func TestPublisherInstallCannotAcceptSupervisorOnlyKinds(t *testing.T) {
	for _, kind := range []Kind{KindGroup, KindConnector} {
		t.Run(string(kind), func(t *testing.T) {
			registry := userRegistry(t)
			job, identity, key := kindFixture(t, kind)
			identity.Kind, identity.ClientId, identity.GrantId = authorityv1.SavedUrl, job.PublisherID, job.GrantID
			identity.PrivateServiceId, identity.PublicUrlId = nil, &job.PublicURLID
			requireScopeFailure(t, registry.Install(t.Context(), job, identity, key))
		})
	}
}

func TestPublisherInstallationRejectsMixedGrantMetadata(t *testing.T) {
	for _, kind := range []Kind{KindPublicURL, KindPrivateService} {
		registry := userRegistry(t)
		job, identity, key := kindFixture(t, kind)
		other := "other-resource"
		for _, mutate := range []func(*authorityv1.PublisherEnrollmentResult){
			func(i *authorityv1.PublisherEnrollmentResult) { i.Namespace = &other },
			func(i *authorityv1.PublisherEnrollmentResult) { i.DomainId = &other },
			func(i *authorityv1.PublisherEnrollmentResult) {
				if kind == KindPublicURL {
					i.PrivateServiceId = &other
				} else {
					i.PublicUrlId = &other
				}
			},
		} {
			changed := identity
			mutate(&changed)
			requireScopeFailure(t, registry.Install(t.Context(), job, changed, key))
		}
	}
}

func TestPublicConfigCannotConsumePrivateJobOrProtocol(t *testing.T) {
	job, identity, key := kindFixture(t, KindPublicURL)
	control, _ := jobBoundary(job, identity, key)
	cfg, err := publicationConfig(job, control.publicURL)
	if err != nil || cfg.ServiceProtocol != controlv1.Http {
		t.Fatalf("public HTTP config: %+v, %v", cfg, err)
	}
	control.publicURL.ServiceProtocol = "tcp"
	_, err = publicationConfig(job, control.publicURL)
	requireScopeFailure(t, err)
	private, _, _ := kindFixture(t, KindPrivateService)
	private.Protocol, private.Target = config.ProtocolHTTP, job.Target
	control.publicURL.Id, control.publicURL.ServiceProtocol = "", controlv1.Http
	_, err = publicationConfig(private, control.publicURL)
	requireScopeFailure(t, err)
}

func TestPrivatePublicationRejectsProtocolMismatchBeforeTargetCapture(t *testing.T) {
	for _, test := range []struct {
		name     string
		kind     Kind
		protocol config.ProtocolName
		metadata controlv1.PrivateServiceProtocol
	}{
		{"missing metadata", KindPrivateService, config.ProtocolPostgres, ""},
		{"different metadata", KindPrivateService, config.ProtocolPostgres, "http"},
		{"unknown metadata", KindPrivateService, config.ProtocolPostgres, "unknown"},
		{"unknown protocol", KindPrivateService, "unknown", "unknown"},
		{"public kind", KindPublicURL, config.ProtocolPostgres, "postgres"},
		{"connector kind", KindConnector, config.ProtocolPostgres, "postgres"},
		{"group kind", KindGroup, config.ProtocolPostgres, "postgres"},
	} {
		t.Run(test.name, func(t *testing.T) {
			job := Job{Kind: test.kind, Protocol: test.protocol, Target: "127.0.0.1:5432"}
			captured := false
			err := PublishPrivate(t.Context(), job, privatepublisher.RunConfig{Metadata: controlv1.PrivateServiceMetadata{Protocol: test.metadata}}, PrivateTargetHooks{
				Capture: func(projectpublisher.TargetSnapshot) error { captured = true; return nil },
			})
			requireScopeFailure(t, err)
			if captured {
				t.Fatal("invalid private declaration reached target capture")
			}
		})
	}
}

func TestJobKindSerializationRemainsStable(t *testing.T) {
	for _, test := range []struct {
		kind Kind
		wire string
	}{{KindPublicURL, ""}, {KindPrivateService, `"private"`}, {KindConnector, `"connector"`}, {KindGroup, `"group"`}} {
		value, err := json.Marshal(Job{Kind: test.kind})
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(value, &fields); err != nil {
			t.Fatal(err)
		}
		if string(fields["kind"]) != test.wire {
			t.Fatalf("installed kind changed: %s, %v", value, err)
		}
	}
}
