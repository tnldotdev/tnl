package state

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/naming"
)

func TestIntegrationRouteCreationAndDeletion(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "service_creation")
	actor := oidcRouteRequest(t, d, now)
	declaration := ProjectServiceConfiguration{Target: "localhost:3000", Hostname: actor.CanonicalHostname, Public: new(true)}
	service, err := d.CreateServiceAt(t.Context(), actor.TeamID, actor.ActingIdentityID, "web", "create", ServicePlacement{}, now, ServiceMetadata{}, &declaration)
	if err != nil {
		t.Fatal(err)
	}
	if service.Recovered {
		t.Fatal("first creation returned a recovered receipt")
	}
	if service.TeamID != actor.TeamID || service.DomainID != actor.DomainID || service.Endpoint.Hostname != actor.CanonicalHostname || service.Endpoint.Port != 443 || !service.Enabled || service.TrustRevision != 1 {
		t.Fatal("creation lost the exact service ownership, endpoint, or trust revision")
	}
	repeated, err := d.CreateServiceAt(t.Context(), actor.TeamID, actor.ActingIdentityID, "web", "create", ServicePlacement{}, now.Add(time.Second), ServiceMetadata{}, &declaration)
	if err != nil || !repeated.Recovered {
		t.Fatal("create replay did not return a recovered receipt", err)
	}
	firstSaved, repeatedSaved := service, repeated
	firstSaved.Recovered, repeatedSaved.Recovered = false, false
	if !reflect.DeepEqual(firstSaved, repeatedSaved) {
		t.Fatal("create replay changed the saved service", err)
	}
	changed := declaration
	changed.Target = "localhost:4000"
	if _, err := d.CreateServiceAt(t.Context(), actor.TeamID, actor.ActingIdentityID, "web", "create", ServicePlacement{}, now, ServiceMetadata{}, &changed); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("create replay changed its intent", err)
	}
	if _, err := d.CreateServiceAt(t.Context(), actor.TeamID, actor.ActingIdentityID, "other", "other", ServicePlacement{}, now, ServiceMetadata{}, &declaration); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("another service claimed an existing hostname", err)
	}
	nested := declaration
	nested.Hostname = "nested.api." + strings.TrimPrefix(actor.CanonicalHostname, "demo.")
	second, err := d.CreateServiceAt(t.Context(), actor.TeamID, actor.ActingIdentityID, "nested", "nested", ServicePlacement{}, now, ServiceMetadata{}, &nested)
	if err != nil || second.TeamID != service.TeamID || second.DomainID != service.DomainID || second.Endpoint.Hostname != nested.Hostname {
		t.Fatal("nested hostname changed member authority", err)
	}
	if err := d.DeleteService(t.Context(), second.ID, actor.ActingIdentityID, observedServiceDeletion(t, d, second.ID), now); err != nil {
		t.Fatal(err)
	}
	page, cursor, err := d.ListServices(t.Context(), actor.TeamID, actor.ActingIdentityID, "")
	if err != nil || len(page) != 1 || cursor != "" || page[0].ID != service.ID {
		t.Fatal("saved service listing changed identity", err)
	}
	loaded, err := d.GetService(t.Context(), service.ID, actor.ActingIdentityID)
	if err != nil || !reflect.DeepEqual(loaded, service) {
		t.Fatal("service read lost saved fields", err)
	}
	if err := d.DeleteService(t.Context(), service.ID, actor.ActingIdentityID, observedServiceDeletion(t, d, service.ID), now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.GetService(t.Context(), service.ID, actor.ActingIdentityID); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("deleted service remained readable", err)
	}
	if _, err := d.CreateServiceAt(t.Context(), actor.TeamID, actor.ActingIdentityID, "web", "create", ServicePlacement{}, now, ServiceMetadata{}, &declaration); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("create retry revived a deleted service", err)
	}
}

func TestIntegrationAdministratorCannotClaimManagedRootNames(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "managed_root")
	actor := oidcRouteRequest(t, d, now)
	d.managedURLMode = naming.ManagedURLModeSimple
	declaration := ProjectServiceConfiguration{Target: "localhost:3000", Hostname: "app.tunnels.example.test"}
	if _, err := d.CreateServiceAt(t.Context(), actor.TeamID, actor.ActingIdentityID, "root", "root", ServicePlacement{}, now, ServiceMetadata{}, &declaration); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("administrator claimed a managed root hostname", err)
	}
	declaration.Hostname = "app.operator.tunnels.example.test"
	first, err := d.CreateServiceAt(t.Context(), actor.TeamID, actor.ActingIdentityID, "app", "app", ServicePlacement{}, now, ServiceMetadata{}, &declaration)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := d.CreateServiceAt(t.Context(), actor.TeamID, actor.ActingIdentityID, "app", "app", ServicePlacement{}, now.Add(time.Second), ServiceMetadata{}, &declaration)
	if err != nil || repeated.ID != first.ID {
		t.Fatal("authorized personal namespace retry failed", err)
	}
}

func TestIntegrationSimpleManagedOrganizationNamespace(t *testing.T) {
	d, now, owner, team := newAuthorityTeam(t)
	d.managedURLMode = naming.ManagedURLModeSimple
	members, err := d.ListTeamMemberships(t.Context(), owner, team.ID)
	if err != nil || len(members) != 1 {
		t.Fatal(err)
	}
	domains, err := d.ListTeamDomains(t.Context(), owner, team.ID)
	if err != nil || len(domains) == 0 {
		t.Fatal(err)
	}
	hostname := "app." + members[0].MemberSlug + "." + team.DisplayName + "." + domains[0].CanonicalDomain
	declaration := ProjectServiceConfiguration{Target: "localhost:3000", Hostname: hostname, DomainID: domains[0].ID}
	service, err := d.CreateServiceAt(t.Context(), team.ID, owner, "app", "simple", ServicePlacement{}, now, ServiceMetadata{}, &declaration)
	if err != nil || service.Endpoint.Hostname != hostname || service.TeamID != team.ID {
		t.Fatal("organization service lost its exact namespace", err)
	}
	declaration.Hostname = "app." + members[0].ManagedLabel + "." + domains[0].CanonicalDomain
	if _, err := d.CreateServiceAt(t.Context(), team.ID, owner, "other", "generated-label", ServicePlacement{}, now, ServiceMetadata{}, &declaration); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("generated label bypassed the simple namespace", err)
	}
}

func TestIntegrationLargePublicURLIPPolicy(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "large_service_ip")
	actor := oidcRouteRequest(t, d, now)
	prefixes := make([]string, 256)
	for index := range prefixes {
		prefixes[index] = fmt.Sprintf("198.18.%d.%d/32", index/256, index%256)
	}
	slices.Sort(prefixes)
	submitted := append(slices.Clone(prefixes), prefixes[0], "::ffff:198.18.0.1/128")
	declaration := ProjectServiceConfiguration{Target: "localhost:3000", HTTP: &config.HTTPService{Access: &config.Access{Mode: "restricted", IP: submitted}}}
	service, err := d.CreateServiceAt(t.Context(), actor.TeamID, actor.ActingIdentityID, "web", "large", ServicePlacement{}, now, ServiceMetadata{}, &declaration)
	if err != nil {
		t.Fatal(err)
	}
	loaded, _, err := d.GetServiceConfiguration(t.Context(), service.ID, actor.ActingIdentityID)
	if err != nil || loaded == nil || loaded.HTTP == nil || loaded.HTTP.Access == nil || !slices.Equal(loaded.HTTP.Access.IP, prefixes) {
		t.Fatal("large IP policy changed during persistence", err)
	}
	var ciphertext []byte
	if err := d.pool.QueryRow(t.Context(), `SELECT configuration_ciphertext FROM control.services WHERE id=$1`, service.ID).Scan(&ciphertext); err != nil || bytes.Contains(ciphertext, []byte("198.18.")) || bytes.Contains(ciphertext, []byte("localhost")) {
		t.Fatal("saved service retained plaintext policy or target", err)
	}
	loaded.HTTP.Access.IP = append(slices.Clone(prefixes), "198.18.1.0/32")
	if _, err := d.ConfigureService(t.Context(), service.ID, actor.ActingIdentityID, service.ServiceMetadata, loaded, ServiceUpdateConditions{UnconditionalConfiguration: true}, now.Add(time.Second)); !errors.Is(err, ErrProjectConfigurationInvalid) {
		t.Fatal("257 distinct normalized prefixes reached mutation", err)
	}
	unchanged, _, err := d.GetServiceConfiguration(t.Context(), service.ID, actor.ActingIdentityID)
	if err != nil || !slices.Equal(unchanged.HTTP.Access.IP, prefixes) {
		t.Fatal("rejected prefix count changed saved configuration", err)
	}
	loaded.HTTP.Access.IP = slices.Clone(prefixes[1:])
	if _, err := d.ConfigureService(t.Context(), service.ID, actor.ActingIdentityID, service.ServiceMetadata, loaded, ServiceUpdateConditions{UnconditionalConfiguration: true}, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	updated, _, err := d.GetServiceConfiguration(t.Context(), service.ID, actor.ActingIdentityID)
	if err != nil || len(updated.HTTP.Access.IP) != 255 {
		t.Fatal("large IP policy update was lost", err)
	}
}

func TestIntegrationConcurrentRouteCreation(t *testing.T) {
	for _, sameRequest := range []bool{true, false} {
		t.Run(fmt.Sprintf("same_request_%t", sameRequest), func(t *testing.T) {
			d, now := newControlStateIntegrationDatabase(t, "service_contention")
			actor := oidcRouteRequest(t, d, now)
			declaration := ProjectServiceConfiguration{Target: "localhost:3000", Ephemeral: !sameRequest}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			workers := newIntegrationWorkers(t, cancel)
			type result struct {
				service ServiceRecord
				err     error
			}
			results := make(chan result, 4)
			for index := range 4 {
				workers.Go(func() {
					key := "same"
					if !sameRequest {
						key = fmt.Sprintf("contender-%d", index)
					}
					service, err := d.CreateServiceAt(ctx, actor.TeamID, actor.ActingIdentityID, "web", key, ServicePlacement{}, now, ServiceMetadata{}, &declaration)
					results <- result{service, err}
				})
			}
			successes, conflicts, fresh, recovered := 0, 0, 0, 0
			var winner ServiceRecord
			for range 4 {
				result := awaitIntegrationResult(t, ctx, results)
				switch {
				case result.err == nil:
					successes++
					if result.service.Recovered {
						recovered++
					} else {
						fresh++
					}
					winnerSaved, resultSaved := winner, result.service
					winnerSaved.Recovered, resultSaved.Recovered = false, false
					if winner.ID != "" && !reflect.DeepEqual(winnerSaved, resultSaved) {
						t.Fatal("concurrent retries changed service identity")
					}
					winner = result.service
				case errors.Is(result.err, ErrServiceConflict):
					conflicts++
				default:
					t.Fatal(result.err)
				}
			}
			want := 1
			if sameRequest {
				want = 4
			}
			if successes != want || conflicts != 4-want {
				t.Fatal("unexpected contention result", successes, conflicts)
			}
			if fresh != 1 || recovered != want-1 {
				t.Fatal("contention did not return exactly one fresh receipt and recovered retries", fresh, recovered)
			}
			if !sameRequest {
				if !winner.Ephemeral || winner.ExpiresAt != nil {
					t.Fatal("ephemeral allocation invented a fixed expiration")
				}
				if count, err := d.ExpireServiceRuns(ctx, now.Add(ephemeralServiceGracePeriod)); err != nil || count != 1 {
					t.Fatal("idle ephemeral cleanup failed", count, err)
				}
			}
		})
	}
}

func TestIntegrationRouteMutationAndExpiredSession(t *testing.T) {
	for _, expiredServing := range []bool{false, true} {
		t.Run(fmt.Sprintf("serving_expired=%t", expiredServing), func(t *testing.T) {
			f := newServicePublicationFixture(t)
			publisherExpiry := f.now.Add(time.Second)
			if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.service_runs SET publisher_expires_at=$2 WHERE id=$1`, f.run.RunID, publisherExpiry); err != nil {
				t.Fatal(err)
			}
			actor, err := f.database.GetServiceForPublisher(t.Context(), f.service.ID, f.publisher, f.now)
			if err != nil {
				t.Fatal(err)
			}
			var creator string
			if err := f.database.pool.QueryRow(t.Context(), `SELECT created_by_identity_id FROM control.services WHERE id=$1`, f.service.ID).Scan(&creator); err != nil {
				t.Fatal(err)
			}
			at := f.now.Add(2 * time.Second)
			if expiredServing {
				at = f.run.ServingUntil
			}
			declaration := ProjectServiceConfiguration{Target: "localhost:5000", HTTP: &config.HTTPService{Access: &config.Access{IP: []string{"192.0.2.0/24"}}}}
			updated, err := f.database.ConfigureService(t.Context(), f.service.ID, creator, actor.ServiceMetadata, &declaration, ServiceUpdateConditions{UnconditionalConfiguration: true}, at)
			if err != nil || updated.ID != f.service.ID || updated.TeamID != f.service.TeamID || updated.DomainID != f.service.DomainID ||
				!reflect.DeepEqual(updated.Endpoint, f.service.Endpoint) || updated.TrustRevision != f.service.TrustRevision || updated.EndpointRevision != f.service.EndpointRevision {
				t.Fatal("configuration update changed saved ownership or endpoint authority", err)
			}
			assertUnchanged := func() {
				t.Helper()
				var liveness, observed, serving time.Time
				if err := f.database.pool.QueryRow(t.Context(), `SELECT publisher_expires_at,serving_observed_at,serving_until FROM control.service_runs WHERE id=$1`, f.run.RunID).Scan(&liveness, &observed, &serving); err != nil ||
					!liveness.Equal(publisherExpiry) || !observed.Equal(f.run.ObservedAt) || !serving.Equal(f.run.ServingUntil) {
					t.Fatal("configuration update or denied heartbeat renewed publication authority", err)
				}
			}
			assertUnchanged()
			heartbeat, err := f.database.HeartbeatServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, at, ServiceRunHealth{StreamCapacity: 64})
			if expiredServing {
				if !errors.Is(err, ErrServiceAccess) {
					t.Fatal("configuration update revived expired serving authority", err)
				}
				assertUnchanged()
			} else if err != nil || heartbeat.ServiceID != f.service.ID || heartbeat.RunID != f.run.RunID || heartbeat.RunNumber != f.run.RunNumber ||
				!heartbeat.ExpiresAt.Equal(at.Add(45*time.Second)) || !heartbeat.ServingUntil.Equal(at.Add(f.database.servingTolerance())) {
				t.Fatal("expired liveness prevented confirmation within the existing serving allowance", err)
			}
		})
	}
}

func TestIntegrationEphemeralRouteExpiry(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "ephemeral_service")
	actor := oidcRouteRequest(t, d, now)
	declaration := ProjectServiceConfiguration{Target: "localhost:3000", Ephemeral: true}
	service, err := d.CreateServiceAt(t.Context(), actor.TeamID, actor.ActingIdentityID, "web", "ephemeral", ServicePlacement{}, now, ServiceMetadata{}, &declaration)
	if err != nil || !service.Ephemeral || service.ExpiresAt != nil {
		t.Fatal("ephemeral service invented a fixed deadline", err)
	}
	for _, test := range []struct {
		at   time.Time
		want int
	}{{now.Add(ephemeralServiceGracePeriod - time.Second), 0}, {now.Add(ephemeralServiceGracePeriod), 1}, {now.Add(ephemeralServiceGracePeriod), 0}} {
		if count, err := d.ExpireServiceRuns(t.Context(), test.at); err != nil || count != test.want {
			t.Fatal("ephemeral idle boundary changed", count, err)
		}
	}
	if _, err := d.GetService(t.Context(), service.ID, actor.ActingIdentityID); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("expired service remained readable", err)
	}
}

func TestIntegrationDNSPublicURLWork(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "service_dns_work")
	actor := oidcRouteRequest(t, d, now)
	declaration := ProjectServiceConfiguration{Protocol: "tcp", Target: "localhost:3000"}
	service, err := d.CreateServiceAt(t.Context(), actor.TeamID, actor.ActingIdentityID, "web", "dns", ServicePlacement{DNSAutomation: true}, now, ServiceMetadata{}, &declaration)
	if err != nil {
		t.Fatal(err)
	}
	// connector-only creation consumes neither public DNS work nor a public port.
	if service.Endpoint.Public || service.Endpoint.Port != 0 {
		t.Fatal("connector-only service reserved public ingress")
	}
	if _, found, err := d.ClaimServiceEndpointDNSWork(t.Context(), "dns-worker", now, time.Minute); err != nil || found {
		t.Fatal("connector-only service queued public DNS", found, err)
	}
	if err := d.DeleteService(t.Context(), service.ID, actor.ActingIdentityID, observedServiceDeletion(t, d, service.ID), now); err != nil {
		t.Fatal(err)
	}
	var removed bool
	if err := d.pool.QueryRow(t.Context(), `SELECT retired_at IS NOT NULL AND dns_state='removed' FROM control.service_endpoints WHERE service_id=$1`, service.ID).Scan(&removed); err != nil || !removed {
		t.Fatal("unmanaged endpoint deletion queued unnecessary DNS work", err)
	}
}

func oidcRouteRequest(t *testing.T, database *Database, now time.Time) serviceTestAuthority {
	t.Helper()
	session := newOIDCSession(t, database, now)
	member := session.Identity.Memberships[0]
	domains, err := database.ListTeamDomains(t.Context(), session.Identity.Identity.ID, member.TeamID)
	if err != nil || len(domains) != 1 {
		t.Fatal("managed domain prerequisite", err)
	}
	return serviceTestAuthority{TeamID: member.TeamID, DomainID: domains[0].ID, MembershipID: member.ID, ActingIdentityID: session.Identity.Identity.ID,
		CanonicalHostname: "demo." + member.ManagedLabel + "." + domains[0].CanonicalDomain}
}
