package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
)

func TestIntegrationPublisherRuntimeLifecycle(t *testing.T) {
	for _, kind := range []string{"group", "installed"} {
		t.Run(kind, func(t *testing.T) {
			d, now := newControlStateIntegrationDatabase(t, "publisher_runtime_"+kind)
			ctx := t.Context()
			q := controlstatedb.New(d.pool)
			var id, key, scope, team string
			var private ed25519.PrivateKey
			var preflight func()
			var rename func()
			if kind == "group" {
				r := appliedProjectRequest(t, d, now)
				r.Configuration = ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{"remote": {}}, Services: map[string]ProjectServiceConfiguration{"api": {PublisherGroup: "remote", Target: "api.internal:3000"}, "db": {PublisherGroup: "remote", Target: "db.internal:5432", Protocol: "postgres"}}}
				applied, err := d.ApplyProjectConfiguration(ctx, r)
				if err != nil {
					t.Fatal(err)
				}
				e, err := d.IssuePublisherGroupEnrollment(ctx, r.TeamID, r.ProjectKey, "remote", r.ActorID, 2, time.Hour, now)
				if err != nil {
					t.Fatal(err)
				}
				replica := enrollAppliedGroup(t, d, r, e, now)
				id, key, scope, team, private = replica.member.PublisherIdentityID, replica.member.KeyID, replica.member.GroupID, r.TeamID, replica.private
				preflight = func() {
					if _, err := d.RedeemPublisherGroupEnrollment(ctx, e.Key, private.Public().(ed25519.PublicKey), now); err != nil {
						t.Fatal(err)
					}
					for _, action := range []string{"verify", "lease"} {
						audience := "https://control.example/v1/publisher-groups/" + action
						proof, _ := publisherproof.Sign(id, key, scope, audience, private, now)
						if action == "verify" {
							_, err = d.VerifyPublisherGroupIdentity(ctx, id, scope, proof, audience, now)
						} else {
							_, err = d.AcquirePublisherGroupLease(ctx, id, scope, proof, audience, now)
						}
						if err != nil {
							t.Fatal(err)
						}
					}
				}
				rename = func() {
					if _, err := d.RenamePublisherGroup(ctx, team, r.ProjectKey, "remote", "live", r.ActorID, applied.Revision, now); err != nil {
						t.Fatal(err)
					}
				}
			} else {
				r := oidcRouteRequest(t, d, now)
				u := createTestPublicURL(t, d, r, now)
				e := publisherEnrollment(t, d, r, PublisherScope{TeamID: u.TeamID, Kind: "saved_public_url", PublicURLID: u.ID}, now)
				public, k, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				private = k
				p, err := d.RedeemPublisherEnrollment(ctx, e.Key, public, now)
				if err != nil {
					t.Fatal(err)
				}
				id, key, scope, team = p.ID, p.KeyID, p.GrantID, u.TeamID
				preflight = func() {
					if _, err := d.RedeemPublisherEnrollment(ctx, e.Key, public, now); err != nil {
						t.Fatal(err)
					}
					publisherAccess(t, d, p, private, "8.8.4.4/32", now)
				}
				rename = func() {}
			}
			status := func(at time.Time) *PublisherRuntimeStatus {
				t.Helper()
				s, err := publisherRuntimeStatus(ctx, q, id, at)
				if err != nil {
					t.Fatal(err)
				}
				return s
			}
			preflight()
			if status(now) != nil {
				t.Fatal("provisioning recorded a runtime")
			}
			request := func(action, run, source string, epoch int64) PublisherRuntimeRequest {
				t.Helper()
				r := PublisherRuntimeRequest{PublisherIdentityID: id, ScopeID: scope, ProcessRunID: run, Action: action, ExpectedEpoch: epoch, SourceIP: source, Audience: "https://control.example/v1/publisher-runtime", Now: now}
				var err error
				r.Assertion, err = publisherproof.Sign(id, key, publisherproof.RuntimeScope(scope, action, run, epoch), r.Audience, private, now)
				if err != nil {
					t.Fatal(err)
				}
				return r
			}
			run := strings.Repeat("a", 32)
			inspect := request("inspect", run, "8.8.4.4", 0)
			if r, err := d.PublisherRuntime(ctx, inspect); err != nil || r.Epoch != 0 || status(now) != nil {
				t.Fatal("inspect mutated observation", err)
			}
			start := request("start", run, "::ffff:8.8.8.8", 0)
			r, err := d.PublisherRuntime(ctx, start)
			if err != nil || r.Epoch != 1 {
				t.Fatal("start", r, err)
			}
			if kind == "group" {
				if r.GroupLease == nil {
					t.Fatal("no runtime group lease")
				}
				a, err := d.GetPublisherGroupAssignments(ctx, r.GroupLease.AccessToken, now)
				if err != nil || len(a.Services) != 2 {
					t.Fatal("runtime lease lost assignments", err)
				}
			}
			original := status(now)
			if original == nil || original.Address != "8.8.8.8" || original.AddressFamily != "ipv4" || original.Evidence != "control_observed" || !original.Active || original.TeamID != team {
				t.Fatalf("startup: %+v", original)
			}
			if _, err = d.PublisherRuntime(ctx, start); !errors.Is(err, ErrPublisherIdentity) {
				t.Fatal("assertion replay", err)
			}
			preflight()
			rename()
			if !reflect.DeepEqual(status(now), original) {
				t.Fatal("preflight or selector rename changed observation")
			}
			now = now.Add(time.Second)
			if _, err = d.PublisherRuntime(ctx, request("start", run, "8.8.4.4", 0)); err != nil {
				t.Fatal("lost reply retry", err)
			}
			if !reflect.DeepEqual(status(now), original) {
				t.Fatal("retry overwrote startup evidence")
			}
			bad := request("renew", run, "8.8.4.4", 1)
			bad.ProcessRunID = strings.Repeat("c", 32)
			if _, err = d.PublisherRuntime(ctx, bad); !errors.Is(err, ErrPublisherIdentity) {
				t.Fatal("identity-run proof substitution", err)
			}
			bad = request("renew", run, "8.8.4.4", 1)
			bad.Action = "stop"
			if _, err = d.PublisherRuntime(ctx, bad); !errors.Is(err, ErrPublisherIdentity) {
				t.Fatal("action proof substitution", err)
			}
			if !reflect.DeepEqual(status(now), original) {
				t.Fatal("failed authentication wrote observation")
			}
			if _, err = d.PublisherRuntime(ctx, request("renew", run, "2606:4700:4700::1111", 1)); err != nil {
				t.Fatal(err)
			}
			s := status(now)
			if s.AddressFamily != "ipv6" || s.Address != "2606:4700:4700::1111" || !s.LastSeenAt.Equal(now) || !s.StartedAt.Equal(original.StartedAt) {
				t.Fatalf("NAT/family change: %+v", s)
			}
			for range 20 {
				if _, err = d.PublisherRuntime(ctx, request("renew", run, "10.1.2.3", 1)); err != nil {
					t.Fatal(err)
				}
			}
			if s = status(now); s.Address != "" || s.AddressFamily != "unknown" || !s.Active {
				t.Fatalf("private runtime: %+v", s)
			}
			var count int
			if err = d.pool.QueryRow(ctx, `SELECT count(*) FROM control.publisher_runtimes WHERE publisher_identity_id=$1`, id).Scan(&count); err != nil || count != 1 {
				t.Fatal("unbounded heartbeat rows", count, err)
			}
			if status(now.Add(3*time.Minute)).Active || !status(now.Add(3*time.Minute)).LastSeenAt.Equal(now) {
				t.Fatal("crash fabricated liveness")
			}
			newRun := strings.Repeat("b", 32)
			if _, err = d.PublisherRuntime(ctx, request("start", newRun, "8.8.4.4", 1)); err != nil {
				t.Fatal("replacement", err)
			}
			current := status(now)
			for _, action := range []string{"start", "renew", "stop"} {
				epoch := int64(1)
				if action == "start" {
					epoch = 0
				}
				if _, err = d.PublisherRuntime(ctx, request(action, run, "8.8.8.8", epoch)); !errors.Is(err, ErrPublisherRuntimeStale) {
					t.Fatal("old process", action, err)
				}
			}
			if !reflect.DeepEqual(status(now), current) {
				t.Fatal("old instance overwrote replacement")
			}
			now = now.Add(time.Second)
			if _, err = d.PublisherRuntime(ctx, request("stop", newRun, "10.0.0.1", 2)); err != nil {
				t.Fatal(err)
			}
			stopped := status(now)
			if stopped.Active || stopped.StoppedAt == nil || stopped.Address != "8.8.4.4" || !stopped.ObservedAt.Equal(current.ObservedAt) || !stopped.LastSeenAt.Equal(now) {
				t.Fatalf("stop lost evidence: %+v", stopped)
			}
			if _, err = d.PublisherRuntime(ctx, request("renew", newRun, "8.8.8.8", 2)); !errors.Is(err, ErrPublisherRuntimeStale) {
				t.Fatal("stopped process renewed", err)
			}
			// simultaneous replacements compare the same prior epoch; exactly one
			// wins, with no lost update or extra history row.
			pending := []PublisherRuntimeRequest{request("start", strings.Repeat("c", 32), "8.8.8.8", 2), request("start", strings.Repeat("d", 32), "8.8.4.4", 2)}
			results := make(chan error, len(pending))
			var wg sync.WaitGroup
			for _, candidate := range pending {
				wg.Go(func() { _, err := d.PublisherRuntime(ctx, candidate); results <- err })
			}
			wg.Wait()
			close(results)
			wins, stale := 0, 0
			for err := range results {
				if err == nil {
					wins++
				} else if errors.Is(err, ErrPublisherRuntimeStale) {
					stale++
				} else {
					t.Fatal(err)
				}
			}
			if wins != 1 || stale != 1 || status(now).Epoch != 3 {
				t.Fatal("concurrent replacement did not fence its loser")
			}
		})
	}
}
