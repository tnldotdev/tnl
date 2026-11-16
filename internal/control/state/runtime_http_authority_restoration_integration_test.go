package state

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
)

func TestIntegrationRuntimeHTTPRestoredAuthorityLossPreservesEvidence(t *testing.T) {
	for _, mutation := range []string{"suspend", "delete", "domain_release"} {
		t.Run(mutation, func(t *testing.T) {
			d, now, owner, team := newAuthorityTeam(t)
			domain := deploymentCustomDomain(t, d, ApplyProjectConfigurationRequest{TeamID: team.ID, ActorID: owner}, now)
			service, err := d.CreateServiceAt(t.Context(), team.ID, owner, "runtime-http", "runtime-http",
				ServicePlacement{DomainID: domain.ID}, now, ServiceMetadata{Protocol: "http"},
				&ProjectServiceConfiguration{Target: "localhost:3000"})
			if err != nil || service.Protocol != "http" || service.DomainID != domain.ID {
				t.Fatal("runtime fixture did not create an actual HTTP service on its custom domain", err)
			}
			enrollment := publisherEnrollment(t, d, serviceTestAuthority{TeamID: team.ID, ActingIdentityID: owner},
				PublisherScope{TeamID: team.ID, Kind: "service", ServiceID: service.ID}, now)
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			publisher, err := d.RedeemPublisherEnrollment(t.Context(), enrollment.Key, public, now)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			const audience = "https://control.example/v1/publisher-runtime"
			process := strings.Repeat("b", 32)
			request := func(action string, epoch int64, at time.Time) PublisherRuntimeRequest {
				t.Helper()
				assertion, err := publisherproof.Sign(publisher.ID, publisher.KeyID,
					publisherproof.RuntimeScope(publisher.GrantID, action, process, epoch, ""), audience, private, at)
				if err != nil {
					t.Fatal(err)
				}
				return PublisherRuntimeRequest{PublisherIdentityID: publisher.ID, ScopeID: publisher.GrantID,
					ProcessRunID: process, Action: action, Assertion: assertion, Audience: audience,
					SourceIP: "192.0.2.7", ExpectedEpoch: epoch, Now: at}
			}
			started, err := d.PublisherRuntime(ctx, request("start", 0, now))
			if err != nil || started.Epoch != 1 {
				t.Fatal("actual HTTP publisher runtime did not start", err)
			}
			if _, err := d.PublisherRuntime(ctx, request("renew", started.Epoch, now.Add(time.Second))); err != nil {
				t.Fatal("runtime renewal was not usable before authority loss", err)
			}
			q := controlstatedb.New(d.pool)
			at := now.Add(2 * time.Second)
			before, err := publisherRuntimeStatus(ctx, q, publisher.ID, at)
			if err != nil || before == nil || !before.Active || before.ProcessRunID != process || before.Epoch != started.Epoch {
				t.Fatal("HTTP runtime lacked exact live evidence before authority loss", err)
			}
			switch mutation {
			case "suspend":
				suspended, err := d.SetServiceEnabled(ctx, service.ID, owner, false, at)
				if err != nil || suspended.Enabled {
					t.Fatal("actual service suspension failed", err)
				}
			case "delete":
				if err := d.DeleteService(ctx, service.ID, owner, at); err != nil {
					t.Fatal("actual service deletion failed", err)
				}
			case "domain_release":
				if err := d.ReleaseTeamDomain(ctx, owner, team.ID, domain.ID, at); err != nil {
					t.Fatal("actual domain release failed", err)
				}
				var releasing bool
				if err := d.pool.QueryRow(ctx, `SELECT state='releasing' FROM control.domains WHERE id=$1`,
					domain.ID).Scan(&releasing); err != nil || !releasing {
					t.Fatal("domain release did not commit its authority transition", err)
				}
			}
			var protocol string
			var enabled, deleted bool
			err = d.pool.QueryRow(ctx, `SELECT protocol,enabled,deleted_at IS NOT NULL
				FROM control.services WHERE id=$1`, service.ID).Scan(&protocol, &enabled, &deleted)
			if err != nil || protocol != "http" ||
				mutation == "delete" && !deleted ||
				mutation != "delete" && enabled {
				t.Fatal("service authority mutation did not reach the actual saved HTTP service", err)
			}
			active, err := q.PublisherRuntimeActive(ctx, controlstatedb.PublisherRuntimeActiveParams{
				PublisherIdentityID: publisher.ID, ProcessRunID: process, Epoch: started.Epoch, Now: timestamptz(at),
			})
			if err != nil || active {
				t.Fatal("HTTP service authority loss left the runtime active", err)
			}
			want := *before
			want.Active = false
			after, err := publisherRuntimeStatus(ctx, q, publisher.ID, at)
			if err != nil || !reflect.DeepEqual(&want, after) {
				t.Fatal("HTTP authority loss changed historical runtime evidence other than active", err)
			}
			if _, err := d.PublisherRuntime(ctx, request("renew", started.Epoch, at.Add(time.Second))); !failure.Only(err, ErrPublisherIdentity) {
				t.Fatal("unavailable HTTP service did not deny renewal with only the known authority error", err)
			}
			afterDenial, err := publisherRuntimeStatus(ctx, q, publisher.ID, at)
			if err != nil || !reflect.DeepEqual(&want, afterDenial) {
				t.Fatal("denied HTTP renewal rewrote historical runtime evidence", err)
			}
		})
	}
}
