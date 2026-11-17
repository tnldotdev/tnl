package state

import (
	"errors"
	"reflect"
	"testing"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationAppliedProtocolChangesRequirePublicPortRelease(t *testing.T) {
	for _, protocol := range []string{"http", "postgres"} {
		t.Run(protocol, func(t *testing.T) {
			d, now, _, _ := newPublishRunPrerequisites(t)
			ctx := t.Context()
			r := appliedProjectRequest(t, d, now)
			binding := ProjectServiceConfiguration{Protocol: protocol, Target: "127.0.0.1:3000", Public: new(true)}
			r.Configuration.Services["web"] = binding
			r = selectedProjectRequest(r, "production")
			applied, err := d.ApplyProjectConfiguration(ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			id := applied.Services[0].ServiceID
			q := controlstatedb.New(d.pool)
			before, err := q.GetService(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			next := binding
			next.Protocol, next.Public = "http", new(false)
			if protocol == "http" {
				next.Protocol = "postgres"
			}
			r.ExpectedRevision = applied.Revision
			r.ServiceDeclarations["web"] = next.Protocol
			r.Configuration.Services["web"] = next
			if _, err := d.ApplyProjectConfiguration(ctx, r); !errors.Is(err, ErrServiceConflict) {
				t.Fatal("protocol edit bypassed public endpoint disablement", err)
			}
			after, err := q.GetService(ctx, id)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("rejected protocol edit changed saved service facts", err)
			}
			binding.Public = new(false)
			r.ServiceDeclarations["web"] = binding.Protocol
			r.Configuration.Services["web"] = binding
			applied, err = d.ApplyProjectConfiguration(ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			r.ExpectedRevision = applied.Revision
			r.ServiceDeclarations["web"] = next.Protocol
			r.Configuration.Services["web"] = next
			if protocol != "http" {
				if _, err := d.ApplyProjectConfiguration(ctx, r); !errors.Is(err, ErrServiceConflict) {
					t.Fatal("protocol edit abandoned its held public port", err)
				}
				current, err := d.GetService(ctx, id, r.ActorID)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := d.ReleaseServiceEndpoint(ctx, id, r.ActorID, current.EndpointRevision, current.Endpoint.Port, now); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := d.ApplyProjectConfiguration(ctx, r); err != nil {
				t.Fatal("released connector-only service could not change protocol", err)
			}
			final, err := q.GetService(ctx, id)
			wantPort := int32(0)
			if next.Protocol == "http" {
				wantPort = 443
			}
			if err != nil || final.Protocol != next.Protocol || final.Public || final.ServicePort.Int32 != wantPort ||
				final.TrustRevision != before.TrustRevision+1 || final.CertificateHostname != before.CertificateHostname {
				t.Fatal("protocol change lost saved identity or independent endpoint facts", final, err)
			}
		})
	}
}
