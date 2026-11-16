package public

import (
	"errors"
	"reflect"
	"slices"
	"testing"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationServicePolicyClearRestorationUsesCompleteDeclaration(t *testing.T) {
	f := newRestoredServiceHTTP(t)
	ctx := t.Context()
	client, err := clientcontrol.New(f.server.URL, f.server.Client(), credentials.AccessToken(f.owner))
	if err != nil {
		t.Fatal(err)
	}
	const target = "localhost:4000"
	declaration := func(prefixes *[]string) *controlv1.ProjectServiceConfiguration {
		return &controlv1.ProjectServiceConfiguration{
			Target: target,
			Http: &controlv1.ProjectServiceHTTP{Access: &controlv1.ProjectHTTPAccess{
				Mode: new(controlv1.Restricted), Ip: prefixes,
			}},
		}
	}
	readPolicy := func(prefixes []string) (*controlv1.ProjectServiceConfiguration, *controlstate.ProjectServiceConfiguration, string) {
		t.Helper()
		wire, digest, err := client.GetServiceConfiguration(ctx, f.service.ID)
		if err != nil || wire == nil || wire.Target != target || wire.Http == nil || wire.Http.Access == nil ||
			wire.Http.Access.Mode == nil || *wire.Http.Access.Mode != controlv1.Restricted {
			t.Fatal("protected configuration lost its target or restricted access", err)
		}
		var actual []string
		if wire.Http.Access.Ip != nil {
			actual = *wire.Http.Access.Ip
		}
		if !slices.Equal(actual, prefixes) {
			t.Fatal("protected configuration changed the exact IP policy", actual, prefixes)
		}
		saved, savedDigest, err := f.database.GetServiceConfiguration(ctx, f.service.ID, f.actor)
		if err != nil || saved == nil || saved.Target != target || saved.HTTP == nil || saved.HTTP.Access == nil ||
			saved.HTTP.Access.Mode != "restricted" || !slices.Equal(saved.HTTP.Access.IP, prefixes) ||
			digest == "" || savedDigest != digest {
			t.Fatal("durable configuration lost its target, exact policy, or protected read condition", err)
		}
		return wire, saved, digest
	}

	seeded, err := client.ConfigureService(ctx, f.service.ID, controlv1.UpdateServiceRequest{
		Protocol: controlv1.ServiceProtocolHTTP, PublisherPool: f.service.PublisherPool,
		ExpectedTrustRevision: f.service.TrustRevision,
		Configuration:         declaration(new([]string{"192.0.2.9/24"})),
	})
	if err != nil || seeded.Id != f.service.ID {
		t.Fatal("could not save the original nonempty IP policy", err)
	}
	originalWire, originalSaved, originalDigest := readPolicy([]string{"192.0.2.0/24"})

	// omitting the whole declaration retains it; this is not a nested patch.
	retained, err := client.ConfigureService(ctx, f.service.ID, controlv1.UpdateServiceRequest{
		Protocol: seeded.Protocol, PublisherPool: seeded.PublisherPool,
		ExpectedTrustRevision: seeded.TrustRevision,
	})
	if err != nil || retained.Id != seeded.Id {
		t.Fatal("omitting configuration did not retain the saved service", err)
	}
	retainedWire, retainedSaved, retainedDigest := readPolicy([]string{"192.0.2.0/24"})
	if retainedDigest != originalDigest || !reflect.DeepEqual(retainedWire, originalWire) || !reflect.DeepEqual(retainedSaved, originalSaved) {
		t.Fatal("omitting configuration changed the saved declaration")
	}

	// another full policy edit invalidates the observed declaration condition
	// without relying on a stale target-trust revision.
	changed, err := client.ConfigureService(ctx, f.service.ID, controlv1.UpdateServiceRequest{
		Protocol: retained.Protocol, PublisherPool: retained.PublisherPool,
		ExpectedTrustRevision: retained.TrustRevision, ExpectedConfigurationDigest: &originalDigest,
		Configuration: declaration(new([]string{"198.51.100.9/24"})),
	})
	if err != nil || changed.Id != seeded.Id || changed.TrustRevision != retained.TrustRevision ||
		changed.EndpointRevision != retained.EndpointRevision {
		t.Fatal("policy-only replacement changed target trust or endpoint identity", err)
	}
	currentWire, currentSaved, currentDigest := readPolicy([]string{"198.51.100.0/24"})
	if currentDigest == originalDigest {
		t.Fatal("changed IP policy retained the old configuration condition")
	}

	// the complete desired declaration supplies its target and access mode,
	// but omits ip entries. it must replace, not merge with, the old policy.
	clear := controlv1.UpdateServiceRequest{
		Protocol: changed.Protocol, PublisherPool: changed.PublisherPool,
		ExpectedTrustRevision: changed.TrustRevision, ExpectedConfigurationDigest: &originalDigest,
		Configuration: declaration(nil),
	}
	if _, err := client.ConfigureService(ctx, f.service.ID, clear); !errors.Is(err, clientcontrol.ErrStatusConflict) {
		t.Fatal("stale observed configuration cleared the current IP policy", err)
	}
	afterWire, afterSaved, afterDigest := readPolicy([]string{"198.51.100.0/24"})
	if afterDigest != currentDigest || !reflect.DeepEqual(afterWire, currentWire) || !reflect.DeepEqual(afterSaved, currentSaved) {
		t.Fatal("rejected stale clear changed the current declaration")
	}
	after, err := client.GetService(ctx, f.service.ID)
	if err != nil || !reflect.DeepEqual(after, changed) {
		t.Fatal("rejected stale clear changed the saved service", err)
	}

	clear.ExpectedConfigurationDigest = &currentDigest
	cleared, err := client.ConfigureService(ctx, f.service.ID, clear)
	if err != nil || cleared.Id != changed.Id || cleared.TrustRevision != changed.TrustRevision ||
		cleared.EndpointRevision != changed.EndpointRevision {
		t.Fatal("current complete replacement failed or changed trust or endpoint identity", err)
	}
	_, _, clearedDigest := readPolicy(nil)
	if clearedDigest == currentDigest {
		t.Fatal("clearing the IP policy retained its previous configuration condition")
	}
}
