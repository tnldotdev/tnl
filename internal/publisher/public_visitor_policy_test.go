package publisher

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestPublisherVisitorPolicyReportsExplicitEmptyAndAllInstalledAllocations(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		base := &policyClientFixture{key: ed25519.NewKeyFromSeed([]byte(strings.Repeat("p", 32)))}
		client := policyClientFunc(func(ctx context.Context, body controlv1.PublisherVisitorPolicyRequest, token string) (controlv1.VisitorPolicyUpdate, error) {
			encoded, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			if base.calls.Load() == 0 {
				if body.ObservedAllocations == nil || len(body.ObservedAllocations) != 0 || !strings.Contains(string(encoded), `"observed_allocations":[]`) {
					t.Fatal("new public publisher did not send an explicit empty observation array", string(encoded))
				}
			} else {
				if len(body.ObservedAllocations) != 2048 {
					t.Fatal("public publisher truncated installed observations", len(body.ObservedAllocations))
				}
				for index, observation := range body.ObservedAllocations {
					if observation.AllocationId != fmt.Sprintf("salloc_%022d", index) || observation.RunId != body.RunId || observation.RunNumber != body.RunNumber || observation.ValidUntil.IsZero() {
						t.Fatal("observation omitted or changed installed allocation evidence", index)
					}
				}
			}
			update, err := base.ReadPublisherVisitorPolicy(ctx, body, token)
			if err != nil {
				return update, err
			}
			for index := range 2048 {
				update.Policy.StreamAllocations = append(update.Policy.StreamAllocations, controlv1.StreamCapacityAllocation{
					Id: fmt.Sprintf("salloc_%022d", index), Resource: body.Resource, RunId: body.RunId, RunNumber: body.RunNumber,
					IngressId: "ingress", IngressRunId: "process", IngressLeaseRevision: 1, Capacity: 1,
					ObservedAt: time.Now(), ValidUntil: time.Now().Add(10 * time.Second), ReservationKey: []byte(strings.Repeat("k", 32)),
				})
			}
			return update, nil
		})
		policy, err := prepareVisitorPolicy(t.Context(), client, visitorscope.Scope{Kind: visitorscope.PublicURL, ID: certificateTestPublicURLID}, "pr_0123456789abcdefghijkl", 1, "run-secret", nil)
		if err != nil {
			t.Fatal(err)
		}
		defer policy.Close()
		if base.calls.Load() != 2 {
			t.Fatal("installed allocations were not reported before the next poll", base.calls.Load())
		}
		if err := policy.refresh(t.Context()); err != nil {
			t.Fatal(err)
		}
		if base.calls.Load() != 3 {
			t.Fatal("observation preparation made unexpected control requests", base.calls.Load())
		}
	})
}
