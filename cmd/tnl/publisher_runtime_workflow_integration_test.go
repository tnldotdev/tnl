package main

import (
	"testing"

	controlclient "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

// local CLI workflows must record an unknown address from the socket peer, not
// skip the observation or invent a public source. epoch zero means never started.
func assertWorkflowPublisherRuntime(t *testing.T, client *controlclient.Client, team, id string, epoch int64, active bool) *controlv1.PublisherRuntimeStatus {
	t.Helper()
	page, err := client.ListPublisherIdentities(t.Context(), team, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, identity := range page.Identities {
		if identity.Id != id {
			continue
		}
		r := identity.Runtime
		if epoch == 0 {
			if r != nil {
				t.Fatal("provisioning recorded a runtime observation")
			}
			return nil
		}
		if r == nil || r.Epoch != epoch || r.Active != active || r.PublisherIdentityId != id || r.TeamId != team || len(r.ProcessRunId) != 32 || r.Evidence != "control_observed" || r.AddressFamily != "unknown" || r.Address != nil || r.ObservedAt.IsZero() || r.StartedAt.IsZero() || r.LastSeenAt.Before(r.ObservedAt) || (r.StoppedAt == nil) != active {
			t.Fatalf("unexpected runtime observation: %+v; want epoch=%d active=%t", r, epoch, active)
		}
		return r
	}
	t.Fatal("publisher missing from authorized status")
	return nil
}
