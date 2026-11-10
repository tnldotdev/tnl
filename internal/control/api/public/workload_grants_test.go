package public

import (
	"testing"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func workloadVisitGrants(t *testing.T, names ...string) controlv1.ProjectWorkloadGrants {
	t.Helper()
	resources := make([]controlv1.ProjectWorkloadResource, 0, len(names))
	for _, name := range names {
		var resource controlv1.ProjectWorkloadResource
		if err := resource.FromProjectWorkloadResource0(controlv1.ProjectWorkloadResource0{Service: name}); err != nil {
			t.Fatal(err)
		}
		resources = append(resources, resource)
	}
	return controlv1.ProjectWorkloadGrants{Visit: &resources}
}
