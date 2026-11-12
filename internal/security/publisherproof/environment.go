package publisherproof

import controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"

// same environment publisher compares immutable enrolled identity facts.
func SameEnvironmentPublisher(first, second controlv1.EnvironmentPublisher) bool {
	return first == second
}
