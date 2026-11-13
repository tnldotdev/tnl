package publisherproof

import controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"

// SameDeploymentMember compares immutable membership fields. selectors are mutable;
// callers verify them separately against control's current/historical names.
func SameDeploymentMember(first, second controlv1.DeploymentPublisherIdentity) bool {
	first.DeploymentName = second.DeploymentName
	return first == second
}
