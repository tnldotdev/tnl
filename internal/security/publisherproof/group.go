package publisherproof

import controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"

// SameGroupMember compares immutable membership fields. selectors are mutable;
// callers verify them separately against control's current/historical names.
func SameGroupMember(first, second controlv1.PublisherGroupMember) bool {
	first.GroupName = second.GroupName
	return first == second
}
