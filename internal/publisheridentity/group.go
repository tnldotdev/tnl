package publisheridentity

import "github.com/tnldotdev/tnl/pkg/api/controlv1"

// SameGroupMember compares immutable membership fields. selectors are mutable;
// callers verify them separately against control's current/historical names.
func SameGroupMember(first, second controlv1.PublisherGroupMember) bool {
	first.GroupName = second.GroupName
	return first == second
}
