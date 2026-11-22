package controlv1

import "strings"

// AliasPolicyConfirmationQuery opts into host-bound confirmation on both
// publisher policy reads and run renewals. older controls ignore the query.
const AliasPolicyConfirmationQuery = "confirm_alias"

// ValidPublisherPolicyBookmark checks an opaque watch hint. it says nothing
// about the service's current visitor permissions or deadlines.
func ValidPublisherPolicyBookmark(value string) bool {
	return len(value) == 64 && strings.Trim(value, "0123456789abcdef") == ""
}
