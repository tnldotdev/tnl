package controlv1

import "strings"

// ValidPublisherPolicyBookmark checks an opaque watch hint. it says nothing
// about the service's current visitor permissions or deadlines.
func ValidPublisherPolicyBookmark(value string) bool {
	return len(value) == 64 && strings.Trim(value, "0123456789abcdef") == ""
}
