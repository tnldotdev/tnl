package naming

// MemberNamespace returns the suffix assigned to one membership on a ready
// domain. managed domains use the server's label; custom domains use the
// member slug.
func MemberNamespace(domain string, managed bool, managedLabel, memberSlug string) string {
	label := memberSlug
	if managed {
		label = managedLabel
	}
	return label + "." + domain
}
