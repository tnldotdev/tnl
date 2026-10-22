package naming

import "strings"

type ManagedURLMode string

const (
	ManagedURLModeSimple    ManagedURLMode = "simple"
	ManagedURLModeGenerated ManagedURLMode = "generated"
)

// NamespaceFacts are the authority-owned names used to place public URLs.
type NamespaceFacts struct {
	Domain       string
	Managed      bool
	Mode         ManagedURLMode
	Personal     bool
	TeamName     string
	MemberSlug   string
	ManagedLabel string
}

// PublicURLNamespace returns the default naming suffix and whether URLs made
// beneath it belong to the team instead of one membership.
func PublicURLNamespace(facts NamespaceFacts) (string, bool) {
	if facts.Personal && !facts.Managed {
		return facts.Domain, true
	}
	if !facts.Managed {
		return facts.MemberSlug + "." + facts.Domain, false
	}
	if facts.Mode == ManagedURLModeSimple {
		if facts.Personal {
			return facts.TeamName + "." + facts.Domain, false
		}
		return facts.MemberSlug + "." + facts.TeamName + "." + facts.Domain, false
	}
	return facts.ManagedLabel + "." + facts.Domain, false
}

// SharedPublicURLNamespace keeps team-owned managed URLs beneath that team's
// reserved label. administrator privilege never selects the server-wide suffix.
func SharedPublicURLNamespace(domain string, managed bool, mode ManagedURLMode, teamName, teamLabel string) string {
	if !managed {
		return domain
	}
	if mode == ManagedURLModeSimple {
		return teamName + "." + domain
	}
	return teamLabel + "." + domain
}

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

// PublicURLWildcard returns the narrowest wildcard that covers hostname while
// staying within the authorized namespace. wildcards cover one DNS label.
func PublicURLWildcard(hostname, namespace string) string {
	if depth, within := ChildDepth(hostname, namespace); !within || depth == 0 {
		return ""
	}
	_, parent, _ := strings.Cut(hostname, ".")
	return "*." + parent
}
