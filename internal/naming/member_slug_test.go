package naming

import (
	"strings"
	"testing"
)

func TestMemberSlugFromDisplayName(t *testing.T) {
	for name, want := range map[string]string{
		"Chase Adams": "chase-adams", "Zoë D’Amour": "zoe-d-amour",
		"LOCAL Administrator": "local-administrator", "  a--b  ": "a-b",
		"李 小龙": "", "😺": "", "John.Doe_12": "john-doe-12",
		"Élodie Ruiz": "elodie-ruiz", strings.Repeat("A", 70): strings.Repeat("a", 63),
	} {
		if got := MemberSlugFromDisplayName(name); got != want {
			t.Fatalf("%q -> %q, want %q", name, got, want)
		}
	}
}

func TestValidAuthorityLabel(t *testing.T) {
	for _, value := range []string{"studio", "design-team", "1-team"} {
		if !ValidAuthorityLabel(value) {
			t.Fatalf("valid label %q rejected", value)
		}
	}
	for _, value := range []string{"", "Studio", "Design Team", "team.name", "-team", "team-", "team_1", strings.Repeat("a", 64)} {
		if ValidAuthorityLabel(value) {
			t.Fatalf("invalid label %q accepted", value)
		}
	}
}
