package httpprotection

import "testing"

func TestSettings(t *testing.T) {
	if s := (Settings{}).Defaults(); s.WAF != Block || *s.MaxBodyBytes != 1<<20 {
		t.Fatal(s)
	}
	for _, s := range []Settings{
		{},
		{WAF: Off},
		{WAF: Detect, MaxBodyBytes: new(MaxBodyBytes)},
		{Exclusions: []Exclusion{{RuleID: 942100, Path: "/search", Parameter: "q"}}},
	} {
		if err := s.Validate(); err != nil {
			t.Fatalf("%+v: %v", s, err)
		}
	}
	for _, s := range []Settings{
		{WAF: "allow"},
		{MaxBodyBytes: new(0)},
		{MaxBodyBytes: new(-1)},
		{MaxBodyBytes: new(MaxBodyBytes + 1)},
		{Exclusions: []Exclusion{{RuleID: 1, Path: "/search"}}},
		{Exclusions: []Exclusion{{RuleID: 949110, Path: "/search"}}},
		{Exclusions: []Exclusion{{RuleID: 942100, Path: "/search?q=x"}}},
		{Exclusions: []Exclusion{{RuleID: 942100, Path: "/__tnl/team/access"}}},
		{Exclusions: []Exclusion{{RuleID: 942100, Path: "/search", Parameter: "q,ctl:ruleEngine=Off"}}},
	} {
		if err := s.Validate(); err == nil {
			t.Fatalf("accepted %+v", s)
		}
	}
}
