package config

import "testing"

func TestWorkloadRefComponents(t *testing.T) {
	for _, prefix := range []string{"refs/heads/", "refs/tags/"} {
		for _, test := range []struct {
			name  string
			valid bool
		}{
			{"release./candidate", true},
			{"team./release./candidate", true},
			{"Release_Candidate/v1.0", true},
			{"-release/candidate-", true},
			{"release/candidate.", false},
			{"release./candidate.", false},
			{".release/candidate", false},
			{"release/.candidate", false},
			{"release.lock/candidate", false},
			{"release/candidate.lock", false},
			{"release//candidate", false},
			{"release/candidate/", false},
		} {
			t.Run(prefix+test.name, func(t *testing.T) {
				if got := ValidWorkloadRef(prefix + test.name); got != test.valid {
					t.Errorf("ValidWorkloadRef(%q) = %v, want %v", prefix+test.name, got, test.valid)
				}
			})
		}
	}
}

func TestWorkloadRefsAllowLiteralAtAndBrace(t *testing.T) {
	for _, prefix := range []string{"refs/heads/", "refs/tags/"} {
		for _, name := range []string{"release@canary", "release{canary", "team/release@canary", "@"} {
			if !ValidWorkloadRef(prefix + name) {
				t.Errorf("valid literal Git ref rejected: %q", prefix+name)
			}
		}
		for _, name := range []string{"release@{1}", "release@{canary", "release..canary", ".release", "release.lock", "release canary", "release\\canary", "release~1", "release^", "release:canary", "release?", "release*", "release[1]"} {
			if ValidWorkloadRef(prefix + name) {
				t.Errorf("invalid Git ref accepted: %q", prefix+name)
			}
		}
	}
	for _, selector := range []struct{ branch, tag *string }{
		{branch: new("release@canary")}, {tag: new("release@canary")},
	} {
		c := TNL{Services: Services{"db": {PublisherGroup: new("production")}}, Workloads: map[string]Workload{"deploy": {
			GitHub:   &WorkloadGitHub{Repository: new("shop/storefront"), Workflow: ".github/workflows/deploy.yml", Branch: selector.branch, Tag: selector.tag},
			Services: []string{"db"},
		}}}
		if err := ValidateWorkloads(c); err != nil {
			t.Errorf("GitHub selector with a literal @ rejected: %v", err)
		}
	}
}
