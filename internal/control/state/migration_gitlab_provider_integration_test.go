package state

import "testing"

func TestIntegrationMigrationRejectsPreGitLabProviderBaseline(t *testing.T) {
	testMigrationRejectsProviderBaseline(t,
		"tnl-control-fresh-v1-workload-kubernetes",
		[]string{"github", "vercel", "fly", "oidc", "google", "kubernetes"}, "gitlab")
}
