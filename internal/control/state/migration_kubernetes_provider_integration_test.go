package state

import "testing"

func TestIntegrationMigrationRejectsPreKubernetesProviderBaseline(t *testing.T) {
	testMigrationRejectsProviderBaseline(t,
		"tnl-control-fresh-v1-workload-google",
		[]string{"github", "vercel", "fly", "oidc", "google"}, "kubernetes")
}
