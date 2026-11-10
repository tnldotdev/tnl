package config

import "testing"

func TestGoogleWorkloadBlock(t *testing.T) {
	c := TNL{Services: Services{"db": {PublisherGroup: new("production")}}, Workloads: map[string]Workload{"app": {Google: &WorkloadGoogle{ServiceAccount: "orders@project.iam.gserviceaccount.com"}, Grants: ServiceVisitGrants("db")}}}
	if err := ValidateWorkloads(c); err != nil {
		t.Fatal(err)
	}
	for _, account := range []string{"112010400000000710080", "123-compute@developer.gserviceaccount.com", "project@appspot.gserviceaccount.com"} {
		if !ValidGoogleServiceAccount(account) {
			t.Fatal("valid service account rejected", account)
		}
	}
	for _, account := range []string{"", "0", "orders@example.com", "*@project.iam.gserviceaccount.com", "orders@project.iam.gserviceaccount.com\n"} {
		if ValidGoogleServiceAccount(account) {
			t.Fatal("invalid account accepted", account)
		}
	}
	p := c.Workloads["app"]
	p.OIDC = &WorkloadOIDC{Issuer: "https://issuer.example", Claims: map[string]string{"sub": "other"}}
	c.Workloads["app"] = p
	if ValidateWorkloads(c) == nil {
		t.Fatal("mixed provider blocks accepted")
	}
}
