package project

import "testing"

func TestGoogleTypeScriptWorkloadUsesServiceAccountKey(t *testing.T) {
	c, err := unmarshalTypeScriptTNL([]byte(`{"workloads":{"app":{"google":{"serviceAccount":"orders@project.iam.gserviceaccount.com"},"services":["db"]}}}`))
	if err != nil || c.Workloads["app"].Google == nil || c.Workloads["app"].Google.ServiceAccount != "orders@project.iam.gserviceaccount.com" {
		t.Fatal("TypeScript serviceAccount was not normalized", err)
	}
}
