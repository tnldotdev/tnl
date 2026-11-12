package project

import "testing"

func TestGoogleTypeScriptWorkloadUsesServiceAccountKey(t *testing.T) {
	c, err := unmarshalTypeScriptTNL([]byte(`{"environments":{"staging":{"workloads":{"app":{"google":{"serviceAccount":"orders@project.iam.gserviceaccount.com"},"visit":["db"]}}}}}`))
	if err != nil || c.Environments["staging"].Workloads["app"].Google == nil || c.Environments["staging"].Workloads["app"].Google.ServiceAccount != "orders@project.iam.gserviceaccount.com" {
		t.Fatal("TypeScript serviceAccount was not normalized", err)
	}
}
