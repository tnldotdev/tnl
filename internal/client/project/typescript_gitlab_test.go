package project

import "testing"

func TestGitLabTypeScriptWorkloadUsesPipelineSourceKey(t *testing.T) {
	c, err := unmarshalTypeScriptTNL([]byte(`{"environments":{"staging":{"workloads":{"deploy":{"gitlab":{"project":"shop/storefront","pipelineSource":"push"},"visit":["db"]}}}}}`))
	if err != nil || c.Environments["staging"].Workloads["deploy"].GitLab == nil || c.Environments["staging"].Workloads["deploy"].GitLab.PipelineSource != "push" {
		t.Fatal("TypeScript pipelineSource was not normalized", err)
	}
}
