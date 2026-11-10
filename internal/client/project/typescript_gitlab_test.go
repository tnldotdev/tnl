package project

import "testing"

func TestGitLabTypeScriptWorkloadUsesPipelineSourceKey(t *testing.T) {
	c, err := unmarshalTypeScriptTNL([]byte(`{"workloads":{"deploy":{"gitlab":{"project":"shop/storefront","pipelineSource":"push"},"grants":{"visit":[{"service":"db"}]}}}}`))
	if err != nil || c.Workloads["deploy"].GitLab == nil || c.Workloads["deploy"].GitLab.PipelineSource != "push" {
		t.Fatal("TypeScript pipelineSource was not normalized", err)
	}
}
