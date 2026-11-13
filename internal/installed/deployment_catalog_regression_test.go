package installed

import (
	"bytes"
	"testing"
)

func TestStandaloneDeploymentsListChurnPreservesRetiredAuthority(t *testing.T) {
	options := testOptions(t)
	options.StandaloneDeployments = true
	r, err := Open(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	first, _, firstKey := kindFixture(t, KindDeployment)
	first.ID = JobKey(first.Server, "deployment", first.DeploymentMember.DeploymentId+":"+first.DeploymentInstance)
	if err := r.ReplaceDeployments(t.Context(), []DeploymentInstall{{first, firstKey}}); err != nil {
		t.Fatal(err)
	}
	for range 256 {
		job, _, key := kindFixture(t, KindDeployment)
		job.ID = JobKey(job.Server, "deployment", job.DeploymentMember.DeploymentId+":"+job.DeploymentInstance)
		if err := r.ReplaceDeployments(t.Context(), []DeploymentInstall{{job, key}}); err != nil {
			t.Fatal("one-entry startup list exhausted by historical references", err)
		}
	}
	member, key, _, err := r.DeploymentIdentity(t.Context(), first)
	if err != nil || member != *first.DeploymentMember || !bytes.Equal(key, firstKey) {
		t.Fatal("retirement lost issued signing authority", err)
	}
	if err := r.ReplaceDeployments(t.Context(), []DeploymentInstall{{first, firstKey}}); err != nil {
		t.Fatal("original authority could not be explicitly reactivated", err)
	}
	_, _, replacement := kindFixture(t, KindDeployment)
	if err := r.ReplaceDeployments(t.Context(), []DeploymentInstall{{first, replacement}}); err == nil {
		t.Fatal("retired selection permitted a replacement key")
	}
}
