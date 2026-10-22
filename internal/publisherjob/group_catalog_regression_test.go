package publisherjob

import (
	"bytes"
	"testing"
)

func TestStandaloneGroupsListChurnPreservesRetiredAuthority(t *testing.T) {
	options := testOptions(t)
	options.StandaloneGroups = true
	r, err := Open(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	first, _, firstKey := kindFixture(t, KindGroup)
	first.ID = JobKey(first.Server, "group", first.GroupMember.GroupId+":"+first.GroupInstance)
	if err := r.ReplaceGroups(t.Context(), []GroupInstall{{first, firstKey}}); err != nil {
		t.Fatal(err)
	}
	for range 256 {
		job, _, key := kindFixture(t, KindGroup)
		job.ID = JobKey(job.Server, "group", job.GroupMember.GroupId+":"+job.GroupInstance)
		if err := r.ReplaceGroups(t.Context(), []GroupInstall{{job, key}}); err != nil {
			t.Fatal("one-entry startup list exhausted by historical references", err)
		}
	}
	member, key, _, err := r.GroupIdentity(t.Context(), first)
	if err != nil || member != *first.GroupMember || !bytes.Equal(key, firstKey) {
		t.Fatal("retirement lost issued signing authority", err)
	}
	if err := r.ReplaceGroups(t.Context(), []GroupInstall{{first, firstKey}}); err != nil {
		t.Fatal("original authority could not be explicitly reactivated", err)
	}
	_, _, replacement := kindFixture(t, KindGroup)
	if err := r.ReplaceGroups(t.Context(), []GroupInstall{{first, replacement}}); err == nil {
		t.Fatal("retired selection permitted a replacement key")
	}
}
