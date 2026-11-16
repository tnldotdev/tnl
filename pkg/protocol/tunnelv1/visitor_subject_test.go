package tunnelv1

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRegisteredVisitorSubjectStrictVariant(t *testing.T) {
	subject := VisitorSubject{Kind: VisitorRegisteredKey, GrantID: "pgrant_" + strings.Repeat("A", 22), KeyID: "pkey_" + strings.Repeat("B", 22)}
	data, err := json.Marshal(subject)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"kind":"registered_key","grant_id":"` + subject.GrantID + `","key_id":"` + subject.KeyID + `"}`
	if string(data) != want {
		t.Fatal("unexpected registered key wire", string(data))
	}
	var decoded VisitorSubject
	if err := json.Unmarshal(data, &decoded); err != nil || decoded != subject {
		t.Fatal("registered subject did not round trip", err)
	}
	for _, extra := range []string{`,"identity_id":""`, `,"device_id":""`, `,"workload_session_id":""`, `,"unknown":""`} {
		if err := json.Unmarshal([]byte(strings.TrimSuffix(want, "}")+extra+"}"), &decoded); err == nil {
			t.Fatal("accepted mixed or unknown variant", extra)
		}
	}
	for _, invalid := range []VisitorSubject{
		{Kind: VisitorRegisteredKey, GrantID: subject.GrantID},
		{Kind: VisitorRegisteredKey, GrantID: subject.GrantID, KeyID: subject.KeyID, DeviceID: "vdev_" + strings.Repeat("C", 22)},
		{Kind: VisitorWorkloadSession, WorkloadSessionID: "wls_" + strings.Repeat("C", 22), KeyID: subject.KeyID},
	} {
		if invalid.Validate() == nil {
			t.Fatal("accepted invalid variant", invalid)
		}
	}
}
